"""Snapshot, scan, and release; fail closed on any missing or changed content."""
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import time
import uuid


class UnsafeFile(ValueError):
    pass


def safe_parts(path):
    if not isinstance(path, str) or not path or "\\" in path or "\x00" in path:
        raise UnsafeFile("Invalid torrent file path.")
    parts = PurePosixPath(path).parts
    if any(part in {"", ".", ".."} or any(ord(c) < 32 for c in part) for part in path.split("/")) \
            or PurePosixPath(path).is_absolute() or len(parts) > 20:
        raise UnsafeFile("Unsafe torrent file path.")
    return parts


def _regular(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    if not stat.S_ISREG(os.fstat(fd).st_mode) or os.fstat(fd).st_nlink != 1:
        os.close(fd)
        raise UnsafeFile("Only regular, non-linked files can be scanned.")
    return fd


def _verify_tree(root, expected):
    actual = set()
    for folder, dirs, files in os.walk(root, followlinks=False):
        for name in dirs + files:
            entry = Path(folder) / name
            kind = entry.lstat().st_mode
            if not (stat.S_ISDIR(kind) or stat.S_ISREG(kind)) or (stat.S_ISREG(kind) and entry.stat().st_nlink != 1):
                raise UnsafeFile("Quarantine contains a link or special file.")
        for name in files:
            actual.add(str((Path(folder) / name).relative_to(root)))
    if actual != set(expected):
        raise UnsafeFile("Torrent contents do not match the file list.")


def snapshot(source, target, files):
    """Copy completed files to an app-owned directory that the torrent client cannot mount."""
    expected = {}
    for file in files:
        parts = safe_parts(file["name"])
        name = str(Path(*parts))
        if name in expected or file["length"] < 0 or file["bytesCompleted"] != file["length"]:
            raise UnsafeFile("Torrent contains incomplete or duplicate files.")
        expected[name] = file["length"]
    if not expected:
        raise UnsafeFile("There are no completed files to scan.")
    _verify_tree(source, expected)
    target.mkdir(mode=0o700)
    hashes = {}
    try:
        for name, size in expected.items():
            parts = safe_parts(name)
            # Reject symlinked parent directories at every level, including the torrent root.
            parent = source
            for segment in parts[:-1]:
                parent = parent / segment
                if not stat.S_ISDIR(parent.lstat().st_mode):
                    raise UnsafeFile("Torrent contains a linked directory.")
            dest = target.joinpath(*parts)
            dest.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            digest = hashlib.sha256()
            fd = _regular(source.joinpath(*parts))
            try:
                before = os.fstat(fd)
                with os.fdopen(fd, "rb", closefd=False) as input_file, dest.open("xb") as output:
                    while chunk := input_file.read(1024 * 1024):
                        digest.update(chunk)
                        output.write(chunk)
                after = os.fstat(fd)
                if (before.st_size != size or after.st_size != size or before.st_mtime_ns != after.st_mtime_ns
                        or before.st_ctime_ns != after.st_ctime_ns):
                    raise UnsafeFile("A downloaded file changed during the scan snapshot.")
            finally:
                os.close(fd)
            hashes[name] = digest.hexdigest()
        _verify_tree(source, expected)
        return hashes
    except Exception:
        shutil.rmtree(target)
        raise


def scan(target, database=Path("/var/lib/clamav"), scanner="clamscan"):
    signatures = list(database.glob("*.cvd")) + list(database.glob("*.cld"))
    if not signatures or max(file.stat().st_mtime for file in signatures) < time.time() - 48 * 3600:
        raise UnsafeFile("Virus signatures are missing or older than 48 hours. Run freshclam.")
    if shutil.which(scanner) is None:
        raise UnsafeFile("ClamAV is not installed.")
    command = [scanner, "--recursive=yes", "--scan-archive=yes", "--alert-encrypted=yes",
               "--alert-exceeds-max=yes", "--max-filesize=2048M", "--max-scansize=4096M",
               "--max-files=100000", "--max-recursion=100", "--max-scantime=1200000", str(target)]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=3600)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise UnsafeFile("Virus scan could not complete.") from exc
    report = (result.stdout + "\n" + result.stderr)[-6000:]
    if result.returncode != 0 or not re.search(r"Infected files:\s*0\b", report):
        raise UnsafeFile("ClamAV did not clear these files. " + report[-1000:])
    return "ClamAV completed with no findings. This is not a guarantee of safety."


def release(snapshot_dir, downloads, hashes, name):
    """Only publish an entirely copied, hash-verified directory via a final rename."""
    _verify_tree(snapshot_dir, hashes)
    downloads.mkdir(exist_ok=True)
    if not downloads.is_dir() or downloads.is_symlink():
        raise UnsafeFile("Downloads is not a normal directory.")
    clean = re.sub(r"[^\w .()-]", "_", name).strip(" .")[:100] or "Torrent"
    temp = downloads / (".torrent-guard-" + uuid.uuid4().hex)
    temp.mkdir(mode=0o700)
    try:
        for rel, expected_hash in hashes.items():
            dest = temp.joinpath(*safe_parts(rel))
            dest.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            digest = hashlib.sha256()
            fd = _regular(snapshot_dir / rel)
            try:
                with os.fdopen(fd, "rb", closefd=False) as input_file, dest.open("xb") as output:
                    while chunk := input_file.read(1024 * 1024):
                        digest.update(chunk)
                        output.write(chunk)
                if digest.hexdigest() != expected_hash:
                    raise UnsafeFile("A scanned file changed before release.")
            finally:
                os.close(fd)
        for suffix in range(1000):
            target = downloads / (clean if suffix == 0 else f"{clean} ({suffix})")
            if not target.exists() and not target.is_symlink():
                # Rename within ~/Downloads: all files become visible at once.
                temp.rename(target)
                return str(target)
        raise UnsafeFile("No free destination name in Downloads.")
    finally:
        if temp.exists():
            shutil.rmtree(temp)
