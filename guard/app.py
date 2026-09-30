#!/usr/bin/env python3
"""English-only loopback web UI and quarantine controller."""
import base64
import binascii
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import threading
import time
import tomllib
import urllib.error
import urllib.request
import uuid

from .profiles import InvalidProfile, import_profiles
from .resources import Usage
from .scanner import UnsafeFile, release, scan, snapshot
from .transmission import RPCError, Transmission


PROJECT = Path(__file__).resolve().parent.parent
DATA = Path(os.environ.get("TORRENT_GUARD_DATA", Path.home() / ".local/share/omarchy-torrent-guard"))
DOWNLOADS = Path.home() / "Downloads"
PORT = 18765


def save_json(path, value):
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(value, indent=2), encoding="utf-8")
    tmp.chmod(0o600)
    tmp.replace(path)


def theme_css():
    try:
        name = subprocess.check_output(["omarchy", "theme", "current"], text=True, timeout=3).strip()
        slug = re.sub(r"[^a-z0-9-]", "-", name.lower()).strip("-")
        for path in (Path.home() / ".config/omarchy/themes" / slug / "colors.toml",
                     Path("/usr/share/omarchy/themes") / slug / "colors.toml"):
            if path.is_file():
                colors = tomllib.loads(path.read_text())
                keys = ("accent", "background", "lighter_background", "foreground", "muted", "green", "red", "yellow")
                if all(re.fullmatch(r"#[0-9a-fA-F]{6}", str(colors[key])) for key in keys):
                    return ":root{" + "".join(f"--{key.replace('_', '-')}: {colors[key]};" for key in keys) + "}"
    except (OSError, KeyError, ValueError, subprocess.SubprocessError):
        pass
    return ":root{--accent:#7aa2f7;--background:#1a1b26;--lighter-background:#24283b;--foreground:#a9b1d6;--muted:#414868;--green:#9ece6a;--red:#f7768e;--yellow:#e0af68;}"


def connection_report(torrent, vpn):
    """Explain tracker failures without mistaking them for a broken VPN tunnel."""
    if vpn != "running":
        return "VPN unavailable — download paused."
    error = torrent.get("errorString", "")
    if error and error != "Connection failed":
        return error[:240]
    if torrent.get("peersConnected", 0):
        return "Connected to peers; waiting for metadata or file pieces."
    trackers = torrent.get("trackerStats", [])
    working = [tracker for tracker in trackers if tracker.get("lastAnnounceSucceeded")]
    if working and all(tracker.get("seederCount") == 0 for tracker in working):
        return "Tracker reachable, but reports no seeders; still searching DHT."
    if working:
        return "Tracker reachable; waiting for peer connections."
    if trackers and all(tracker.get("hasAnnounced") for tracker in trackers):
        return "Tracker unreachable; searching DHT for peers."
    return "Looking for peers and tracker connections…"


class Guard:
    def __init__(self, root=DATA, downloads=DOWNLOADS, rpc=None):
        os.umask(0o077)
        self.root, self.downloads = Path(root), Path(downloads)
        self.lock = threading.RLock()
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.root.chmod(0o700)
        for name in ("profiles", "active", "transmission", "quarantine", "snapshots"):
            (self.root / name).mkdir(exist_ok=True, mode=0o700)
        self.database = self.root / "state.json"
        self.state = json.loads(self.database.read_text()) if self.database.exists() else {
            "profiles": [], "active": None, "torrents": {}}
        recovered = False
        for item in self.state["torrents"].values():
            if item["state"] == "scanning":
                item.update(state="blocked", rescan_pending=True,
                            report="Scan interrupted. Rescanning when the torrent client is available.")
                recovered = True
        if recovered:
            self.persist()
        password_file = self.root / "rpc-password"
        if not password_file.exists():
            password_file.write_text(secrets.token_urlsafe(36))
            password_file.chmod(0o600)
        self.rpc = rpc or Transmission(password_file.read_text().strip())
        env = self.root / "compose.env"
        env.write_text(f"APP_DATA={self.root}\nAPP_UID={os.getuid()}\nAPP_GID={os.getgid()}\n")
        env.chmod(0o600)
        self.rpc_online = False
        self.vpn = "unavailable"
        self.usage = Usage(self.root)
        self.stopping = threading.Event()

    def persist(self):
        save_json(self.database, self.state)

    def vpn_status(self):
        try:
            with urllib.request.urlopen("http://127.0.0.1:18000/v1/vpn/status", timeout=2) as response:
                value = json.load(response).get("status", "unavailable")
            return value if value in {"running", "stopped"} else "unavailable"
        except (OSError, ValueError):
            return "unavailable"

    def public(self):
        with self.lock:
            self.vpn = self.vpn_status()
            items = [{"hash": key, "name": item["name"], "state": item["state"],
                      "progress": item.get("progress", 0), "speed": item.get("speed", 0),
                      "upload_speed": item.get("upload_speed", 0), "size": item.get("size", 0),
                      "downloaded": item.get("downloaded", item.get("size", 0) if item.get("progress") == 1 else 0),
                      "peers": item.get("peers", 0),
                      "active_peers": item.get("active_peers", 0), "eta": item.get("eta", -1),
                      "report": item.get("report", ""),
                      "destination": item.get("destination", "")}
                     for key, item in self.state["torrents"].items()]
            return {"vpn": self.vpn, "rpc": self.rpc_online, "profiles": self.state["profiles"],
                    "active": self.state["active"], "torrents": items,
                    "scanner": shutil.which("clamscan") is not None,
                    "usage": self.usage.sample()}

    def import_vpn(self, filename, blob):
        profiles = import_profiles(blob, filename)
        with self.lock:
            for profile in profiles:
                path = self.root / "profiles" / (profile["id"] + ".conf")
                path.write_text(profile["config"])
                path.chmod(0o600)
                self.state["profiles"].append({"id": profile["id"], "name": profile["name"]})
            self.persist()
        return len(profiles)

    def apply_profile(self, profile_id):
        with self.lock:
            if profile_id not in {profile["id"] for profile in self.state["profiles"]}:
                raise ValueError("Unknown VPN profile.")
            if any(item["state"] == "downloading" for item in self.state["torrents"].values()):
                raise ValueError("Pause active downloads before changing VPN profiles.")
            # Stop all torrents before replacing their shared network namespace.
            try:
                for torrent in self.rpc.list():
                    self.rpc.stop(torrent["hashString"])
            except RPCError:
                pass  # When Docker is not running, there is nothing to stop.
            selected = (self.root / "profiles" / (profile_id + ".conf")).read_bytes()
            current = self.root / "active/wg0.conf"
            previous = current.read_bytes() if current.exists() else None
            temp = current.with_suffix(".tmp")
            temp.write_bytes(selected)
            temp.chmod(0o600)
            temp.replace(current)
            # A polkit dialog grants one explicit Docker Compose action; no Docker socket in the UI.
            command = ["pkexec", "/usr/bin/docker", "compose", "--project-directory", str(PROJECT),
                       "--env-file", str(self.root / "compose.env"), "-f", str(PROJECT / "compose.yaml"),
                       "up", "-d", "--force-recreate"]
            try:
                result = subprocess.run(command, capture_output=True, text=True, timeout=240)
                if result.returncode:
                    raise ValueError("Docker could not start the VPN and torrent client. " + result.stderr[-350:])
            except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
                if previous is None:
                    current.unlink(missing_ok=True)
                else:
                    current.write_bytes(previous)
                    current.chmod(0o600)
                raise ValueError(str(exc)) from exc
            self.state["active"] = profile_id
            self.persist()

    def pause_torrent(self, key):
        with self.lock:
            item = self.state["torrents"].get(key)
            if not item or item["state"] != "downloading":
                raise ValueError("Only active downloads can be paused.")
            row = next((r for r in self.rpc.list() if r["hashString"] == key), None)
            if not row or row["isFinished"] and row["leftUntilDone"] == 0:
                raise ValueError("This download is already complete; wait for its scan.")
            self.rpc.stop(key)
            item.update(state="paused", speed=0, upload_speed=0, peers=0, active_peers=0,
                        eta=-1, report="Paused — resume manually when ready.")
            self.persist()

    def resume_torrent(self, key):
        with self.lock:
            item = self.state["torrents"].get(key)
            if not item or item["state"] != "paused":
                raise ValueError("Only paused downloads can be resumed.")
            if self.vpn_status() != "running":
                raise ValueError("Connect the VPN before resuming a download.")
            row = next((r for r in self.rpc.list() if r["hashString"] == key), None)
            if not row or row["downloadDir"] != "/downloads/" + item["folder"] or row["status"] != 0:
                raise ValueError("The torrent is missing, in an unexpected location, or already running.")
            if row["isFinished"] and row["leftUntilDone"] == 0:
                raise ValueError("This download is complete and should be scanned instead.")
            self.rpc.set_safety()
            self.rpc.start(key)
            item.update(state="downloading", report="Looking for peers and tracker connections…")
            self.persist()

    def disconnect(self, confirm_active=False, shutdown=False):
        with self.lock:
            if shutdown and any(item["state"] == "scanning" for item in self.state["torrents"].values()):
                raise ValueError("Wait for the virus scan to finish before safe shutdown.")
            active = [item for item in self.state["torrents"].values() if item["state"] == "downloading"]
            if active and confirm_active is not True:
                raise ValueError("Confirm pausing active downloads before disconnecting.")
            try:
                for row in self.rpc.list():
                    if row["status"] not in (0, 1, 2):
                        self.rpc.stop(row["hashString"])
            except RPCError as exc:
                if self.vpn_status() == "running":
                    raise ValueError("Torrent client unavailable; could not confirm downloads are paused.") from exc
            for item in active:
                item.update(state="paused", speed=0, upload_speed=0, peers=0, active_peers=0,
                            eta=-1, report="Paused — reconnect the VPN, then resume manually.")
            self.persist()
            command = ["pkexec", "/usr/bin/docker", "compose", "--project-directory", str(PROJECT),
                       "--env-file", str(self.root / "compose.env"), "-f", str(PROJECT / "compose.yaml"),
                       "down", "--timeout", "20"]
            try:
                result = subprocess.run(command, capture_output=True, text=True, timeout=120)
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise ValueError("Could not stop Docker containers; downloads remain paused.") from exc
            if result.returncode:
                raise ValueError("Could not stop Docker containers; downloads remain paused. " + result.stderr[-350:])
            self.vpn, self.rpc_online = "unavailable", False
            if shutdown:
                self.stopping.set()
            return len(active)

    def add_torrent(self, magnet=None, blob=None):
        if self.vpn_status() != "running":
            raise ValueError("VPN unavailable — download paused. Select and start a VPN profile first.")
        with self.lock:
            self.rpc.set_safety()
            folder = uuid.uuid4().hex
            if magnet:
                if len(magnet) > 4096 or not re.match(r"^magnet:\?xt=urn:btih:(?:[a-fA-F0-9]{40}|[A-Za-z2-7]{32})(?:&|$)", magnet):
                    raise ValueError("Enter a valid BitTorrent magnet link.")
            elif blob is None or len(blob) > 4 * 1024 * 1024 or not blob.startswith(b"d") or not blob.endswith(b"e"):
                raise ValueError("Choose a valid .torrent file under 4 MB.")
            (self.root / "quarantine" / folder).mkdir(mode=0o700)
            try:
                hash_string = self.rpc.add(folder, magnet, blob)
            except Exception:
                (self.root / "quarantine" / folder).rmdir()
                raise
            self.state["torrents"][hash_string] = {"folder": folder, "name": "Fetching metadata…",
                                                    "state": "downloading", "progress": 0}
            self.persist()
            self.rpc.start(hash_string)
            return hash_string

    def poll(self):
        with self.lock:
            self.vpn = self.vpn_status()
            try:
                torrents = {row["hashString"]: row for row in self.rpc.list()}
                self.rpc_online = True
                self.rpc.set_safety()
            except RPCError:
                self.rpc_online = False
                return
            for key, item in self.state["torrents"].items():
                row = torrents.get(key)
                if not row or item["state"] in {"ready", "scanning", "released"}:
                    continue
                if item.get("rescan_pending"):
                    if (row["status"] == 0 and row["isFinished"] and row["leftUntilDone"] == 0
                            and row["downloadDir"] == "/downloads/" + item["folder"]):
                        item.update(state="scanning", report="", rescan_pending=False)
                        self.persist()
                        threading.Thread(target=self._scan_job, args=(key, row["files"]), daemon=True).start()
                    continue
                if item["state"] == "blocked":
                    continue
                size = row.get("sizeWhenDone", row["totalSize"])
                item.update(name=row["name"], progress=row["percentDone"],
                            speed=row["rateDownload"] if item["state"] == "downloading" else 0,
                            upload_speed=row.get("rateUpload", 0) if item["state"] == "downloading" else 0,
                            size=size, downloaded=max(0, size - row["leftUntilDone"]),
                            peers=row.get("peersConnected", 0) if item["state"] == "downloading" else 0,
                            active_peers=row.get("peersSendingToUs", 0) if item["state"] == "downloading" else 0,
                            eta=row.get("eta", -1) if item["state"] == "downloading" else -1)
                if item["state"] == "downloading":
                    item["report"] = connection_report(row, self.vpn)
                if row["leftUntilDone"] == 0 and row["isFinished"] and row["files"]:
                    if row["status"] != 0:
                        self.rpc.stop(key)
                        continue
                    if row["downloadDir"] != "/downloads/" + item["folder"]:
                        item.update(state="blocked", report="Unexpected download location.")
                        continue
                    item["state"] = "scanning"
                    item.update(speed=0, upload_speed=0, peers=0, active_peers=0, eta=-1, report="Scanning completed download…")
                    self.persist()
                    threading.Thread(target=self._scan_job, args=(key, row["files"]), daemon=True).start()
                elif item["state"] == "downloading" and row["status"] == 0:
                    item.update(state="paused", speed=0, upload_speed=0, peers=0, active_peers=0,
                                eta=-1, report="Paused — resume manually when ready.")
            self.persist()

    def _scan_job(self, key, files):
        with self.lock:
            item = self.state["torrents"][key]
            folder = item["folder"]
        source = self.root / "quarantine" / folder
        target = self.root / "snapshots" / folder
        try:
            if target.exists():
                shutil.rmtree(target)
            if source.is_symlink() or not source.is_dir():
                raise UnsafeFile("Quarantine folder was replaced.")
            hashes = snapshot(source, target, files)
            report = scan(target)
            with self.lock:
                item.update(state="ready", hashes=hashes, report=report, progress=1)
                self.persist()
            self.notify("Scan complete", "No findings. Manual release is available.")
        except (UnsafeFile, OSError, KeyError, ValueError) as exc:
            with self.lock:
                item.update(state="blocked", report=str(exc)[:450])
                self.persist()
            self.notify("Download blocked", "The scan did not clear this download.")

    def release_torrent(self, key):
        with self.lock:
            item = self.state["torrents"].get(key)
            if not item or item["state"] != "ready":
                raise ValueError("Only completed, scanned downloads can be released.")
            # Confirm the daemon is still stopped, even if the app was restarted.
            match = next((row for row in self.rpc.list() if row["hashString"] == key), None)
            if not match or match["status"] != 0:
                raise ValueError("Stop the torrent before releasing it.")
            path = release(self.root / "snapshots" / item["folder"], self.downloads,
                           item["hashes"], item["name"])
            item.update(state="released", destination=path, report="Released after manual approval.")
            self.persist()
            shutil.rmtree(self.root / "snapshots" / item["folder"])
            try:
                self.rpc.remove(key)
                source = self.root / "quarantine" / item["folder"]
                if source.is_dir() and not source.is_symlink():
                    shutil.rmtree(source)
            except RPCError:
                pass  # The torrent remains stopped; release has already been recorded.
            self.notify("Files released", "Your download is now in Downloads.")
            return path

    def retry_scan(self, key):
        with self.lock:
            item = self.state["torrents"].get(key)
            if not item or item["state"] != "blocked":
                raise ValueError("Only blocked downloads can be scanned again.")
            row = next((torrent for torrent in self.rpc.list() if torrent["hashString"] == key), None)
            if not row or row["status"] != 0 or not row["isFinished"] or row["leftUntilDone"] != 0:
                raise ValueError("The torrent must be complete and stopped before scanning.")
            if row["downloadDir"] != "/downloads/" + item["folder"]:
                raise ValueError("Unexpected download location.")
            item.update(state="scanning", report="")
            self.persist()
            threading.Thread(target=self._scan_job, args=(key, row["files"]), daemon=True).start()

    def remove_torrent(self, key):
        with self.lock:
            item = self.state["torrents"].get(key)
            if not item or item["state"] == "scanning":
                raise ValueError("Wait for the scan to finish before removing this torrent.")
            match = next((row for row in self.rpc.list() if row["hashString"] == key), None)
            if match:
                self.rpc.stop(key)
                self.rpc.remove(key)
            for name in ("quarantine", "snapshots"):
                path = self.root / name / item["folder"]
                if path.is_symlink():
                    raise UnsafeFile("Unexpected linked folder; removal cancelled.")
                if path.exists():
                    shutil.rmtree(path)
            del self.state["torrents"][key]
            self.persist()

    @staticmethod
    def notify(title, body):
        if shutil.which("notify-send"):
            subprocess.Popen(["notify-send", "Torrent Guard", title + " — " + body],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def loop(self):
        while not self.stopping.is_set():
            try:
                self.poll()
            except (OSError, KeyError, ValueError, RPCError):
                pass
            self.stopping.wait(3)


class Handler(BaseHTTPRequestHandler):
    guard = None
    token = ""

    def log_message(self, fmt, *args):
        # Never log request bodies (VPN private keys and magnet tracker details).
        pass

    def send(self, status, data, content_type="application/json"):
        body = json.dumps(data).encode() if content_type == "application/json" else data
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(body)

    def trusted(self):
        return self.headers.get("Host", "") in {f"127.0.0.1:{PORT}", f"localhost:{PORT}"}

    def do_GET(self):
        if not self.trusted():
            return self.send(403, {"error": "Local access only."})
        if self.path == "/api/status":
            return self.send(200, self.guard.public())
        if self.path == "/theme.css":
            return self.send(200, theme_css().encode(), "text/css; charset=utf-8")
        if self.path in {"/", "/app.js", "/app.css", "/actions.css"}:
            path = PROJECT / "web" / ("index.html" if self.path == "/" else self.path[1:])
            data = path.read_bytes()
            if self.path == "/":
                data = data.replace(b"__CSRF_TOKEN__", self.token.encode())
            mime = {"/": "text/html", "/app.js": "text/javascript", "/app.css": "text/css", "/actions.css": "text/css"}[self.path]
            return self.send(200, data, mime + "; charset=utf-8")
        self.send(404, {"error": "Not found."})

    def do_POST(self):
        origin = self.headers.get("Origin", "")
        if not self.trusted() or origin not in {f"http://127.0.0.1:{PORT}", f"http://localhost:{PORT}"} \
                or not secrets.compare_digest(self.headers.get("X-Guard-Token", ""), self.token):
            return self.send(403, {"error": "Request not authorized."})
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 < size <= 36 * 1024 * 1024:
                raise ValueError("Request is too large or empty.")
            params = json.loads(self.rfile.read(size))
            if self.path == "/api/import":
                blob = base64.b64decode(params["data"], validate=True)
                result = {"imported": self.guard.import_vpn(params["filename"], blob)}
            elif self.path == "/api/apply":
                self.guard.apply_profile(params["id"])
                result = {"ok": True}
            elif self.path == "/api/add":
                blob = base64.b64decode(params["data"], validate=True) if params.get("data") else None
                result = {"hash": self.guard.add_torrent(magnet=params.get("magnet"), blob=blob)}
            elif self.path == "/api/release":
                result = {"destination": self.guard.release_torrent(params["hash"])}
            elif self.path == "/api/retry":
                self.guard.retry_scan(params["hash"])
                result = {"ok": True}
            elif self.path == "/api/remove":
                self.guard.remove_torrent(params["hash"])
                result = {"ok": True}
            elif self.path == "/api/pause":
                self.guard.pause_torrent(params["hash"])
                result = {"ok": True}
            elif self.path == "/api/resume":
                self.guard.resume_torrent(params["hash"])
                result = {"ok": True}
            elif self.path in {"/api/disconnect", "/api/shutdown"}:
                paused = self.guard.disconnect(confirm_active=params.get("confirm_active") is True,
                                               shutdown=self.path == "/api/shutdown")
                result = {"ok": True, "paused": paused}
            else:
                return self.send(404, {"error": "Not found."})
            self.send(200, result)
            if self.path == "/api/shutdown":
                threading.Timer(1, self.server.shutdown).start()
        except (KeyError, ValueError, TypeError, InvalidProfile, UnsafeFile, RPCError, binascii.Error) as exc:
            self.send(400, {"error": str(exc)[:500]})


def main():
    guard = Guard()
    Handler.guard = guard
    Handler.token = secrets.token_urlsafe(32)
    threading.Thread(target=guard.loop, daemon=True).start()
    server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"Torrent Guard: http://127.0.0.1:{PORT}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
