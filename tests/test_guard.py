import base64
import io
import json
from pathlib import Path
import shutil
import tempfile
import threading
import unittest
import zipfile
from unittest.mock import patch

from guard.app import Guard, connection_report
from guard.resources import Usage
from guard.profiles import InvalidProfile, import_profiles
from guard.scanner import UnsafeFile, release, safe_parts, scan, snapshot


PRIVATE = base64.b64encode(bytes(range(32))).decode()
PUBLIC = base64.b64encode(bytes(range(32, 64))).decode()
PROFILE = (f"[Interface]\nPrivateKey = {PRIVATE}\nAddress = 10.64.0.2/32, fd00::1/128\n"
           f"DNS = 10.64.0.1\n[Peer]\nPublicKey = {PUBLIC}\n"
           "AllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = 185.1.2.3:51820\n").encode()


class ProfileTests(unittest.TestCase):
    def test_zip_import_and_reject_hooks(self):
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w") as output:
            output.writestr("relays/../server.conf", PROFILE)
        profiles = import_profiles(archive.getvalue(), "mullvad.zip")
        self.assertEqual(len(profiles), 1)
        self.assertNotIn("DNS", profiles[0]["config"])
        with self.assertRaises(InvalidProfile):
            import_profiles(PROFILE + b"PostUp = curl example.com\n", "server.conf")

    def test_reject_non_full_tunnel(self):
        with self.assertRaises(InvalidProfile):
            import_profiles(PROFILE.replace(b"0.0.0.0/0", b"192.0.0.0/8"), "server.conf")


class ConnectionStatusTests(unittest.TestCase):
    def test_tracker_failure_and_no_seeders_are_distinct(self):
        stalled = {"errorString": "Connection failed", "peersConnected": 0,
                   "trackerStats": [{"hasAnnounced": True, "lastAnnounceSucceeded": False}]}
        self.assertIn("Tracker unreachable", connection_report(stalled, "running"))
        stalled["trackerStats"].append({"hasAnnounced": True, "lastAnnounceSucceeded": True,
                                        "seederCount": 0})
        self.assertIn("reports no seeders", connection_report(stalled, "running"))
        self.assertIn("VPN unavailable", connection_report(stalled, "stopped"))


class SnapshotTests(unittest.TestCase):
    def test_bad_paths_and_links(self):
        for path in ("../secret", "/etc/passwd", "a/../../secret", "a\\secret"):
            with self.assertRaises(UnsafeFile):
                safe_parts(path)
        with tempfile.TemporaryDirectory() as base:
            root = Path(base)
            source = root / "quarantine"
            source.mkdir()
            (source / "safe.txt").symlink_to("/etc/passwd")
            with self.assertRaises(UnsafeFile):
                snapshot(source, root / "snapshot", [{"name": "safe.txt", "length": 0, "bytesCompleted": 0}])

    def test_snapshot_and_release_recheck_hash(self):
        with tempfile.TemporaryDirectory() as base:
            root = Path(base)
            source = root / "quarantine"; source.mkdir()
            (source / "file.txt").write_text("safe data")
            files = [{"name": "file.txt", "length": 9, "bytesCompleted": 9}]
            snap = root / "snapshot"
            hashes = snapshot(source, snap, files)
            (source / "file.txt").write_text("changed after scan")
            downloads = root / "Downloads"
            destination = Path(release(snap, downloads, hashes, "Demo"))
            self.assertEqual((destination / "file.txt").read_text(), "safe data")
            (snap / "file.txt").write_text("changed snapshot")
            with self.assertRaises(UnsafeFile):
                release(snap, downloads, hashes, "Demo")
            self.assertEqual(list(downloads.iterdir()), [destination])


class FakeRPC:
    def list(self):
        return [{"hashString": "abc", "status": 0}]

    def stop(self, key):
        pass

    def remove(self, key):
        pass


class TrackingRPC:
    def __init__(self):
        self.row = {"hashString": "abc", "status": 4, "isFinished": False,
                    "leftUntilDone": 80, "downloadDir": "/downloads/123", "name": "Test",
                    "percentDone": .2, "rateDownload": 1000, "rateUpload": 50,
                    "sizeWhenDone": 100, "totalSize": 100, "peersConnected": 4,
                    "peersSendingToUs": 2, "eta": 60, "errorString": "", "trackerStats": [], "files": []}
        self.calls = []

    def list(self):
        return [dict(self.row)]

    def set_safety(self):
        self.calls.append("safe")

    def stop(self, key):
        self.calls.append("stop")
        self.row["status"] = 0

    def start(self, key):
        self.calls.append("start")
        self.row["status"] = 4


class ReleaseTests(unittest.TestCase):
    def test_cannot_release_unscanned_download(self):
        with tempfile.TemporaryDirectory() as base:
            root = Path(base)
            app = Guard(root / "state", root / "Downloads", FakeRPC())
            app.state["torrents"]["abc"] = {"state": "downloading", "name": "Demo", "folder": "123"}
            with self.assertRaises(ValueError):
                app.release_torrent("abc")
            self.assertFalse((root / "Downloads").exists())

    def test_vpn_must_be_running_before_adding_torrent(self):
        with tempfile.TemporaryDirectory() as base:
            app = Guard(Path(base) / "state", Path(base) / "Downloads", FakeRPC())
            with patch.object(app, "vpn_status", return_value="stopped"):
                with self.assertRaisesRegex(ValueError, "VPN unavailable"):
                    app.add_torrent(magnet="magnet:?xt=urn:btih:" + "a" * 40)
            self.assertFalse(list((app.root / "quarantine").iterdir()))

    def test_scan_fails_closed_without_current_signatures(self):
        with tempfile.TemporaryDirectory() as base:
            path = Path(base)
            with self.assertRaisesRegex(UnsafeFile, "signatures"):
                scan(path, path / "missing")

    def test_remove_cleans_quarantine_but_keeps_released_files(self):
        with tempfile.TemporaryDirectory() as base:
            root = Path(base)
            app = Guard(root / "state", root / "Downloads", FakeRPC())
            folder = app.root / "quarantine" / "123"
            folder.mkdir()
            (folder / "junk").write_text("untrusted")
            downloads = app.downloads / "Already released"
            downloads.mkdir(parents=True)
            (downloads / "file").write_text("trusted")
            app.state["torrents"]["abc"] = {"state": "released", "name": "Demo", "folder": "123"}
            app.remove_torrent("abc")
            self.assertFalse(folder.exists())
            self.assertEqual((downloads / "file").read_text(), "trusted")


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.rpc = TrackingRPC()
        self.app = Guard(Path(self.temp.name) / "state", Path(self.temp.name) / "Downloads", self.rpc)
        self.app.state["torrents"]["abc"] = {"state": "downloading", "name": "Test", "folder": "123"}

    def test_progress_peers_and_manual_resume_only(self):
        with patch.object(self.app, "vpn_status", return_value="running"):
            self.app.poll()
            item = self.app.public()["torrents"][0]
            self.assertEqual((item["downloaded"], item["size"], item["peers"], item["active_peers"]), (20, 100, 4, 2))
            self.app.pause_torrent("abc")
            self.assertEqual(self.rpc.calls[-1], "stop")
            self.app.poll()
            self.assertEqual(self.app.state["torrents"]["abc"]["state"], "paused")
            self.assertEqual(self.rpc.calls[-1], "safe")
            self.app.resume_torrent("abc")
            self.assertEqual(self.rpc.calls[-1], "start")

    def test_disconnect_requires_confirmation_then_keeps_manual_pause(self):
        with patch.object(self.app, "vpn_status", return_value="running"), \
                patch("guard.app.subprocess.run") as command:
            command.return_value.returncode = 0
            with self.assertRaisesRegex(ValueError, "Confirm"):
                self.app.disconnect()
            command.assert_not_called()
            self.app.disconnect(confirm_active=True)
            self.assertEqual(self.app.state["torrents"]["abc"]["state"], "paused")
            self.assertEqual(self.rpc.calls, ["stop"])
            self.assertEqual(command.call_args.args[0][-3:], ["down", "--timeout", "20"])

    def test_safe_shutdown_waits_for_scans(self):
        self.app.state["torrents"]["abc"]["state"] = "scanning"
        with patch("guard.app.subprocess.run") as command:
            with self.assertRaisesRegex(ValueError, "scan to finish"):
                self.app.disconnect(confirm_active=True, shutdown=True)
            command.assert_not_called()

    def test_shutdown_pauses_active_download_and_stops_controller(self):
        with patch.object(self.app, "vpn_status", return_value="running"), \
                patch("guard.app.subprocess.run") as command:
            command.return_value.returncode = 0
            self.assertEqual(self.app.disconnect(confirm_active=True, shutdown=True), 1)
        self.assertTrue(self.app.stopping.is_set())
        self.assertEqual(self.app.state["torrents"]["abc"]["state"], "paused")
        self.assertEqual(self.rpc.row["status"], 0)

    def test_failed_privilege_prompt_does_not_resume_torrent(self):
        with patch.object(self.app, "vpn_status", return_value="running"), \
                patch("guard.app.subprocess.run") as command:
            command.return_value.returncode = 1
            command.return_value.stderr = "Authorization denied."
            with self.assertRaisesRegex(ValueError, "remain paused"):
                self.app.disconnect(confirm_active=True)
        self.assertEqual(self.app.state["torrents"]["abc"]["state"], "paused")
        self.assertEqual(self.rpc.row["status"], 0)

    def test_interrupted_scan_is_rescheduled_only_after_stopped_completion(self):
        self.app.state["torrents"]["abc"]["state"] = "scanning"
        self.app.persist()
        other = Guard(self.app.root, self.app.downloads, self.rpc)
        item = other.state["torrents"]["abc"]
        self.assertEqual(item["state"], "blocked")
        self.assertTrue(item["rescan_pending"])
        self.rpc.row.update(status=0, isFinished=True, leftUntilDone=0, files=[{"name": "test", "length": 100, "bytesCompleted": 100}])
        completed = threading.Event()
        with patch.object(other, "_scan_job", side_effect=lambda *_: completed.set()):
            other.poll()
            self.assertTrue(completed.wait(2))
        self.assertEqual(item["state"], "scanning")

    def test_resources_are_readable_without_docker(self):
        value = Usage(self.app.root).sample()
        self.assertIsNotNone(value["app"])
        self.assertEqual((value["quarantine"], value["snapshots"]), (0, 0))

    def test_existing_released_download_displays_full_size(self):
        item = self.app.state["torrents"]["abc"]
        item.update(state="released", size=987654, progress=1)
        self.assertEqual(self.app.public()["torrents"][0]["downloaded"], 987654)


class LiveScannerTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("clamscan"), "ClamAV is not installed")
    def test_real_signatures_clear_clean_and_block_eicar(self):
        with tempfile.TemporaryDirectory() as base:
            path = Path(base)
            (path / "clean.txt").write_text("Harmless test content")
            self.assertIn("no findings", scan(path))
            # EICAR is an inert industry-standard test signature, not malware.
            eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}" + "$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
            (path / "eicar.com").write_text(eicar)
            with self.assertRaisesRegex(UnsafeFile, "did not clear"):
                scan(path)


if __name__ == "__main__":
    unittest.main()
