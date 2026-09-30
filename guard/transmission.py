"""Small Transmission 4 legacy RPC client (supported by Transmission 4)."""
import base64
import json
import urllib.error
import urllib.request


FIELDS = ["id", "hashString", "name", "status", "percentDone", "rateDownload", "rateUpload",
          "totalSize", "leftUntilDone", "isFinished", "downloadDir", "files", "fileStats",
          "errorString", "trackerStats", "peersConnected", "peersSendingToUs", "eta", "sizeWhenDone"]


class RPCError(Exception):
    pass


class Transmission:
    def __init__(self, password, url="http://127.0.0.1:19091/transmission/rpc"):
        self.url = url
        self.auth = "Basic " + base64.b64encode(("guard:" + password).encode()).decode()
        self.session = ""

    def call(self, method, arguments=None):
        body = json.dumps({"method": method, "arguments": arguments or {}}).encode()
        for _ in range(2):
            request = urllib.request.Request(self.url, body, {
                "Authorization": self.auth, "X-Transmission-Session-Id": self.session,
                "Content-Type": "application/json"}, method="POST")
            try:
                with urllib.request.urlopen(request, timeout=12) as response:
                    result = json.load(response)
                if result.get("result") != "success":
                    raise RPCError(str(result.get("result", "Transmission request failed.")))
                return result["arguments"]
            except urllib.error.HTTPError as exc:
                if exc.code == 409:
                    self.session = exc.headers.get("X-Transmission-Session-Id", "")
                    continue
                raise RPCError("Transmission RPC rejected the request.") from exc
            except (urllib.error.URLError, TimeoutError, ValueError) as exc:
                raise RPCError("Torrent client unavailable.") from exc
        raise RPCError("Transmission session handshake failed.")

    def list(self):
        return self.call("torrent-get", {"fields": FIELDS})["torrents"]

    def set_safety(self):
        self.call("session-set", {"seedRatioLimited": True, "seedRatioLimit": 0,
                                  "renamePartialFiles": True, "startAddedTorrents": False,
                                  "downloadDir": "/downloads", "incompleteDirEnabled": False})

    def add(self, folder, magnet=None, blob=None):
        arguments = {"download-dir": "/downloads/" + folder, "paused": True}
        if magnet:
            arguments["filename"] = magnet
        else:
            arguments["metainfo"] = base64.b64encode(blob).decode()
        result = self.call("torrent-add", arguments)
        if "torrent-duplicate" in result:
            raise RPCError("This torrent is already in the download list.")
        return result["torrent-added"]["hashString"]

    def stop(self, hash_string):
        self.call("torrent-stop", {"ids": [hash_string]})

    def start(self, hash_string):
        self.call("torrent-start", {"ids": [hash_string]})

    def remove(self, hash_string):
        # The host app removes its own UUID quarantine directory, not Transmission.
        self.call("torrent-remove", {"ids": [hash_string], "delete-local-data": False})
