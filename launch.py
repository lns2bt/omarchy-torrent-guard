#!/usr/bin/env python3
"""Omarchy launcher; start the local UI if necessary, then open a Chromium app window."""
import os
from pathlib import Path
import subprocess
import time
import urllib.error
import urllib.request


PROJECT = Path(__file__).resolve().parent
URL = "http://127.0.0.1:18765/"


def ready():
    try:
        with urllib.request.urlopen(URL + "api/status", timeout=1):
            return True
    except (urllib.error.URLError, TimeoutError):
        return False


if __name__ == "__main__":
    if not ready():
        env = os.environ.copy()
        env["PYTHONPATH"] = str(PROJECT)
        subprocess.Popen(["/usr/bin/python3", "-m", "guard.app"], cwd=PROJECT, env=env,
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         start_new_session=True)
        for _ in range(35):
            if ready():
                break
            time.sleep(.2)
    subprocess.Popen(["omarchy-launch-webapp", URL], start_new_session=True)
