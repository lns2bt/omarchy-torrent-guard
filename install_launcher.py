#!/usr/bin/env python3
"""Install the user-owned Omarchy desktop entry without changing system files."""
from pathlib import Path


PROJECT = Path(__file__).resolve().parent
DESTINATION = Path.home() / ".local/share/applications/omarchy-torrent-guard.desktop"


def desktop_argument(path):
    # Desktop Entry Exec quoting is not shell quoting.
    return '"' + str(path).replace("\\", "\\\\").replace('"', '\\"') + '"'


def main():
    DESTINATION.parent.mkdir(parents=True, exist_ok=True)
    DESTINATION.write_text(
        "[Desktop Entry]\n"
        "Type=Application\n"
        "Name=Torrent Guard\n"
        "Comment=VPN-only torrents with quarantine and manual virus-scan release\n"
        f"Exec=/usr/bin/python3 {desktop_argument(PROJECT / 'launch.py')}\n"
        "Icon=network-vpn\n"
        "Terminal=false\n"
        "Categories=Network;\n"
        "StartupNotify=true\n",
        encoding="utf-8",
    )
    print(f"Omarchy launcher installed: {DESTINATION}")


if __name__ == "__main__":
    main()
