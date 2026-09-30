# Torrent Guard

Local English-language Omarchy app for Mullvad WireGuard torrent downloads, ClamAV quarantine scans, and **manual** release to `~/Downloads`.

## Setup (Omarchy / Arch)

Install or refresh the Omarchy launcher after checking out this repository or moving its directory:

```sh
python3 install_launcher.py
```

The app launcher is installed at `~/.local/share/applications/omarchy-torrent-guard.desktop`. Search for **Torrent Guard** in the Omarchy launcher. Chromium opens it as a local app window. The Python service binds to `127.0.0.1:18765` and does not need Docker access.

Before downloading, install ClamAV and update signatures in an interactive terminal:

```sh
sudo pacman -S clamav
sudo freshclam
sudo systemctl enable --now clamav-freshclam.service
sudo systemctl enable --now docker.socket
```

The first time you select **Connect** in the UI, a Polkit password prompt authorizes Docker Compose to create the VPN and torrent containers. Image downloads can take several minutes. Do not add your user to the `docker` group: that group grants root-equivalent access. Make sure port 19091 and 18000 are unused on localhost.

1. Launch Torrent Guard, import a Mullvad `.conf` or ZIP of `.conf` files, select a profile and click **Connect**.
2. When the status shows **VPN CONNECTED**, add a magnet link or `.torrent` file.
3. Transmission stops each completed torrent. Torrent Guard makes a separate snapshot, scans it with fresh ClamAV signatures, and reports the result. Torrents may upload *while downloading*; they do not continue seeding afterwards.
4. For a scan with no findings, click **Release to Downloads** and confirm. The files appear together in `~/Downloads/<torrent name>/`. Infected, encrypted or incompletely scanned content cannot be released.

The download cards show completed/total size, connected and currently transferring peers, download speed, and an ETA when Transmission can calculate one. The **System usage** card shows approximate CPU and memory for the VPN, client, app, and active scanner; container memory includes reclaimable filesystem cache. Quarantine and scan-snapshot disk use and current torrent traffic are shown separately. These readings come from read-only Linux cgroups and processes, without granting the app Docker socket access.

Closing only the browser window leaves the local Python controller, VPN and torrent container running. Downloads and scans continue in the background. **Disconnect** stops active torrents and the two containers but leaves the local UI running; **Safe shutdown** also ends the local Python controller after the browser receives confirmation. If a browser does not permit the app window to close itself, close the window manually after the confirmation. A running scan must complete before Safe shutdown. Neither action deletes quarantine or scan snapshots, and incomplete torrents require an explicit **Resume download** after the next **Connect**. Safe shutdown leaves the system-wide Docker service and ClamAV signature updater alone. Restarting the launcher starts only the local controller and browser, not the VPN; Connect is explicit. If an unexpected controller exit interrupts a scan, it is rescanned from quarantine after the controller and client are available again, without releasing it in the meantime.

If the scanner was unavailable or its signatures were outdated, update it and use **Retry scan** on the blocked download.

The Compose stack uses Gluetun's built-in firewall and only publishes RPC and read-only VPN status on `127.0.0.1`. Transmission shares Gluetun's network namespace and has no independent network. The download mount is `~/.local/share/omarchy-torrent-guard/quarantine`; `~/Downloads` is **never** mounted in the torrent container. Keys, RPC password and scan snapshots reside under `~/.local/share/omarchy-torrent-guard/` with private permissions. Never share that directory. The app does not alter the existing `omarchy-wireguard` installation or connect the host system to Mullvad.

ClamAV flags encrypted files and archive scanning limits, and refuses release if signatures are older than 48 hours. It cannot guarantee that a file is harmless. Archives are never automatically extracted. For high-risk software, use a VM before executing it.

## Maintenance / diagnostics

From an interactive terminal (Docker requires sudo):

```sh
sudo docker compose --project-directory "$HOME/Work/omarchy-torrent-guard" --env-file "$HOME/.local/share/omarchy-torrent-guard/compose.env" -f "$HOME/Work/omarchy-torrent-guard/compose.yaml" ps
systemctl status clamav-freshclam.service
```

The VPN does not start until a profile is selected. If Docker cannot start, confirm `docker.socket` is running and check `/dev/net/tun`. For a VPN interruption, Gluetun blocks the torrent network; the UI displays an unavailable state. The user's normal WireGuard profile is not a substitute for this tunnel. Container images and ClamAV signatures need periodic updates. Mullvad does not offer port forwarding, so incoming torrent connections may be limited.

If a torrent displays **Tracker unreachable**, that tracker is not answering; the client still searches DHT for peers. If it displays **Tracker reachable, but reports no seeders**, the VPN and tracker are working, but this tracker cannot supply a complete peer. The app continues searching DHT. Try a well-seeded public torrent or wait for a seeder; the app cannot download missing data from a swarm without one.

## Development

```sh
cd ~/Work/omarchy-torrent-guard
python3 -m unittest discover -s tests -v
```

The web server uses only the Python standard library. API mutations require a session token and an exact local Origin, and the server rejects non-local Host headers. ZIP import has entry and byte limits, does not extract files, rejects wg-quick hooks, and reconstructs an allow-listed Gluetun WireGuard config. The browser and downloader have no Docker socket. Only an explicit **Connect** action triggers Polkit authorization.
