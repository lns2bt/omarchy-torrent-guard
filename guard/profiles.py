"""Import only passive Mullvad WireGuard configurations, never wg-quick hooks."""
import base64
import configparser
import ipaddress
import io
import re
import uuid
import zipfile


class InvalidProfile(ValueError):
    pass


def _key(value):
    try:
        return len(base64.b64decode(value, validate=True)) == 32
    except (ValueError, base64.binascii.Error):
        return False


def parse_profile(data, name):
    if len(data) > 128 * 1024:
        raise InvalidProfile("WireGuard profile exceeds 128 KB.")
    try:
        text = data.decode("utf-8-sig")
        parser = configparser.ConfigParser(interpolation=None, strict=True)
        parser.read_string(text)
        if set(parser.sections()) != {"Interface", "Peer"}:
            raise InvalidProfile("A profile must contain one Interface and one Peer section.")
        interface, peer = parser["Interface"], parser["Peer"]
        if set(interface) - {"privatekey", "address", "dns", "mtu"} or set(peer) - {
            "publickey", "allowedips", "endpoint", "persistentkeepalive", "presharedkey"
        }:
            raise InvalidProfile("Unsupported WireGuard settings (including shell hooks).")
        private, public = interface["privatekey"].strip(), peer["publickey"].strip()
        if not _key(private) or not _key(public):
            raise InvalidProfile("The WireGuard key is invalid.")
        ipv4 = next((item.strip() for item in interface["address"].split(",")
                     if ":" not in item), "")
        address = ipaddress.IPv4Interface(ipv4)
        endpoint = peer["endpoint"].strip()
        match = re.fullmatch(r"(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})", endpoint)
        if not match or not (1 <= int(match[2]) <= 65535):
            raise InvalidProfile("Endpoint must be an IPv4 address and port.")
        ipaddress.IPv4Address(match[1])
        allowed = {item.strip() for item in peer["allowedips"].split(",")}
        if "0.0.0.0/0" not in allowed:
            raise InvalidProfile("The profile does not route all IPv4 traffic through the VPN.")
        # Build a minimal, validated config; never pass arbitrary uploaded fields to Gluetun.
        result = (f"[Interface]\nPrivateKey = {private}\nAddress = {address}\n\n"
                  f"[Peer]\nPublicKey = {public}\nAllowedIPs = 0.0.0.0/0\n"
                  f"Endpoint = {endpoint}\n")
        if "presharedkey" in peer:
            value = peer["presharedkey"].strip()
            if not _key(value):
                raise InvalidProfile("Invalid preshared key.")
            result += f"PresharedKey = {value}\n"
        if "persistentkeepalive" in peer:
            interval = int(peer["persistentkeepalive"])
            if not 0 <= interval <= 65535:
                raise InvalidProfile("Invalid keepalive interval.")
            result += f"PersistentKeepalive = {interval}\n"
        return {"id": uuid.uuid4().hex, "name": re.sub(r"[^\w .-]", "_", name)[:90],
                "config": result}
    except (KeyError, ValueError, configparser.Error) as exc:
        if isinstance(exc, InvalidProfile):
            raise
        raise InvalidProfile("Invalid Mullvad WireGuard configuration.") from exc


def import_profiles(blob, filename):
    if filename.lower().endswith(".conf"):
        return [parse_profile(blob, filename.rsplit("/", 1)[-1].removesuffix(".conf"))]
    if not filename.lower().endswith(".zip") or len(blob) > 25 * 1024 * 1024:
        raise InvalidProfile("Choose a .conf file or a ZIP archive under 25 MB.")
    try:
        with zipfile.ZipFile(io.BytesIO(blob)) as archive:
            entries = archive.infolist()
            if len(entries) > 1000:
                raise InvalidProfile("Too many archive entries.")
            files = [item for item in entries if not item.is_dir() and item.filename.lower().endswith(".conf")]
            if not files or len(files) > 200 or sum(item.file_size for item in files) > 10 * 1024 * 1024:
                raise InvalidProfile("The archive needs 1–200 .conf files (at most 10 MB total).")
            profiles = []
            for item in files:
                if item.flag_bits & 1 or item.file_size > 128 * 1024:
                    raise InvalidProfile("Encrypted or oversized profile in ZIP.")
                # Read a bounded stream, not extract(): paths and links in the ZIP are ignored.
                with archive.open(item) as stream:
                    data = stream.read(128 * 1024 + 1)
                profiles.append(parse_profile(data, item.filename.replace("\\", "/").split("/")[-1].removesuffix(".conf")))
            return profiles
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        raise InvalidProfile("Invalid or damaged ZIP archive.") from exc
