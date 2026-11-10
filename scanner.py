"""TCP connect port scanner with banner grabbing, built on the standard library.

A "connect scan" simply tries to open a TCP connection to each port. If the
connection succeeds, the port is open. Threads let us test many ports at once,
because each attempt spends most of its time waiting.

Use it only on machines you own or have written permission to test. By default
it refuses public IP addresses to prevent accidents.
"""
import argparse
import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor

# A few well-known ports, to label results. Not exhaustive.
SERVICES = {21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
            110: "pop3", 143: "imap", 443: "https", 445: "smb", 3306: "mysql",
            3389: "rdp", 5432: "postgres", 8080: "http-alt"}
# Services that send passwords unencrypted: worth flagging in a report.
RISKY = {21: "FTP sends passwords in clear text", 23: "Telnet sends passwords in clear text",
         445: "SMB exposed; common ransomware target", 3389: "RDP exposed to the network"}


def parse_ports(spec: str) -> list[int]:
    """'22,80,8000-8010' -> [22, 80, 8000, ..., 8010]. Raises ValueError on bad input."""
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = (int(x) for x in part.split("-"))
            if lo > hi:
                raise ValueError(f"bad range: {part}")
            ports.update(range(lo, hi + 1))
        else:
            ports.add(int(part))
    if not ports or min(ports) < 1 or max(ports) > 65535:
        raise ValueError("ports must be between 1 and 65535")
    return sorted(ports)


def is_private(host: str) -> bool:
    """True for loopback and private-network addresses (127.x, 10.x, 192.168.x, 172.16-31.x)."""
    ip = ipaddress.ip_address(socket.gethostbyname(host))
    return ip.is_loopback or ip.is_private


def probe(host: str, port: int, timeout: float = 0.5) -> dict | None:
    """Try one port. Return a result dict if open, else None."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            banner = ""
            try:
                banner = s.recv(128).decode(errors="replace").strip()   # many services greet first
            except (socket.timeout, OSError):
                pass                                                    # others wait for us to speak
            return {"port": port, "service": SERVICES.get(port, "unknown"), "banner": banner,
                    "risk": RISKY.get(port, "")}
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


def scan(host: str, ports: list[int], workers: int = 100, timeout: float = 0.5) -> list[dict]:
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = pool.map(lambda p: probe(host, p, timeout), ports)
    return sorted((r for r in results if r), key=lambda r: r["port"])


def main(argv=None):
    ap = argparse.ArgumentParser(description="TCP connect scanner (own machines only)")
    ap.add_argument("host")
    ap.add_argument("-p", "--ports", default="1-1024")
    ap.add_argument("--allow-public", action="store_true", help="I own or am authorized to test this host")
    a = ap.parse_args(argv)
    if not a.allow_public and not is_private(a.host):
        ap.error("refusing public address; pass --allow-public only if you are authorized")
    found = scan(a.host, parse_ports(a.ports))
    for r in found:
        note = f"  ! {r['risk']}" if r["risk"] else ""
        print(f"{r['port']:>5}/tcp open  {r['service']:<9} {r['banner'][:40]}{note}")
    print(f"{len(found)} open port(s) found")
    return found


if __name__ == "__main__":
    main()
