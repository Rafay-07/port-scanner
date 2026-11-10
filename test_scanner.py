import socket
import threading

import pytest

import scanner


def serve(banner: bytes | None):
    """Start a throwaway local TCP server on a free port; return (port, stop_function)."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    stop = threading.Event()

    def loop():
        srv.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except OSError:
                continue
            if banner:
                conn.sendall(banner)
            conn.close()

    threading.Thread(target=loop, daemon=True).start()
    return srv.getsockname()[1], lambda: (stop.set(), srv.close())


def test_parse_ports():
    assert scanner.parse_ports("80,22,8000-8002") == [22, 80, 8000, 8001, 8002]
    for bad in ("0", "70000", "10-5", "abc"):
        with pytest.raises(ValueError):
            scanner.parse_ports(bad)


def test_finds_open_port_and_banner():
    port, stop = serve(b"SSH-2.0-TestServer\r\n")
    try:
        r = scanner.probe("127.0.0.1", port)
        assert r["port"] == port and r["banner"].startswith("SSH-2.0")
    finally:
        stop()


def test_closed_port_returns_none():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
    assert scanner.probe("127.0.0.1", port) is None


def test_scan_many_ports_only_reports_open():
    p1, stop1 = serve(None)
    p2, stop2 = serve(b"hello")
    try:
        found = scanner.scan("127.0.0.1", sorted({p1, p2, p1 + 1000 if p1 + 1000 < 65000 else p1 - 1000}))
        assert [r["port"] for r in found] == sorted([p1, p2])
    finally:
        stop1(); stop2()


def test_private_check_and_cli_refuses_public(capsys):
    assert scanner.is_private("127.0.0.1")
    with pytest.raises(SystemExit):
        scanner.main(["8.8.8.8", "-p", "53"])
