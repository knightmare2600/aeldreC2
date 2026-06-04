"""
grid.exe test suite.

Spins up a real TCP listener on localhost and checks that grid finds it.
Also verifies the tab-delimited quiet-mode output format.
"""

import socket
import threading
import time

import pytest
from conftest import exe_path, free_port, wine_run


@pytest.fixture(scope="module")
def grid(wine):
    return exe_path("grid.exe"), wine


def run_grid(grid, *args, timeout=30):
    exe, w = grid
    return wine_run(w, exe, *args, timeout=timeout)


# ------------------------------------------------------------------
# Helper: open a listening socket and keep it alive during a test
# ------------------------------------------------------------------

class Listener:
    def __init__(self, port=None):
        self.port = port or free_port()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", self.port))
        self._sock.listen(32)
        self._sock.settimeout(0.2)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self):
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
                conn.close()
            except socket.timeout:
                pass
        self._sock.close()

    def close(self):
        self._stop.set()
        self._thread.join(timeout=1)


# ------------------------------------------------------------------
# Basic open-port detection
# ------------------------------------------------------------------

def test_finds_open_port(grid):
    l = Listener()
    try:
        r = run_grid(grid, "127.0.0.1", "-p", str(l.port), "-q")
        assert r.returncode == 0
        assert str(l.port) in r.stdout
        assert "open" in r.stdout.lower() or "/tcp" in r.stdout
    finally:
        l.close()


def test_closed_port_not_reported(grid):
    port = free_port()          # bind then immediately release
    r = run_grid(grid, "127.0.0.1", "-p", str(port), "-q")
    # port should not appear as open
    assert "/tcp" not in r.stdout or str(port) not in r.stdout


def test_multiple_ports_csv(grid):
    l1, l2 = Listener(), Listener()
    try:
        ports = f"{l1.port},{l2.port}"
        r = run_grid(grid, "127.0.0.1", "-p", ports, "-q")
        assert str(l1.port) in r.stdout
        assert str(l2.port) in r.stdout
    finally:
        l1.close()
        l2.close()


# ------------------------------------------------------------------
# Output format (quiet mode = tab-delimited)
# ------------------------------------------------------------------

def test_quiet_tsv_format(grid):
    """Quiet output: HOST<TAB>PORT/tcp<TAB>open[<TAB>SERVICE][<TAB>BANNER]"""
    l = Listener()
    try:
        r = run_grid(grid, "127.0.0.1", "-p", str(l.port), "-q")
        lines = [ln for ln in r.stdout.splitlines() if str(l.port) in ln]
        assert lines, "expected at least one result line"
        fields = lines[0].split("\t")
        assert fields[0].strip() == "127.0.0.1"
        assert f"{l.port}/tcp" in fields[1]
        assert "open" in fields[2].lower()
    finally:
        l.close()


# ------------------------------------------------------------------
# Banner grab
# ------------------------------------------------------------------

def test_banner_grab(grid):
    """A listener that sends a banner; grid -b should capture it."""
    port = free_port()
    banner = b"220 AeldreC2 test banner\r\n"

    def serve():
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", port))
        srv.listen(5)
        srv.settimeout(10)
        try:
            conn, _ = srv.accept()
            conn.sendall(banner)
            conn.close()
        except Exception:
            pass
        srv.close()

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    time.sleep(0.05)

    r = run_grid(grid, "127.0.0.1", "-p", str(port), "-q", "-b")
    t.join(timeout=5)
    assert "AeldreC2" in r.stdout or "test banner" in r.stdout


# ------------------------------------------------------------------
# Timeout flag is accepted without error
# ------------------------------------------------------------------

def test_timeout_flag_accepted(grid):
    l = Listener()
    try:
        r = run_grid(grid, "127.0.0.1", "-p", str(l.port), "-t", "200", "-q")
        assert r.returncode == 0
    finally:
        l.close()


# ------------------------------------------------------------------
# Pool size flag is accepted without error
# ------------------------------------------------------------------

def test_pool_size_flag(grid):
    l = Listener()
    try:
        r = run_grid(grid, "127.0.0.1", "-p", str(l.port), "-T", "4", "-q")
        assert r.returncode == 0
        assert str(l.port) in r.stdout
    finally:
        l.close()
