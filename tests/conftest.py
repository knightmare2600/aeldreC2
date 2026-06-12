"""
Shared fixtures for the AeldreC2 test suite.

Yes, we're writing pytest tests for Windows 3.11 C2 software.
History will judge us accordingly.

Requirements:
    pip install pytest requests
    wine (apt: wine-stable)
"""

import os
import socket
import subprocess
import sys
import threading
import time

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
WINDOWS_DIR = os.path.join(REPO_ROOT, "windows")

# ------------------------------------------------------------------
# Wine detection
# ------------------------------------------------------------------

def _find_wine():
    for candidate in ("wine", "wine64", "wine32"):
        r = subprocess.run(["which", candidate], capture_output=True)
        if r.returncode == 0:
            return candidate
    return None

_WINE = _find_wine()


@pytest.fixture(scope="session")
def wine():
    if _WINE is None:
        pytest.skip("wine not found in PATH — skipping Wine-dependent tests")
    return _WINE


@pytest.fixture(scope="session")
def exe_dir():
    return WINDOWS_DIR


def exe_path(name):
    return os.path.join(WINDOWS_DIR, name)


def wine_env(extra=None):
    """
    Build a clean environment dict for running Wine binaries.

    Key settings:
    - WINEDEBUG=-all     suppresses Wine's verbose fixme/err chatter
    - WINEDLLOVERRIDES   uses Wine's built-in secur32 so the binary
                         starts even when a native Windows secur32.dll
                         is absent — fixes the 'SECUR32.DLL not found'
                         error seen when running outside a configured
                         Wine prefix
    - DISPLAY=""         headless; GUI apps need Xvfb or DISPLAY=:N
    """
    env = os.environ.copy()
    env["WINEDEBUG"] = "-all"
    env["WINEDLLOVERRIDES"] = "secur32=b;advapi32=b"
    env.setdefault("DISPLAY", "")
    if extra:
        env.update(extra)
    return env


def wine_run(wine_bin, *args, timeout=15, env=None, **kwargs):
    return subprocess.run(
        [wine_bin, *args],
        capture_output=True,
        encoding="latin-1",   # Windows apps output CP1252, not UTF-8
        timeout=timeout,
        env=wine_env(env),
        **kwargs,
    )


# ------------------------------------------------------------------
# Free-port helper
# ------------------------------------------------------------------

def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ------------------------------------------------------------------
# Simple TCP echo/accept server for network tests
# ------------------------------------------------------------------

class AcceptServer:
    """Accepts exactly one connection, stores received data, closes."""

    def __init__(self, port=None):
        self.port = port or free_port()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", self.port))
        self._sock.listen(1)
        self._sock.settimeout(20)
        self.received = b""
        self.connected = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        try:
            conn, _ = self._sock.accept()
            self.connected.set()
            conn.settimeout(5)
            buf = b""
            try:
                while True:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
            except (socket.timeout, ConnectionResetError):
                pass
            self.received = buf
            conn.close()
        except socket.timeout:
            pass
        finally:
            self._sock.close()

    def wait(self, timeout=10):
        return self.connected.wait(timeout)


# ------------------------------------------------------------------
# Minimal HTTP server for wget tests
# ------------------------------------------------------------------

class MiniHTTPServer:
    """Single-file HTTP/1.0 server."""

    def __init__(self, content=b"Hello from AeldreC2 test server", filename="test.txt"):
        self.port = free_port()
        self.content = content
        self.filename = filename
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        time.sleep(0.05)

    def _serve(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", self.port))
        srv.listen(5)
        srv.settimeout(1)
        while not self._stop.is_set():
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            try:
                conn.recv(4096)
                response = (
                    b"HTTP/1.0 200 OK\r\n"
                    b"Content-Type: text/plain\r\n"
                    + b"Content-Length: " + str(len(self.content)).encode() + b"\r\n"
                    + b"\r\n"
                    + self.content
                )
                conn.sendall(response)
            except Exception:
                pass
            finally:
                conn.close()
        srv.close()

    def stop(self):
        self._stop.set()
        self._thread.join(timeout=2)

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}/{self.filename}"
