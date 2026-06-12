"""
C2 protocol test suite — Tank implant ↔ Joshua controller.

Strategy
--------
Build a test implant (tank_test.exe) at test time with C2HOST=127.0.0.1,
C2PORT=<free-port>, and TANK_C2_KEY=DEADBEEF.  Run it under Wine against
a Python mock server that speaks enough of the Joshua wire protocol to
receive the Tank/1 banner and reply to basic commands.

Gate
----
Set C2_INTEGRATION=1 to run these tests.  They require:
  - Docker (to build the test implant)
  - Wine (to run tank.exe)
  - aeldrec2-builder image (docker build -t aeldrec2-builder .)

To run locally:
    C2_INTEGRATION=1 pytest tests/test_c2_protocol.py -v

Protocol (from tank.c)
----------------------
After connect, Tank immediately sends:
    Tank/1 host=<hostname> os=<major>.<minor>.<build> shell=<path> key=<8hex>\n
Then blocks waiting for commands.  Commands are newline-terminated.
Responses end with <<<DONE>>>\n.
"""

import os
import re
import socket
import subprocess
import threading
import time

import pytest
from conftest import AcceptServer, exe_path, free_port, wine_env

INTEGRATION = os.environ.get("C2_INTEGRATION", "0") == "1"
skip_unless_integration = pytest.mark.skipif(
    not INTEGRATION, reason="set C2_INTEGRATION=1 to run C2 protocol tests"
)

# Known test key — baked into the test implant at build time
TEST_KEY = "DEADBEEF"
DOCKER_IMAGE = "aeldrec2-builder"


# ------------------------------------------------------------------
# Build a test implant pointing at localhost with a known key
# ------------------------------------------------------------------

def _inside_docker():
    return os.path.exists("/.dockerenv")


def build_test_implant(port, tmp_path, key=TEST_KEY):
    """
    Build tank.exe with C2HOST=127.0.0.1, C2PORT=<port>, TANK_C2_KEY=<key>.
    Returns path to output binary, or None if the build fails.

    When running inside the builder container (/.dockerenv exists) wmake is
    already on PATH and /src is the repo — no docker-in-docker needed.
    From the host, the build runs via docker run as before.

    Either way, windows/tank.exe is saved before the build and restored
    afterward so smoke tests keep the default 127.0.0.1:4444 / 00000000 binary.
    """
    import shutil

    out   = tmp_path / "tank_test.exe"
    repo  = "/src" if _inside_docker() else os.path.abspath(
                os.path.join(os.path.dirname(__file__), ".."))
    src   = os.path.join(repo, "windows", "tank.exe")

    # Save original
    backup = None
    if os.path.exists(src):
        backup = tmp_path / "tank_orig.exe"
        shutil.copy2(src, str(backup))

    xflags = (f"-DTANK_C2_HOST=127.0.0.1"
              f" -DTANK_C2_PORT={port}"
              f" -DTANK_C2_KEY={key}")

    if _inside_docker():
        cmd = ["wmake", "-a", "-f", "Makefile.wc", "tank.exe", f"XFLAGS={xflags}"]
        r = subprocess.run(cmd, capture_output=True, timeout=180,
                           cwd=os.path.join(repo, "windows"))
    else:
        cmd = [
            "docker", "run", "--rm",
            "-v", f"{repo}:/src", "-w", "/src/windows",
            DOCKER_IMAGE,
            "wmake", "-a", "-f", "Makefile.wc", "tank.exe",
            f"XFLAGS={xflags}",
        ]
        r = subprocess.run(cmd, capture_output=True, timeout=180)

    built = os.path.exists(src) and r.returncode == 0
    if built:
        shutil.copy2(src, str(out))

    # Always restore original
    if backup and os.path.exists(str(backup)):
        shutil.copy2(str(backup), src)

    return str(out) if built else None


# ------------------------------------------------------------------
# Mock Joshua server that speaks the wire protocol
# ------------------------------------------------------------------

class MockJoshua:
    """
    Accepts one Tank connection.

    Protocol:
      Tank → Server:  Tank/1 host=X os=Y shell=Z key=K\\n
      Server does nothing further (tank blocks waiting for commands).
      Server closes after collecting the banner.
    """

    TEST_KEY = TEST_KEY

    def __init__(self, port=None):
        self.port = port or free_port()
        self.banner = b""
        self.connected = threading.Event()
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", self.port))
        self._srv.listen(1)
        self._srv.settimeout(20)
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        try:
            conn, _ = self._srv.accept()
            self.connected.set()
            conn.settimeout(8)
            buf = b""
            try:
                while b"\n" not in buf:
                    chunk = conn.recv(1024)
                    if not chunk:
                        break
                    buf += chunk
            except (socket.timeout, ConnectionResetError):
                pass
            self.banner = buf
            conn.close()
        except socket.timeout:
            pass
        finally:
            self._srv.close()

    def wait_connect(self, timeout=15):
        return self.connected.wait(timeout)

    def banner_str(self):
        return self.banner.decode("ascii", errors="replace")


# ------------------------------------------------------------------
# Protocol tests
# ------------------------------------------------------------------

@skip_unless_integration
def test_tank_connects_to_c2(wine, tmp_path):
    """tank.exe must establish a TCP connection to the configured C2 host."""
    srv = MockJoshua()
    implant = build_test_implant(srv.port, tmp_path)
    if implant is None:
        pytest.skip(f"Could not build test implant (Docker / {DOCKER_IMAGE} not available?)")

    proc = subprocess.Popen(
        [wine, implant],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=wine_env(),
    )
    connected = srv.wait_connect(timeout=15)
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()

    assert connected, "Tank did not connect to mock C2 within 15 s"


@skip_unless_integration
def test_tank_sends_banner(wine, tmp_path):
    """Tank must send a Tank/1 banner immediately after connecting."""
    srv = MockJoshua()
    implant = build_test_implant(srv.port, tmp_path)
    if implant is None:
        pytest.skip("Could not build test implant")

    proc = subprocess.Popen(
        [wine, implant],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=wine_env(),
    )
    srv.wait_connect(timeout=15)
    time.sleep(2)
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()

    banner = srv.banner_str()
    assert banner.startswith("Tank/1 "), (
        f"Expected banner starting with 'Tank/1 ', got: {banner!r}"
    )


@skip_unless_integration
def test_tank_banner_fields(wine, tmp_path):
    """Banner must contain host=, os=, shell=, and key= fields."""
    srv = MockJoshua()
    implant = build_test_implant(srv.port, tmp_path)
    if implant is None:
        pytest.skip("Could not build test implant")

    proc = subprocess.Popen(
        [wine, implant],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=wine_env(),
    )
    srv.wait_connect(timeout=15)
    time.sleep(2)
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()

    banner = srv.banner_str()
    assert "host=" in banner,  f"No host= in banner: {banner!r}"
    assert "os="   in banner,  f"No os= in banner: {banner!r}"
    assert "shell=" in banner, f"No shell= in banner: {banner!r}"
    assert " key=" in banner,  f"No key= in banner: {banner!r}"

    # Key must match what we baked into the implant
    m = re.search(r" key=([0-9A-Fa-f]{8})", banner)
    assert m, f"key= field missing or malformed in banner: {banner!r}"
    assert m.group(1).upper() == TEST_KEY.upper(), (
        f"Banner key {m.group(1)!r} != expected {TEST_KEY!r}"
    )


@skip_unless_integration
def test_tank_banner_os_is_windows(wine, tmp_path):
    """os= field must look like a Windows version (digits.digits.digits)."""
    srv = MockJoshua()
    implant = build_test_implant(srv.port, tmp_path)
    if implant is None:
        pytest.skip("Could not build test implant")

    proc = subprocess.Popen(
        [wine, implant],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=wine_env(),
    )
    srv.wait_connect(timeout=15)
    time.sleep(2)
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()

    banner = srv.banner_str()
    m = re.search(r"os=(\d+\.\d+)", banner)
    assert m, f"os= field not in expected format in banner: {banner!r}"


# ------------------------------------------------------------------
# Non-integration: sanity checks on built binary
# ------------------------------------------------------------------

def test_tank_exe_exists():
    path = exe_path("tank.exe")
    assert os.path.exists(path), "tank.exe not built — run docker build first"


def test_tank16_exe_exists():
    path = exe_path("tank16.exe")
    assert os.path.exists(path), "tank16.exe not built"


def test_clu_magic_in_tank():
    """CLU config block must be present and have the correct layout."""
    path = exe_path("tank.exe")
    if not os.path.exists(path):
        pytest.skip("tank.exe not built")
    with open(path, "rb") as f:
        data = f.read()
    magic = b"AELDRECLU0001"
    pos = data.find(magic)
    assert pos >= 0, "CLU magic not found in tank.exe"
    # Block layout: 14 magic + 64 host + 2 port + 1 tls + 9 key = 90 bytes
    assert pos + 90 <= len(data), "CLU block extends past end of file"


def test_clu_magic_in_tank16():
    """CLU config block must be present in tank16.exe."""
    path = exe_path("tank16.exe")
    if not os.path.exists(path):
        pytest.skip("tank16.exe not built")
    with open(path, "rb") as f:
        data = f.read()
    magic = b"AELDRECLU0001"
    assert data.find(magic) >= 0, "CLU magic not found in tank16.exe"


def test_clu_default_key_is_zeros():
    """Default tank.exe key field must be 00000000 (unpatched)."""
    path = exe_path("tank.exe")
    if not os.path.exists(path):
        pytest.skip("tank.exe not built")
    with open(path, "rb") as f:
        data = f.read()
    pos = data.find(b"AELDRECLU0001")
    assert pos >= 0
    # offset 81 from magic = key field
    key_bytes = data[pos + 81 : pos + 89]
    assert key_bytes == b"00000000", (
        f"Expected default key '00000000', got {key_bytes!r}"
    )
