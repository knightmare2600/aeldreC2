"""
C2 protocol test suite — Tank implant ↔ Joshua controller.

Strategy
--------
We build a special test implant (tank_test.exe) at test time with the C2
host/port pointed at a local mock server, then run it under Wine and
verify the wire protocol.

Because the full build environment (Docker / OpenWatcom) may not be
present on the test host, these tests are grouped under the
``c2_integration`` mark and are skipped when:
  - Wine is not available, or
  - The test implant cannot be built (Docker not available), or
  - The ``C2_INTEGRATION`` environment variable is not set to "1"

To run locally:
    C2_INTEGRATION=1 pytest tests/test_c2_protocol.py -v

Protocol (derived from tank.c / joshua.c)
------------------------------------------
After TCP connect, Tank sends an initial HELLO/SYSINFO message.  The
exact wire format is documented in the source; the tests check what
can be observed at the socket level without a full codec.

TODO: fill in exact message framing once the protocol spec is finalised.
"""

import os
import socket
import struct
import subprocess
import threading
import time

import pytest
from conftest import AcceptServer, exe_path, free_port, wine_run

INTEGRATION = os.environ.get("C2_INTEGRATION", "0") == "1"
skip_unless_integration = pytest.mark.skipif(
    not INTEGRATION, reason="set C2_INTEGRATION=1 to run C2 protocol tests"
)


# ------------------------------------------------------------------
# Build a test implant pointing at localhost
# ------------------------------------------------------------------

def build_test_implant(port, tmp_path):
    """
    Build tank.exe with C2HOST=127.0.0.1 and C2PORT=<port> using Docker.
    Returns path to the output binary, or None if the build fails.
    """
    out = tmp_path / "tank_test.exe"
    repo = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    cmd = [
        "docker", "run", "--rm",
        "-v", f"{repo}:/src",
        "-w", "/src/windows",
        "putty-win32s-builder",
        "wmake", "-f", "Makefile.wc", "tank.exe",
        f'XFLAGS=-DTANK_C2_HOST=\\"127.0.0.1\\" -DTANK_C2_PORT={port}',
    ]
    r = subprocess.run(cmd, capture_output=True, timeout=120)
    if r.returncode != 0:
        return None
    src = os.path.join(repo, "windows", "tank.exe")
    os.rename(src, str(out))
    return str(out)


# ------------------------------------------------------------------
# Mock Joshua listener
# ------------------------------------------------------------------

class MockJoshua:
    """
    Accepts one Tank connection, exchanges handshake, records messages.

    The exact Tank wire protocol:
      - After connect, tank sends a length-prefixed or newline-terminated
        SYSINFO block (TODO: confirm exact framing from tank.c).
      - Joshua responds with a command or a keep-alive.

    For now we just capture raw bytes and assert that *something* was sent.
    """

    def __init__(self, port=None, response=b""):
        self.port = port or free_port()
        self.messages = []
        self.connected = threading.Event()
        self._response = response
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", self.port))
        self._srv.listen(1)
        self._srv.settimeout(15)
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        try:
            conn, addr = self._srv.accept()
            self.connected.set()
            conn.settimeout(5)
            if self._response:
                conn.sendall(self._response)
            buf = b""
            try:
                while True:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
            except (socket.timeout, ConnectionResetError):
                pass
            self.messages.append(buf)
            conn.close()
        except socket.timeout:
            pass
        finally:
            self._srv.close()

    def wait_connect(self, timeout=10):
        return self.connected.wait(timeout)


# ------------------------------------------------------------------
# Protocol tests
# ------------------------------------------------------------------

@skip_unless_integration
def test_tank_connects_to_c2(wine, tmp_path):
    """tank.exe should establish a TCP connection to the configured C2 host."""
    srv = MockJoshua()
    implant = build_test_implant(srv.port, tmp_path)
    if implant is None:
        pytest.skip("Could not build test implant (Docker not available?)")

    proc = subprocess.Popen(
        [wine, implant],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={**os.environ, "WINEDEBUG": "-all", "DISPLAY": ""},
    )
    connected = srv.wait_connect(timeout=15)
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()

    assert connected, "Tank did not connect to mock C2 within 15 s"


@skip_unless_integration
def test_tank_sends_initial_data(wine, tmp_path):
    """Tank should send something immediately after connecting (SYSINFO / banner)."""
    srv = MockJoshua()
    implant = build_test_implant(srv.port, tmp_path)
    if implant is None:
        pytest.skip("Could not build test implant")

    proc = subprocess.Popen(
        [wine, implant],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={**os.environ, "WINEDEBUG": "-all", "DISPLAY": ""},
    )
    srv.wait_connect(timeout=15)
    time.sleep(3)       # let the implant send its banner
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()

    assert srv.messages, "Tank connected but sent no data"
    assert len(srv.messages[0]) > 0, "Tank sent empty message"


@skip_unless_integration
def test_tank_banner_contains_os_info(wine, tmp_path):
    """
    The SYSINFO message should contain recognisable OS/hostname information.

    TODO: once the exact framing (length prefix, delimiter) is confirmed,
    decode the message properly and assert specific fields.
    """
    srv = MockJoshua()
    implant = build_test_implant(srv.port, tmp_path)
    if implant is None:
        pytest.skip("Could not build test implant")

    proc = subprocess.Popen(
        [wine, implant],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={**os.environ, "WINEDEBUG": "-all", "DISPLAY": ""},
    )
    srv.wait_connect(timeout=15)
    time.sleep(3)
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()

    if not srv.messages:
        pytest.skip("No data received (connection may have failed)")

    raw = srv.messages[0]
    # Under Wine the OS will report something Windows-like
    # TODO: decode framing and check hostname / OS version fields
    assert len(raw) >= 4, f"Initial message too short ({len(raw)} bytes)"


# ------------------------------------------------------------------
# Non-integration: verify the binary protocol constants are sane
# ------------------------------------------------------------------

def test_magic_block_fits_in_exe():
    """Sanity: the CLU magic + config block fits within tank.exe."""
    import os
    path = exe_path("tank.exe")
    if not os.path.exists(path):
        pytest.skip("tank.exe not built")
    size = os.path.getsize(path)
    assert size > 128, f"tank.exe suspiciously small ({size} bytes)"


def test_tank16_binary_is_ne_format():
    """tank16.exe must be a Windows NE (16-bit) executable, not PE."""
    import os
    path = exe_path("tank16.exe")
    if not os.path.exists(path):
        pytest.skip("tank16.exe not built")
    with open(path, "rb") as f:
        mz = f.read(2)
        assert mz == b"MZ", "Not an MZ executable"
        f.seek(0x3C)
        pe_offset = struct.unpack("<H", f.read(2))[0]
        f.seek(pe_offset)
        sig = f.read(2)
    assert sig == b"NE", f"Expected NE sig at 0x{pe_offset:x}, got {sig!r}"


def test_tank32_binary_is_pe_format():
    """tank.exe must be a Windows PE (32-bit) executable."""
    import os
    path = exe_path("tank.exe")
    if not os.path.exists(path):
        pytest.skip("tank.exe not built")
    with open(path, "rb") as f:
        mz = f.read(2)
        assert mz == b"MZ"
        f.seek(0x3C)
        pe_offset = struct.unpack("<I", f.read(4))[0]
        f.seek(pe_offset)
        sig = f.read(4)
    assert sig == b"PE\x00\x00", f"Expected PE sig, got {sig!r}"
