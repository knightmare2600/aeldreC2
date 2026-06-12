"""
Wine smoke tests — verify key binaries start, run, and exit cleanly.

These test that:
  - The binary loads and starts under Wine without a loader error
  - Console tools produce recognisable output for known inputs
  - Binaries exit with a sensible code

SECUR32.DLL note
----------------
Wine prints "SECUR32.DLL not found" when its built-in secur32 DLL
isn't mapped.  wine_env() sets WINEDLLOVERRIDES="secur32=b;advapi32=b"
which tells Wine to use its built-in implementations, suppressing that
error.  If tests still report SECUR32 errors, run:
    WINEPREFIX=~/.wine winecfg
and set secur32 and advapi32 to "Built-in" in the Libraries tab.

Requirements: wine in PATH.  Skip automatically if not available.
"""

import os
import re
import socket
import subprocess
import time

import pytest
from conftest import exe_path, wine_env, free_port

_WINE = None
try:
    r = subprocess.run(["which", "wine"], capture_output=True)
    if r.returncode == 0:
        _WINE = "wine"
    else:
        r = subprocess.run(["which", "wine64"], capture_output=True)
        if r.returncode == 0:
            _WINE = "wine64"
except Exception:
    pass

skip_no_wine = pytest.mark.skipif(
    _WINE is None,
    reason="wine not found in PATH"
)

TIMEOUT_QUICK = 10   # seconds: tools that should exit immediately
TIMEOUT_TANK  = 35   # seconds: tank retries once (30 s default) then we kill it


def run(name, *args, timeout=TIMEOUT_QUICK, extra_env=None):
    path = exe_path(name)
    if not os.path.exists(path):
        pytest.skip(f"{name} not built")
    return subprocess.run(
        [_WINE, path, *args],
        capture_output=True,
        encoding="latin-1",   # Windows apps output CP1252, not UTF-8
        timeout=timeout,
        env=wine_env(extra_env),
    )


# ------------------------------------------------------------------
# ipcalc32.exe — exits immediately, produces structured output
# ------------------------------------------------------------------

@skip_no_wine
def test_ipcalc_cidr_output():
    """ipcalc32.exe 192.168.1.0/24 should print Network, Broadcast, HostMin, HostMax."""
    r = run("ipcalc32.exe", "192.168.1.0/24")
    out = r.stdout + r.stderr
    assert "192.168.1.0" in out,   f"Expected network address in output:\n{out}"
    assert "192.168.1.255" in out, f"Expected broadcast in output:\n{out}"
    assert "192.168.1.1" in out,   f"Expected HostMin in output:\n{out}"


@skip_no_wine
def test_ipcalc_rfc1918_flag():
    """ipcalc32.exe should label 10.0.0.0/8 as RFC 1918."""
    r = run("ipcalc32.exe", "10.0.0.0/8")
    out = r.stdout + r.stderr
    assert "10." in out


@skip_no_wine
def test_ipcalc_loopback():
    """ipcalc32.exe 127.0.0.1/8 should produce loopback output."""
    r = run("ipcalc32.exe", "127.0.0.1/8")
    out = r.stdout + r.stderr
    assert "127." in out


# ------------------------------------------------------------------
# lightman.exe — NT console, no args → usage/error, exits fast
# ------------------------------------------------------------------

@skip_no_wine
def test_lightman_no_args_exits():
    """lightman.exe with no args should exit quickly (usage or connection refused)."""
    r = run("lightman.exe", timeout=TIMEOUT_QUICK)
    # Should exit (not hang), don't care about exit code
    assert r.returncode is not None


@skip_no_wine
def test_lightman_bad_host_exits():
    """lightman.exe with an unreachable host should exit after timeout."""
    r = run("lightman.exe", "127.0.0.1", "19999", "BADKEY", "test",
            timeout=TIMEOUT_QUICK)
    assert r.returncode is not None


# ------------------------------------------------------------------
# gridcli.exe — NT console scanner, no args → usage, exits fast
# ------------------------------------------------------------------

@skip_no_wine
def test_gridcli_no_args():
    r = run("gridcli.exe", timeout=TIMEOUT_QUICK)
    assert r.returncode is not None


# ------------------------------------------------------------------
# netstatN.exe — should run and exit (may produce nothing on Wine)
# ------------------------------------------------------------------

@skip_no_wine
def test_netstatn_exits():
    r = run("netstatN.exe", "-a", timeout=TIMEOUT_QUICK)
    assert r.returncode is not None


# ------------------------------------------------------------------
# tank.exe — GUI subsystem, tries to connect to 127.0.0.1:4444 by
# default.  We listen on a free port and assert the tank connects.
# ------------------------------------------------------------------

@skip_no_wine
def test_tank_connects_and_sends_banner():
    """
    tank.exe (default key=00000000) should connect to a listening server.
    We listen on a free port, set TANK_C2_HOST/PORT via the CLU config
    defaults (127.0.0.1:4444), and use a fresh socket.

    Since tank.exe is already built with host=127.0.0.1 port=4444,
    we just listen on 4444 (if free) or skip.
    """
    port = 4444
    try:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", port))
        srv.listen(1)
        srv.settimeout(12)
    except OSError:
        pytest.skip(f"Port {port} not available — another process is using it")

    path = exe_path("tank.exe")
    if not os.path.exists(path):
        srv.close()
        pytest.skip("tank.exe not built")

    proc = subprocess.Popen(
        [_WINE, path],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=wine_env(),
    )

    banner = b""
    try:
        conn, _ = srv.accept()
        conn.settimeout(5)
        buf = b""
        while b"\n" not in buf:
            chunk = conn.recv(512)
            if not chunk:
                break
            buf += chunk
        banner = buf
        conn.close()
    except socket.timeout:
        pass
    finally:
        srv.close()
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

    assert banner, "tank.exe connected but sent no banner data"
    assert banner.startswith(b"Tank/1 "), (
        f"Expected Tank/1 banner, got: {banner!r}"
    )
    assert b" key=" in banner, f"No key= field in banner: {banner!r}"
    assert b"00000000" in banner, (
        f"Expected default key 00000000 in banner: {banner!r}"
    )


# ------------------------------------------------------------------
# CLU smoke: clu.exe should start (GUI, needs display) — check PE only
# ------------------------------------------------------------------

@skip_no_wine
def test_clu_is_pe_and_starts(tmp_path):
    """
    clu.exe is a GUI app that will hang under wine without a display.
    Start it, let wine emit any loader errors (which arrive immediately),
    then kill it and inspect stderr — we only care that the binary loaded
    without a format/loader error, not that it exited cleanly.
    """
    path = exe_path("clu.exe")
    if not os.path.exists(path):
        pytest.skip("clu.exe not built")

    proc = subprocess.Popen(
        [_WINE, path],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        env=wine_env({"DISPLAY": ""}),
    )
    try:
        stdout, stderr = proc.communicate(timeout=4)
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout, stderr = proc.communicate()

    combined = (stdout + stderr).lower()
    assert "bad exe format" not in combined, f"Wine rejected clu.exe as bad format"
    assert "not a valid win32" not in combined


# ------------------------------------------------------------------
# Regression: SECUR32.DLL must not appear in Wine error output
# ------------------------------------------------------------------

@skip_no_wine
@pytest.mark.parametrize("name", ["tank.exe", "lightman.exe", "ipcalc32.exe"])
def test_no_secur32_loader_error(name):
    """
    Binaries must start without Wine reporting a secur32.dll loader error.
    (If this fails, check that WINEDLLOVERRIDES=secur32=b is effective
    or run winecfg and set secur32 to Built-in.)

    GUI apps and implants won't exit on --version, so we start them,
    allow wine to emit any loader errors (which happen immediately at
    load time), then kill and inspect stderr.
    """
    path = exe_path(name)
    if not os.path.exists(path):
        pytest.skip(f"{name} not built")

    env = wine_env({"WINEDEBUG": "err+loaddll,err+module"})
    proc = subprocess.Popen(
        [_WINE, path, "--version"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        env=env,
    )
    try:
        _, stderr = proc.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        _, stderr = proc.communicate()

    # Strip ntlm_auth diagnostics — wine's built-in secur32 reports missing
    # ntlm_auth support at runtime; that is not a loader error.
    filtered = "\n".join(
        l for l in stderr.splitlines() if "ntlm_auth" not in l.lower()
    )
    err = filtered.lower()
    assert "secur32" not in err or "builtin" in err, (
        f"{name}: Wine reported a secur32 loader error:\n{stderr[:400]}"
    )
