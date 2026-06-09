"""
clu.exe / binary patcher test suite.

CLU is a GUI tool so full automation under Wine requires SendMessage/WM_ tricks
that aren't worth the pain in CI.  What we can test without the GUI:

  1. tank.exe and tank16.exe contain the expected CLU magic signature
  2. The magic block has the correct structure (offset constants)
  3. A Python re-implementation of the patch operation round-trips correctly
  4. GUI smoke test: clu.exe launches under Wine without immediately crashing
"""

import os
import struct

import pytest
from conftest import exe_path, wine_run

CLU_MAGIC = b"AELDRECLU0001"
MAGIC_LEN  = len(CLU_MAGIC)

# Layout after the magic: host[64] + port[2] (big-endian) + tls[1]
# char magic[14] includes the null terminator, so host starts at offset 14.
# Total config block: 14 + 64 + 2 + 1 = 81 bytes
HOST_OFFSET = MAGIC_LEN + 1  # +1 for the null terminator in char magic[14]
HOST_LEN    = 64
PORT_OFFSET = HOST_OFFSET + HOST_LEN
TLS_OFFSET  = PORT_OFFSET + 2


def read_exe(name):
    path = exe_path(name)
    if not os.path.exists(path):
        pytest.skip(f"{name} not built")
    return open(path, "rb").read()


def find_magic(data):
    idx = data.find(CLU_MAGIC)
    if idx == -1:
        return None
    return idx


def decode_config(data, offset):
    host_bytes = data[offset + HOST_OFFSET: offset + HOST_OFFSET + HOST_LEN]
    host = host_bytes.rstrip(b"\x00").decode("ascii", errors="replace")
    port = struct.unpack_from(">H", data, offset + PORT_OFFSET)[0]
    tls  = data[offset + TLS_OFFSET]
    return host, port, tls


def patch_config(data, offset, host, port, tls=0):
    data = bytearray(data)
    hb = host.encode("ascii")[:HOST_LEN]
    hb = hb + b"\x00" * (HOST_LEN - len(hb))
    data[offset + HOST_OFFSET: offset + HOST_OFFSET + HOST_LEN] = hb
    struct.pack_into(">H", data, offset + PORT_OFFSET, port)
    data[offset + TLS_OFFSET] = tls
    return bytes(data)


# ------------------------------------------------------------------
# Signature checks
# ------------------------------------------------------------------

def test_tank32_has_magic():
    data = read_exe("tank.exe")
    assert find_magic(data) is not None, "tank.exe missing CLU magic block"


def test_tank16_has_magic():
    data = read_exe("tank16.exe")
    assert find_magic(data) is not None, "tank16.exe missing CLU magic block"


# ------------------------------------------------------------------
# Config block structure
# ------------------------------------------------------------------

def test_tank32_default_config_readable():
    data = read_exe("tank.exe")
    off = find_magic(data)
    assert off is not None
    host, port, tls = decode_config(data, off)
    # Must not raise; host/port may be zeroed (default unpatched build)
    assert isinstance(host, str)
    assert 0 <= port <= 65535
    assert tls in (0, 1)


# ------------------------------------------------------------------
# Round-trip patch
# ------------------------------------------------------------------

def test_patch_roundtrip_tank32():
    data = read_exe("tank.exe")
    off = find_magic(data)
    assert off is not None

    patched = patch_config(data, off, "172.16.93.1", 4444, tls=0)
    host, port, tls = decode_config(patched, off)
    assert host == "172.16.93.1"
    assert port == 4444
    assert tls == 0


def test_patch_roundtrip_tls():
    data = read_exe("tank.exe")
    off = find_magic(data)
    assert off is not None

    patched = patch_config(data, off, "10.0.0.1", 443, tls=1)
    host, port, tls = decode_config(patched, off)
    assert host == "10.0.0.1"
    assert port == 443
    assert tls == 1


def test_patch_does_not_alter_magic():
    data = read_exe("tank.exe")
    off = find_magic(data)
    patched = patch_config(data, off, "192.168.1.1", 1234)
    assert patched[off: off + MAGIC_LEN] == CLU_MAGIC


def test_patch_does_not_grow_binary():
    data = read_exe("tank.exe")
    off = find_magic(data)
    patched = patch_config(data, off, "1.2.3.4", 8080)
    assert len(patched) == len(data)


# ------------------------------------------------------------------
# GUI smoke test: clu.exe should launch (and exit cleanly when closed)
# ------------------------------------------------------------------

def test_clu_launches(wine):
    import subprocess, signal, time

    clu = exe_path("clu.exe")
    if not os.path.exists(clu):
        pytest.skip("clu.exe not built")

    env = {"WINEDEBUG": "-all", "DISPLAY": ""}
    proc = subprocess.Popen(
        [wine, clu],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={**os.environ, **env},
    )
    time.sleep(2)
    still_running = proc.poll() is None
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()

    # If it crashed instantly (returncode != 0 before we killed it) that's a fail
    assert still_running or proc.returncode == 0, \
        f"clu.exe exited immediately with code {proc.returncode}"
