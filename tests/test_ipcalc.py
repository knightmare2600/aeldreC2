"""
ipcalc32.exe test suite.

Pure-computation tool: feed in CIDR/mask, check the text output.
Runs under Wine; falls back to a skip if Wine isn't present.
"""

import pytest
from conftest import exe_path, wine_run


@pytest.fixture(scope="module")
def ipcalc(wine):
    return exe_path("ipcalc32.exe"), wine


def run(ipcalc, *args):
    exe, w = ipcalc
    return wine_run(w, exe, *args)


# ------------------------------------------------------------------
# Basic CIDR decomposition
# ------------------------------------------------------------------

def test_class_c_network(ipcalc):
    r = run(ipcalc, "192.168.1.0/24")
    assert r.returncode == 0
    assert "192.168.1.0" in r.stdout
    assert "255.255.255.0" in r.stdout
    assert "192.168.1.255" in r.stdout      # broadcast
    assert "192.168.1.1" in r.stdout        # HostMin
    assert "192.168.1.254" in r.stdout      # HostMax


def test_host_count_class_c(ipcalc):
    r = run(ipcalc, "192.168.1.0/24")
    assert "254" in r.stdout                # 2^8 - 2


def test_class_b_subnet(ipcalc):
    r = run(ipcalc, "10.0.0.0/16")
    assert r.returncode == 0
    assert "255.255.0.0" in r.stdout
    assert "10.0.255.255" in r.stdout       # broadcast


def test_slash_32_host_route(ipcalc):
    r = run(ipcalc, "172.16.93.1/32")
    assert r.returncode == 0
    # /32 has 1 address, 0 usable hosts
    assert "172.16.93.1" in r.stdout


def test_slash_8(ipcalc):
    r = run(ipcalc, "10.0.0.0/8")
    assert r.returncode == 0
    assert "255.0.0.0" in r.stdout


def test_apipa_flag(ipcalc):
    r = run(ipcalc, "169.254.69.0/24")
    assert r.returncode == 0
    out = r.stdout.upper()
    assert "APIPA" in out or "LINK-LOCAL" in out or "RFC 3927" in out


def test_rfc1918_private_flag(ipcalc):
    r = run(ipcalc, "10.0.0.0/8")
    out = r.stdout.upper()
    assert "PRIVATE" in out or "RFC 1918" in out


def test_dotted_mask_input(ipcalc):
    r = run(ipcalc, "192.168.1.0", "255.255.255.0")
    assert r.returncode == 0
    assert "192.168.1.0" in r.stdout
    assert "255.255.255.0" in r.stdout


def test_output_file(ipcalc, tmp_path):
    outfile = str(tmp_path / "result.txt")
    r = run(ipcalc, "-o", outfile, "10.20.0.0/16")
    assert r.returncode == 0
    with open(outfile) as f:
        content = f.read()
    assert "10.20.0.0" in content
    assert "255.255.0.0" in content


def test_multicast_flag(ipcalc):
    r = run(ipcalc, "224.0.0.0/4")
    out = r.stdout.upper()
    assert "MULTICAST" in out


def test_loopback_flag(ipcalc):
    r = run(ipcalc, "127.0.0.0/8")
    out = r.stdout.upper()
    assert "LOOPBACK" in out or "127." in out
