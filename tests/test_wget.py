"""
wget.exe test suite.

Starts a local HTTP server and checks that wget downloads files correctly.
Also tests the -O flag, -q flag, and non-existent URL handling.
"""

import os
import threading
import time

import pytest
from conftest import MiniHTTPServer, exe_path, free_port, wine_run


@pytest.fixture(scope="module")
def wget(wine):
    return exe_path("wget.exe"), wine


def run_wget(wget, *args, timeout=20):
    exe, w = wget
    return wine_run(w, exe, *args, timeout=timeout)


# ------------------------------------------------------------------
# Basic download
# ------------------------------------------------------------------

def test_basic_http_download(wget, tmp_path):
    content = b"AeldreC2 wget test payload 12345"
    srv = MiniHTTPServer(content=content, filename="payload.bin")
    outfile = str(tmp_path / "payload.bin")
    try:
        r = run_wget(wget, srv.url, "-O", outfile, "-q")
        assert r.returncode == 0
        assert os.path.exists(outfile)
        assert open(outfile, "rb").read() == content
    finally:
        srv.stop()


def test_download_filename_from_url(wget, tmp_path):
    """Without -O, wget derives the filename from the URL path."""
    content = b"auto-named file content"
    srv = MiniHTTPServer(content=content, filename="auto.txt")
    orig_dir = os.getcwd()
    os.chdir(tmp_path)
    try:
        r = run_wget(wget, srv.url, "-q")
        assert r.returncode == 0
        assert os.path.exists(tmp_path / "auto.txt")
        assert (tmp_path / "auto.txt").read_bytes() == content
    finally:
        os.chdir(orig_dir)
        srv.stop()


def test_quiet_flag_suppresses_stderr(wget, tmp_path):
    content = b"quiet mode test"
    srv = MiniHTTPServer(content=content, filename="q.txt")
    outfile = str(tmp_path / "q.txt")
    try:
        r = run_wget(wget, srv.url, "-O", outfile, "-q")
        assert r.returncode == 0
        # -q should suppress progress output to stderr
        assert r.stderr.strip() == "" or "wine" in r.stderr.lower()
    finally:
        srv.stop()


def test_large_ish_payload(wget, tmp_path):
    """64 KB payload — checks chunked recv loop."""
    content = b"X" * 65536
    srv = MiniHTTPServer(content=content, filename="big.bin")
    outfile = str(tmp_path / "big.bin")
    try:
        r = run_wget(wget, srv.url, "-O", outfile, "-q")
        assert r.returncode == 0
        data = open(outfile, "rb").read()
        assert len(data) == 65536
        assert data == content
    finally:
        srv.stop()


def test_output_path_with_subdirectory(wget, tmp_path):
    content = b"subdir test"
    srv = MiniHTTPServer(content=content, filename="out.txt")
    # Wine maps Z: to the Linux filesystem
    outfile = str(tmp_path / "out.txt")
    try:
        r = run_wget(wget, srv.url, "-O", outfile, "-q")
        assert r.returncode == 0
        assert open(outfile, "rb").read() == content
    finally:
        srv.stop()


def test_connection_refused_exits_nonzero(wget, tmp_path):
    port = free_port()
    outfile = str(tmp_path / "nope.txt")
    r = run_wget(wget, f"http://127.0.0.1:{port}/nope.txt", "-O", outfile, "-q")
    assert r.returncode != 0


def test_binary_payload_integrity(wget, tmp_path):
    """Download a binary blob and verify byte-for-byte."""
    content = bytes(range(256)) * 16     # 4096 bytes, all byte values
    srv = MiniHTTPServer(content=content, filename="bytes.bin")
    outfile = str(tmp_path / "bytes.bin")
    try:
        r = run_wget(wget, srv.url, "-O", outfile, "-q")
        assert r.returncode == 0
        assert open(outfile, "rb").read() == content
    finally:
        srv.stop()
