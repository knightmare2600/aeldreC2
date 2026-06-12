"""
Binary format validation tests — no Wine required.

Checks that every compiled .exe has the correct format, subsystem,
import table, and embedded constants.  These run on every build and
catch linker/toolchain regressions before anything is deployed.
"""

import os
import struct

import pytest

WINDOWS_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "windows")
)


def exe(name):
    return os.path.join(WINDOWS_DIR, name)


def read_bytes(path):
    with open(path, "rb") as f:
        return f.read()


def skip_if_missing(path):
    if not os.path.exists(path):
        pytest.skip(f"{os.path.basename(path)} not built")


# ------------------------------------------------------------------
# PE helpers
# ------------------------------------------------------------------

def pe_header(data):
    """Return (pe_offset, machine, num_sections, subsystem, imports_rva, imports_size)."""
    if data[:2] != b"MZ":
        return None
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe_off:pe_off+4] != b"PE\x00\x00":
        return None
    machine      = struct.unpack_from("<H", data, pe_off + 4)[0]
    num_sections = struct.unpack_from("<H", data, pe_off + 6)[0]
    opt_magic    = struct.unpack_from("<H", data, pe_off + 24)[0]
    if opt_magic == 0x10B:   # PE32
        subsystem = struct.unpack_from("<H", data, pe_off + 92)[0]
        # Data directories start at optional header offset 96 (0x60);
        # optional header is at pe_off+24; entry 1 (imports) is 8 bytes in.
        dd_offset = pe_off + 24 + 96 + 1 * 8
    elif opt_magic == 0x20B: # PE32+
        subsystem = struct.unpack_from("<H", data, pe_off + 92)[0]
        dd_offset = pe_off + 24 + 112 + 1 * 8
    else:
        return None
    imp_rva  = struct.unpack_from("<I", data, dd_offset)[0]
    imp_size = struct.unpack_from("<I", data, dd_offset + 4)[0]
    return pe_off, machine, num_sections, subsystem, imp_rva, imp_size


def pe_subsystem(data):
    h = pe_header(data)
    return h[3] if h else None


PE_GUI     = 2   # IMAGE_SUBSYSTEM_WINDOWS_GUI
PE_CONSOLE = 3   # IMAGE_SUBSYSTEM_WINDOWS_CUI


def is_ne(data):
    """Return True if the file is a 16-bit NE (Win16) executable."""
    if data[:2] != b"MZ":
        return False
    ne_off = struct.unpack_from("<H", data, 0x3C)[0]
    return data[ne_off:ne_off+2] == b"NE"


def pe_imports(data):
    """Return set of DLL names found in the PE import table (lower-case)."""
    h = pe_header(data)
    if not h:
        return set()
    pe_off, _, num_sections, _, imp_rva, imp_size = h
    if imp_rva == 0:
        return set()

    # Locate section containing the import RVA
    section_table_off = pe_off + 24 + struct.unpack_from("<H", data, pe_off + 20)[0]
    sections = []
    for i in range(num_sections):
        off = section_table_off + i * 40
        vaddr = struct.unpack_from("<I", data, off + 12)[0]
        vsize = struct.unpack_from("<I", data, off + 16)[0]
        raw   = struct.unpack_from("<I", data, off + 20)[0]
        sections.append((vaddr, vsize, raw))

    def rva_to_offset(rva):
        for vaddr, vsize, raw in sections:
            if vaddr <= rva < vaddr + vsize:
                return raw + (rva - vaddr)
        return None

    imports = set()
    off = rva_to_offset(imp_rva)
    if off is None:
        return imports

    while off + 20 <= len(data):
        name_rva = struct.unpack_from("<I", data, off + 12)[0]
        if name_rva == 0:
            break
        name_off = rva_to_offset(name_rva)
        if name_off is None:
            break
        end = data.index(b"\x00", name_off)
        imports.add(data[name_off:end].decode("ascii", errors="replace").lower())
        off += 20

    return imports


def dos_stub_message(data):
    """Return the DOS stub message string if it contains NT or DOS-mode text."""
    if data[:2] != b"MZ":
        return ""
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    stub = data[0:pe_off]   # entire region before the PE header
    # AeldreC2 stub uses lowercase 'r' in 'requires'
    for s in (b"requires Windows NT", b"Requires Windows NT",
              b"This program cannot", b"cannot run in DOS"):
        if s in stub:
            return stub.decode("ascii", errors="replace").strip()
    return ""


# ------------------------------------------------------------------
# Existence checks
# ------------------------------------------------------------------

EXPECTED_WIN32_GUI = [
    "joshua.exe", "tank.exe", "clu.exe", "grid.exe", "flynn.exe",
    "ncwfw.exe", "ipcalc32.exe", "markuped.exe", "wget.exe",
    "jloshtog.exe", "dumont.exe", "yori32.exe", "net-stat.exe",
    "setup32.exe",
]

EXPECTED_WIN32_GUI_EXTRA = [
    "yoriview.exe",   # GUI subsystem (-l=nt_win) even though it's an "NT" tool
]

EXPECTED_NT_CONSOLE = [
    "lightman.exe", "gridcli.exe", "netstatN.exe", "route.exe",
    "ncnt.exe", "svcany.exe", "regcli.exe", "whoami.exe",
    "arp.exe", "stager.exe", "timestmp.exe",
    "grid32.exe", "gridnt.exe",
]

EXPECTED_WIN16 = [
    "tank16.exe", "net_stat.exe", "route16.exe", "ipcalc16.exe",
    "wget16.exe", "yori16.exe", "clip16.exe", "lman16.exe",
    "nc16.exe", "grid16.exe",
]


@pytest.mark.parametrize("name", EXPECTED_WIN32_GUI)
def test_win32_gui_binary_exists(name):
    assert os.path.exists(exe(name)), f"{name} not built"


@pytest.mark.parametrize("name", EXPECTED_NT_CONSOLE)
def test_nt_console_binary_exists(name):
    assert os.path.exists(exe(name)), f"{name} not built"


@pytest.mark.parametrize("name", EXPECTED_WIN16)
def test_win16_binary_exists(name):
    assert os.path.exists(exe(name)), f"{name} not built"


# ------------------------------------------------------------------
# Format checks
# ------------------------------------------------------------------

@pytest.mark.parametrize("name", EXPECTED_WIN32_GUI + EXPECTED_WIN32_GUI_EXTRA)
def test_win32_gui_has_pe_gui_subsystem(name):
    path = exe(name)
    skip_if_missing(path)
    data = read_bytes(path)
    sub = pe_subsystem(data)
    assert sub == PE_GUI, f"{name}: expected GUI subsystem (2), got {sub}"


@pytest.mark.parametrize("name", EXPECTED_NT_CONSOLE)
def test_nt_console_has_pe_console_subsystem(name):
    path = exe(name)
    skip_if_missing(path)
    data = read_bytes(path)
    sub = pe_subsystem(data)
    assert sub == PE_CONSOLE, f"{name}: expected console subsystem (3), got {sub}"


@pytest.mark.parametrize("name", EXPECTED_WIN16)
def test_win16_is_ne_format(name):
    path = exe(name)
    skip_if_missing(path)
    data = read_bytes(path)
    assert is_ne(data), f"{name}: expected NE (Win16) format"


# ------------------------------------------------------------------
# Import table: SECUR32.DLL must NOT be statically imported
# ------------------------------------------------------------------

ALL_WIN32 = EXPECTED_WIN32_GUI + EXPECTED_WIN32_GUI_EXTRA + EXPECTED_NT_CONSOLE


@pytest.mark.parametrize("name", ALL_WIN32)
def test_no_static_secur32_import(name):
    """
    SECUR32.DLL is loaded at runtime via LoadLibrary in tls_load().
    It must NOT appear in the PE import table, or the binary will
    fail to start on systems where secur32.dll is absent (Win32s,
    NT 3.1, bare WFW + Win32s).
    """
    path = exe(name)
    skip_if_missing(path)
    data = read_bytes(path)
    imports = pe_imports(data)
    assert "secur32.dll" not in imports, (
        f"{name} statically imports SECUR32.DLL — "
        "use LoadLibrary instead (see tls_load() pattern)"
    )
    assert "security.dll" not in imports, (
        f"{name} statically imports SECURITY.DLL"
    )


# ------------------------------------------------------------------
# NT stub: NT-only tools must print the custom "Requires NT" message
# ------------------------------------------------------------------

NT_STUB_TOOLS = [
    "lightman.exe", "gridcli.exe", "netstatN.exe", "route.exe",
    "ncnt.exe", "svcany.exe", "regcli.exe", "whoami.exe",
    "arp.exe", "stager.exe", "timestmp.exe",
    "grid32.exe", "gridnt.exe",
]

@pytest.mark.parametrize("name", NT_STUB_TOOLS)
def test_nt_tools_have_custom_dos_stub(name):
    """NT-only tools must carry the AeldreC2 custom DOS stub."""
    path = exe(name)
    skip_if_missing(path)
    data = read_bytes(path)
    msg = dos_stub_message(data)
    # Custom stub uses "requires Windows NT" (lowercase r)
    assert "Windows NT" in msg, (
        f"{name}: expected 'Windows NT' in DOS stub, got: {msg!r}"
    )


# ------------------------------------------------------------------
# CLU config block: tank binaries must carry the magic + correct layout
# ------------------------------------------------------------------

CLU_MAGIC = b"AELDRECLU0001"
CLU_BLOCK_SIZE = 90   # 14 magic + 64 host + 2 port + 1 tls + 9 key


@pytest.mark.parametrize("name", ["tank.exe", "tank16.exe"])
def test_clu_magic_present(name):
    path = exe(name)
    skip_if_missing(path)
    data = read_bytes(path)
    assert CLU_MAGIC in data, f"{name}: CLU magic block not found"


@pytest.mark.parametrize("name", ["tank.exe", "tank16.exe"])
def test_clu_block_fits_in_binary(name):
    path = exe(name)
    skip_if_missing(path)
    data = read_bytes(path)
    pos = data.find(CLU_MAGIC)
    assert pos >= 0, f"{name}: CLU magic not found"
    assert pos + CLU_BLOCK_SIZE <= len(data), (
        f"{name}: CLU block at offset {pos} extends beyond end of file"
    )


@pytest.mark.parametrize("name", ["tank.exe", "tank16.exe"])
def test_clu_default_key_is_zeros(name):
    """Unpatched binaries must have the default key 00000000."""
    path = exe(name)
    skip_if_missing(path)
    data = read_bytes(path)
    pos = data.find(CLU_MAGIC)
    assert pos >= 0
    key = data[pos + 81 : pos + 89]
    assert key == b"00000000", (
        f"{name}: default key should be b'00000000', got {key!r}"
    )


def test_clu_default_host_is_loopback():
    """Default tank.exe must be configured to call back to 127.0.0.1."""
    path = exe("tank.exe")
    skip_if_missing(path)
    data = read_bytes(path)
    pos = data.find(CLU_MAGIC)
    assert pos >= 0
    host = data[pos + 14 : pos + 78].rstrip(b"\x00").decode("ascii", errors="replace")
    assert host == "127.0.0.1", f"Default host should be 127.0.0.1, got {host!r}"


# ------------------------------------------------------------------
# Joshua binary checks
# ------------------------------------------------------------------

def test_joshua_is_pe_gui():
    path = exe("joshua.exe")
    skip_if_missing(path)
    assert pe_subsystem(read_bytes(path)) == PE_GUI


def test_joshua_imports_wsock32():
    path = exe("joshua.exe")
    skip_if_missing(path)
    imports = pe_imports(read_bytes(path))
    assert "wsock32.dll" in imports, "joshua.exe must import wsock32.dll"


def test_joshua_does_not_import_secur32():
    path = exe("joshua.exe")
    skip_if_missing(path)
    imports = pe_imports(read_bytes(path))
    assert "secur32.dll" not in imports
    assert "security.dll" not in imports
