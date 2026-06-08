#!/usr/bin/env python3
"""
mksetup.py -- Bundle AeldreC2 & Putty-Win32s into a self-extracting setup.exe

Run from the repo root after building:
    python3 tools/mksetup.py [--c2-dir windows] [--putty-dir windows] [--out setup.exe]

Bundle format (appended after setup16.exe):
    [setup16.exe bytes]
    [file data: file0, file1, ...]
    [index: array of BundleEntry structs, 73 bytes each]
    [footer: 12 bytes: index_off(u32), n_files(u32), magic(u32='ALD1')]

setup16.exe reads its own path, seeks to the last 12 bytes, validates the magic,
reads the index, then extracts files to the chosen destination directories.
"""

import argparse
import os
import struct
import sys

BUNDLE_MAGIC = 0x31444C41   # 'ALD1' little-endian

DEST_C2    = 0
DEST_PUTTY = 1
DEST_DLL   = 2
DEST_ROOT  = 3   # same dir as C2 (GRP, TXT files)


def pack_entry(name: str, dest: int, offset: int, size: int) -> bytes:
    name_b = name.encode('ascii', errors='replace')[:63]
    name_b = name_b + b'\x00' * (64 - len(name_b))
    return struct.pack('<64sBLL', name_b, dest, offset, size)


def collect_files(c2_dir: str, putty_dir: str, repo_root: str, dist_dir: str):
    """Return list of (filename, dest_code, abs_path)."""
    files = []

    # --- AeldreC2 binaries ---
    c2_bins = [
        'joshua.exe', 'tank.exe', 'tank16.exe',
        'clu.exe', 'grid.exe',
        'ipcalc32.exe', 'ipcalc16.exe',
        'markuped.exe',
        'wget.exe', 'wget16.exe',
        'lightman.exe', 'flynn.exe',
        'ncwfw.exe',
        'aelctl.dll',   # Win32s controls shim — shared by all Win32 C2 tools
    ]
    for fn in c2_bins:
        path = os.path.join(c2_dir, fn)
        if os.path.isfile(path):
            files.append((fn.upper(), DEST_C2, path))
        else:
            print(f'  [skip] {fn} not found in {c2_dir}', file=sys.stderr)

    # --- Root-level files (GRP, licence text) ---
    root_extras = [
        ('AELDREC2.GRP', 'AELDREC2.GRP'),
        ('GPL30.TXT',    'gpl30.txt'),
        ('README.MD',    'README.md'),   # readable in markuped.exe
    ]
    for dest_name, src_name in root_extras:
        path = os.path.join(repo_root, src_name)
        if os.path.isfile(path):
            files.append((dest_name, DEST_ROOT, path))
        else:
            print(f'  [skip] {src_name} not found at repo root', file=sys.stderr)

    # --- Putty-Win32s binaries ---
    if putty_dir and os.path.isdir(putty_dir):
        putty_bins = [
            'putty.exe', 'puttytel.exe', 'puttygen.exe',
            'winsftp.exe', 'pageant.exe',
            'aelctl.dll',   # Win32s controls shim — winsftp depends on it
        ]
        for fn in putty_bins:
            path = os.path.join(putty_dir, fn)
            if os.path.isfile(path):
                files.append((fn.upper(), DEST_PUTTY, path))
            else:
                print(f'  [skip] {fn} not found in {putty_dir}', file=sys.stderr)
    else:
        print('  [info] No putty-dir specified or not found; Putty-Win32s not bundled',
              file=sys.stderr)

    # --- Runtime DLLs (WSOCK32, COMDLG32) from dist/ ---
    # These are the only Win32s-compatible DLLs that may be missing on the target.
    # COMCTL32 is NOT included: it is not part of Win32s and ships with Win95/NT4.
    for dll in ('WSOCK32.DLL', 'COMDLG32.DLL'):
        path = os.path.join(dist_dir, dll)
        if os.path.isfile(path):
            files.append((dll, DEST_DLL, path))
        else:
            print(f'  [info] {dll} not found in {dist_dir} — skipping', file=sys.stderr)

    return files


def build_bundle(setup_exe: str, files: list, out_exe: str):
    with open(setup_exe, 'rb') as f:
        data = bytearray(f.read())

    print(f'  setup16.exe: {len(data):,} bytes')

    entries = []
    for name, dest, path in files:
        with open(path, 'rb') as f:
            file_data = f.read()
        offset = len(data)
        data += file_data
        entries.append((name, dest, offset, len(file_data)))
        print(f'  + {name:<20} dest={dest}  {len(file_data):>8,} bytes  @ {offset:,}')

    # Write index
    index_off = len(data)
    for name, dest, offset, size in entries:
        data += pack_entry(name, dest, offset, size)

    # Write footer (last 12 bytes)
    footer = struct.pack('<LLL', index_off, len(entries), BUNDLE_MAGIC)
    data += footer

    with open(out_exe, 'wb') as f:
        f.write(data)

    print(f'\nCreated: {out_exe}')
    print(f'  {len(entries)} files bundled, total {len(data):,} bytes'
          f' ({len(data) // 1024} KB)')


def main():
    parser = argparse.ArgumentParser(
        description='Bundle AeldreC2 files into self-extracting Win16 and Win32 setup.exe')
    parser.add_argument('--setup16',  default='windows/setup16.exe',
                        help='Path to compiled setup16.exe (default: windows/setup16.exe)')
    parser.add_argument('--setup32',  default='windows/setup32.exe',
                        help='Path to compiled setup32.exe (default: windows/setup32.exe)')
    parser.add_argument('--c2-dir',   default='windows',
                        help='Directory containing AeldreC2 .exe files (default: windows)')
    parser.add_argument('--putty-dir', default='windows',
                        help='Directory containing Putty-Win32s .exe files (default: windows)')
    parser.add_argument('--dist-dir', default='dist',
                        help='Directory containing runtime DLLs (default: dist)')
    parser.add_argument('--out16',    default='setup16.exe',
                        help='Output Win16 installer (default: setup16.exe)')
    parser.add_argument('--out32',    default='setup32.exe',
                        help='Output Win32 installer (default: setup32.exe)')
    args = parser.parse_args()

    # All paths relative to repo root (where this script should be run from)
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    c2_dir    = os.path.join(repo_root, args.c2_dir)
    putty_dir = os.path.join(repo_root, args.putty_dir)
    dist_dir  = os.path.join(repo_root, args.dist_dir)

    print('Collecting files...')
    files = collect_files(c2_dir, putty_dir, repo_root, dist_dir)

    if not files:
        print('WARNING: no files to bundle — installers will warn at runtime',
              file=sys.stderr)

    built = 0
    for setup_rel, out_rel, label in (
            (args.setup16, args.out16, 'Win16'),
            (args.setup32, args.out32, 'Win32'),
    ):
        setup_exe = os.path.join(repo_root, setup_rel)
        out_exe   = os.path.join(repo_root, out_rel)
        if not os.path.isfile(setup_exe):
            print(f'  [skip] {label} loader {setup_exe} not found', file=sys.stderr)
            continue
        print(f'\nBuilding {label} bundle...')
        build_bundle(setup_exe, files, out_exe)
        built += 1

    if built == 0:
        print('ERROR: no loader executables found. Build setup16.exe and/or setup32.exe first.',
              file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
