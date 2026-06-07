#!/usr/bin/env bash
# fetch-win32s.sh  --  AeldreC2
#
# Download the Win32s 1.30c redistributable from archive mirrors.
# Win32s is required to run Win32 programs (joshua.exe, grid.exe, etc.)
# on Windows 3.11 / WFW 3.11 without upgrading to Windows 95.
#
# The file (pw1232.exe) is freely redistributable and was distributed
# by Microsoft in the mid-1990s.  It is archived on:
#   - WinWorld PC  https://winworldpc.com/
#   - textfiles.com (Simtel archive mirrors)
#   - archive.org
#
# Usage:
#   ./fetch-win32s.sh           Download to dist/win32s/
#   ./fetch-win32s.sh -o <dir>  Download to <dir>
#   ./fetch-win32s.sh -v        Verbose
#
# After download the file is extracted to output/win32s/ so setup16.exe
# can bundle it.  The installer detects its absence and prompts the user.

set -e

OUTDIR="dist/win32s"
VERBOSE=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        -o) OUTDIR="$2"; shift 2 ;;
        -v) VERBOSE=1; shift ;;
        -h|--help)
            echo "Usage: $0 [-o outdir] [-v]"
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

mkdir -p "$OUTDIR"

log() { [[ $VERBOSE -eq 1 ]] && echo "$@" >&2; }
info() { echo "$@"; }

# The canonical Win32s 1.30c package.
# Primary: WinWorld PC (direct, no hot-linking protection for archival files)
# Fall-backs in order.
FILENAME="pw1232.exe"
MIRRORS=(
    "https://winworldpc.com/download/41c398c3-b818-c39a-11c3-9d6d14434241/from/c39ac2af-c381-c2bf-1b25-11c3a4e284a2"
    "https://archive.org/download/win32s130c/pw1232.exe"
    "https://ia803205.us.archive.org/8/items/win32s130c/pw1232.exe"
)

DEST="$OUTDIR/$FILENAME"

if [[ -f "$DEST" ]]; then
    info "Win32s already present at $DEST"
    exit 0
fi

info "Fetching Win32s 1.30c redistributable..."
info "  Target: $DEST"

DOWNLOADED=0
for URL in "${MIRRORS[@]}"; do
    info "  Trying: $URL"
    if command -v curl &>/dev/null; then
        if curl -fsSL --retry 3 -o "$DEST.tmp" "$URL" 2>/dev/null; then
            mv "$DEST.tmp" "$DEST"
            DOWNLOADED=1
            break
        fi
    elif command -v wget &>/dev/null; then
        if wget -q --tries=3 -O "$DEST.tmp" "$URL" 2>/dev/null; then
            mv "$DEST.tmp" "$DEST"
            DOWNLOADED=1
            break
        fi
    else
        echo "ERROR: neither curl nor wget found.  Cannot download Win32s automatically."
        echo ""
        echo "Please download pw1232.exe manually from:"
        echo "  https://winworldpc.com  (search for 'Win32s 1.30')"
        echo "  https://archive.org/details/win32s130c"
        echo ""
        echo "Place it at: $DEST"
        exit 1
    fi
    rm -f "$DEST.tmp"
done

if [[ $DOWNLOADED -eq 0 ]]; then
    echo "WARNING: Could not automatically download Win32s."
    echo ""
    echo "Please download pw1232.exe manually and place it at:"
    echo "  $DEST"
    echo ""
    echo "Sources:"
    echo "  https://winworldpc.com  (Win32s 1.30c)"
    echo "  https://archive.org/details/win32s130c"
    echo "  textfiles.com (Simtel mirrors, search for pw1232.exe)"
    exit 1
fi

FSIZ=$(stat -c%s "$DEST" 2>/dev/null || stat -f%z "$DEST" 2>/dev/null || echo "?")
info "  Downloaded: $DEST ($FSIZ bytes)"

# Extract if 7z / unzip available (pw1232.exe is a self-extracting ZIP)
EXTRACT_DIR="$OUTDIR/extracted"
if command -v 7z &>/dev/null; then
    info "  Extracting to $EXTRACT_DIR ..."
    mkdir -p "$EXTRACT_DIR"
    7z x -o"$EXTRACT_DIR" "$DEST" -y >/dev/null 2>&1 && info "  Extracted OK."
elif command -v unzip &>/dev/null; then
    info "  Extracting to $EXTRACT_DIR ..."
    mkdir -p "$EXTRACT_DIR"
    unzip -q -o "$DEST" -d "$EXTRACT_DIR" 2>/dev/null && info "  Extracted OK."
else
    info "  Note: 7z/unzip not found — skipping extraction."
    info "  Run the .exe on a Windows machine to extract Win32s files."
fi

info ""
info "Win32s 1.30c is ready at: $DEST"
info ""
info "To install on WFW 3.11:"
info "  1. Copy $FILENAME to the target machine"
info "  2. Run pw1232.exe — it self-extracts"
info "  3. Run SETUP.EXE from the extracted W32S folder"
info "  4. Restart Windows"
info ""
info "After installing Win32s, AeldreC2 Win32 tools will run on WFW 3.11."
