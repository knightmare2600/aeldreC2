#!/bin/sh
# fetch-nmap-data.sh  --  download nmap GPL data files and rename to 8.3 filenames
#
# Files are fetched from the nmap GitHub mirror and placed in data/
# The nmap data files are GPL-licensed; see https://nmap.org/book/man-legal.html

set -e

REPO="$(cd "$(dirname "$0")" && pwd)"
OUTDIR="$REPO/data"
BASE="https://raw.githubusercontent.com/nmap/nmap/master"

mkdir -p "$OUTDIR"

fetch() {
    src="$1"
    dst="$2"
    echo "  $src -> data/$dst"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$BASE/$src" -o "$OUTDIR/$dst"
    elif command -v wget >/dev/null 2>&1; then
        wget -q "$BASE/$src" -O "$OUTDIR/$dst"
    else
        echo "ERROR: need curl or wget" >&2
        exit 1
    fi
}

echo "Fetching nmap data files..."

fetch "nmap-services"       "SERVICES.DAT"
fetch "nmap-protocols"      "PROTOS.DAT"
fetch "nmap-rpc"            "NMAPRPC.DAT"
fetch "nmap-mac-prefixes"   "MACPFX.DAT"

# These are large; fetch only if -a flag given
if [ "${1:-}" = "-a" ]; then
    fetch "nmap-os-db"          "OSDB.DAT"
    fetch "nmap-service-probes" "SVCPRO.DAT"
    echo "All files fetched (including large files)."
else
    echo "Skipped OSDB.DAT and SVCPRO.DAT (large). Run with -a to include them."
fi

echo "Done. Files in: $OUTDIR/"
echo ""
echo "8.3 filename map:"
echo "  nmap-services       -> SERVICES.DAT"
echo "  nmap-protocols      -> PROTOS.DAT"
echo "  nmap-rpc            -> NMAPRPC.DAT"
echo "  nmap-mac-prefixes   -> MACPFX.DAT"
echo "  nmap-os-db          -> OSDB.DAT       (requires -a)"
echo "  nmap-service-probes -> SVCPRO.DAT     (requires -a)"
echo ""
echo "Copy SERVICES.DAT next to grid.exe, or set GRIDDATA=<dir>"
