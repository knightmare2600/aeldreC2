#!/bin/sh
# build-c2.sh — build AeldreC2 C2 components using the putty-win32s-builder Docker image
#
# Usage:
#   ./build-c2.sh                        # build all C2 tools
#   ./build-c2.sh joshua                 # single target
#   ./build-c2.sh tank                   # tank with default config
#   ./build-c2.sh tank16
#   ./build-c2.sh clu
#   ./build-c2.sh ncwfw
#
# Override Tank callback address:
#   C2HOST=10.0.0.1 C2PORT=443 ./build-c2.sh tank
#
# Enable Recognizer (anti-analysis checks):
#   RECOGNIZER=1 ./build-c2.sh tank
#
# Both:
#   C2HOST=10.0.0.1 RECOGNIZER=1 ./build-c2.sh tank

set -e

REPO="$(cd "$(dirname "$0")" && pwd)"
IMG="putty-win32s-builder"

# Build XFLAGS from env vars
XFLAGS=""
if [ -n "$C2HOST" ]; then
    XFLAGS="$XFLAGS -DTANK_C2_HOST=${C2HOST}"
fi
if [ -n "$C2PORT" ]; then
    XFLAGS="$XFLAGS -DTANK_C2_PORT=${C2PORT}"
fi
if [ -n "$RECOGNIZER" ]; then
    XFLAGS="$XFLAGS -DRECOGNIZER_ENABLE"
fi
XFLAGS="${XFLAGS# }"  # strip leading space

run() {
    echo ">>> $*"
    if [ -n "$XFLAGS" ]; then
        docker run --rm \
            -v "$REPO:/src" \
            -w /src/windows \
            "$IMG" \
            wmake -f Makefile.wc "$@" "XFLAGS=$XFLAGS"
    else
        docker run --rm \
            -v "$REPO:/src" \
            -w /src/windows \
            "$IMG" \
            wmake -f Makefile.wc "$@"
    fi
}

TARGET="${1:-c2}"

case "$TARGET" in
    c2)
        run joshua.exe
        run tank.exe
        run tank16.exe
        run clu.exe
        run ncwfw.exe
        run grid.exe
        run ipcalc32.exe
        run ipcalc16.exe
        run markuped.exe
        run wget.exe
        run wget16.exe
        echo ""
        echo "Built: joshua.exe tank.exe tank16.exe clu.exe ncwfw.exe grid.exe ipcalc32.exe ipcalc16.exe markuped.exe wget.exe wget16.exe"
        echo "Output: $REPO/windows/"
        ;;
    all)
        # full PuTTY + C2 suite — slow
        run all
        ;;
    joshua|tank|tank16|clu|ncwfw|grid|ipcalc32|ipcalc16|markuped|wget|wget16)
        run "${TARGET}.exe"
        ;;
    *)
        run "$@"
        ;;
esac
