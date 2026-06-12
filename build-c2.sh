#!/bin/bash
# build-c2.sh — build AeldreC2 C2 components using the aeldrec2-builder Docker image
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
#
# Full compiler output is always written to build.log in the repo root.
# Only errors, warnings and notes are printed to the terminal.

set -e

REPO="$(cd "$(dirname "$0")" && pwd)"
IMG="aeldrec2-builder"
BUILD_LOG="$REPO/build.log"

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
    local rc=0
    local tmplog
    tmplog=$(mktemp)

    printf ">>> %s  " "$*"
    printf "\n=== %s ===\n" "$*" >> "$BUILD_LOG"

    if [ -n "$XFLAGS" ]; then
        docker run --rm \
            -v "$REPO:/src" \
            -w /src/windows \
            "$IMG" \
            wmake -f Makefile.wc "$@" "XFLAGS=$XFLAGS" >> "$tmplog" 2>&1 \
            && rc=0 || rc=$?
    else
        docker run --rm \
            -v "$REPO:/src" \
            -w /src/windows \
            "$IMG" \
            wmake -f Makefile.wc "$@" >> "$tmplog" 2>&1 \
            && rc=0 || rc=$?
    fi

    cat "$tmplog" >> "$BUILD_LOG"

    if [ $rc -eq 0 ]; then
        echo "ok"
    else
        echo "FAILED (full log: $BUILD_LOG)"
        grep -E 'Error|Warning!|Note!' "$tmplog" || true
    fi

    rm -f "$tmplog"
    return $rc
}

TARGET="${1:-c2}"

# Reset log for this build session
> "$BUILD_LOG"

# ----------------------------------------------------------------
# Helper: run pytest inside the builder container
# ----------------------------------------------------------------
run_tests_in_docker() {
    echo ""
    printf ">>> Running test suite inside container...\n"
    docker run --rm \
        -v "$REPO:/src" \
        -e "C2_INTEGRATION=${C2_INTEGRATION:-1}" \
        "$IMG" \
        sh -c 'cd /src && python3 -m pytest tests/ -v --tb=short'
}

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
        run lightman.exe
        run flynn.exe
        run setup16.exe
        echo ""
        echo "Built: joshua.exe tank.exe tank16.exe clu.exe ncwfw.exe grid.exe ipcalc32.exe ipcalc16.exe markuped.exe wget.exe wget16.exe lightman.exe flynn.exe setup16.exe"
        echo "Output: $REPO/windows/"
        echo ""
        echo "To bundle into a self-extracting setup.exe:"
        echo "  python3 tools/mksetup.py"
        ;;
    setup)
        run setup16.exe
        echo "Bundling..."
        docker run --rm -v "$REPO":/src -w /src openwatcom/owtools:latest \
            python3 tools/mksetup.py
        ;;
    test)
        # Build image (layer-cached if Dockerfile unchanged), build any stale
        # binaries (incremental — no -a), then run the test suite.
        # Use FORCE=1 ./build-c2.sh test to force a full rebuild.
        docker build -t "$IMG" "$REPO"
        docker run --rm \
            -v "$REPO:/src" \
            -e "C2_INTEGRATION=${C2_INTEGRATION:-1}" \
            "$IMG" \
            sh -c "wmake ${FORCE:+-a} -f Makefile.wc dist && cd /src && python3 -m pytest tests/ -v --tb=short"
        ;;
    test-only)
        # Run tests against already-built binaries — no build, no image rebuild
        run_tests_in_docker
        ;;
    dist)
        # Full release build: all binaries + InnoSetup installer + WinHelp + ZIP
        run dist
        ;;
    all)
        # Full PuTTY + C2 suite — slow
        run all
        ;;
    joshua|tank|tank16|clu|ncwfw|grid|ipcalc32|ipcalc16|markuped|wget|wget16|lightman|flynn|setup16|setup32)
        run "${TARGET}.exe"
        ;;
    *)
        run "$@"
        ;;
esac
