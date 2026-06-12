#!/bin/sh
# Run InnoSetup 16-bit COMPIL16.EXE under xvfb and wait for the output file.
#
# COMPIL16.EXE is a GUI app: it compiles the script then shows a modal
# "Compilation successful" dialog and waits for OK.  We start it under a
# virtual framebuffer, poll until the output .exe appears, then kill the
# process.  The dialog is never dismissed; we don't need it to be.
#
# Usage: run_inno16.sh <COMPIL16.EXE path> <script.iss> <expected output.exe>
#
# Exit 0 if output file exists after compilation, 1 otherwise.

COMPIL="$1"
ISS="$2"
OUT="$3"

if [ -z "$COMPIL" ] || [ -z "$ISS" ] || [ -z "$OUT" ]; then
    echo "Usage: run_inno16.sh <COMPIL16.EXE> <script.iss> <output.exe>" >&2
    exit 1
fi

xvfb-run -a wine "$COMPIL" "$ISS" &
WINE_PID=$!

# Poll up to 120 seconds for the output file
i=0
while [ $i -lt 60 ]; do
    [ -f "$OUT" ] && break
    sleep 2
    i=$((i + 1))
done

kill "$WINE_PID" 2>/dev/null
wait "$WINE_PID" 2>/dev/null

if [ -f "$OUT" ]; then
    echo "InnoSetup: $OUT created successfully"
    exit 0
else
    echo "InnoSetup: $OUT not found after 120 seconds" >&2
    exit 1
fi
