FROM ubuntu:22.04

LABEL description="ÆldreC2 build environment — OpenWatcom 2.0 + mingw-w64 Win16/Win32s cross-compiler"

ENV DEBIAN_FRONTEND=noninteractive

# Build tools: mingw windres, Python + Pillow for win16ico.py
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates wget \
        gcc-mingw-w64-i686 \
        binutils-mingw-w64-i686 \
        python3 python3-pip xz-utils zip \
    && pip3 install --no-cache-dir Pillow \
    && rm -rf /var/lib/apt/lists/*

# Wine (32-bit) for running Win32 test binaries; pytest + requests for the test suite
RUN dpkg --add-architecture i386 \
    && apt-get update \
    && apt-get install -y --no-install-recommends wine wine32 \
    && pip3 install --no-cache-dir pytest requests \
    && rm -rf /var/lib/apt/lists/*

# Pre-initialise the Wine prefix so tests don't stall on first run
RUN WINEDEBUG=-all DISPLAY= wine wineboot --init 2>/dev/null || true

# OpenWatcom 2.0 — Linux x86_64 snapshot
# The tarball has a top-level "watcom/" directory; extracting to /opt/ gives /opt/watcom/
# If the upstream release renames the root dir, adjust accordingly.
ARG OW_URL=https://github.com/open-watcom/open-watcom-v2/releases/download/Current-build/ow-snapshot.tar.xz
RUN wget -nv -O /tmp/ow.tar.xz "$OW_URL" \
    && mkdir -p /opt/watcom \
    && tar --no-overwrite-dir --strip-components=1 -xJf /tmp/ow.tar.xz -C /opt/watcom \
    && rm /tmp/ow.tar.xz \
    && find /opt/watcom -name wmake | grep -q .

ENV WATCOM=/opt/watcom
ENV PATH="${PATH}:/opt/watcom/binl64:/opt/watcom/binl"
ENV INCLUDE="/opt/watcom/h:/opt/watcom/h/nt"

WORKDIR /src/windows
CMD ["wmake", "-a", "-f", "Makefile.wc", "dist"]
