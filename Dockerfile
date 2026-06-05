FROM ubuntu:22.04

LABEL description="AeldreC2 build environment — OpenWatcom 2.0 + mingw-w64 Win16/Win32s cross-compiler"

ENV DEBIAN_FRONTEND=noninteractive

# mingw windres for .rc compilation; Python + Pillow for win16ico.py
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates wget \
        gcc-mingw-w64-i686 \
        binutils-mingw-w64-i686 \
        python3 python3-pip \
    && pip3 install --no-cache-dir Pillow \
    && rm -rf /var/lib/apt/lists/*

# OpenWatcom 2.0 — Linux x86_64 snapshot
# The tarball has a top-level "watcom/" directory; extracting to /opt/ gives /opt/watcom/
# If the upstream release renames the root dir, adjust accordingly.
ARG OW_URL=https://github.com/open-watcom/open-watcom-v2/releases/download/Current-build/ow-snapshot.tar.xz
RUN wget -nv -O /tmp/ow.tar.xz "$OW_URL" \
    && tar -xJf /tmp/ow.tar.xz -C /opt \
    && rm /tmp/ow.tar.xz \
    && ls /opt/watcom/binl64/ /opt/watcom/binl/ 2>/dev/null | grep wmake \
    && ( test -x /opt/watcom/binl64/wmake || test -x /opt/watcom/binl/wmake )

ENV WATCOM=/opt/watcom
ENV PATH="${PATH}:/opt/watcom/binl64:/opt/watcom/binl"
ENV INCLUDE="/opt/watcom/h:/opt/watcom/h/nt"

WORKDIR /src
