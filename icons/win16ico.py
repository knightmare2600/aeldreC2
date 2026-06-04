#!/usr/bin/env python3
"""
win16ico.py -- Convert any image to a 4-bit (16-colour) Windows ICO file.

Produces 32x32 and 16x16 images quantised to the classic Windows VGA
palette and written as a proper 4bpp ICO.  Compatible with Win3.1 / Win32s.

Usage: python3 win16ico.py <input_image> <output.ico>
"""

import struct, sys
from PIL import Image

WIN16_PAL = [
    (  0,   0,   0),  #  0  Black
    (128,   0,   0),  #  1  Maroon
    (  0, 128,   0),  #  2  Green
    (128, 128,   0),  #  3  Olive
    (  0,   0, 128),  #  4  Navy
    (128,   0, 128),  #  5  Purple
    (  0, 128, 128),  #  6  Teal
    (192, 192, 192),  #  7  Silver
    (128, 128, 128),  #  8  Gray
    (255,   0,   0),  #  9  Red
    (  0, 255,   0),  # 10  Lime
    (255, 255,   0),  # 11  Yellow
    (  0,   0, 255),  # 12  Blue
    (255,   0, 255),  # 13  Fuchsia
    (  0, 255, 255),  # 14  Aqua
    (255, 255, 255),  # 15  White
]

def nearest(r, g, b):
    best, bd = 0, 0x7FFFFFFF
    for i, (pr, pg, pb) in enumerate(WIN16_PAL):
        d = (r-pr)**2 + (g-pg)**2 + (b-pb)**2
        if d < bd:
            bd, best = d, i
    return best

def fit_square(img, size):
    """Scale image to fit within size×size, centred on transparent canvas."""
    rgba = img.convert('RGBA')
    w, h = rgba.size
    scale = min(size / w, size / h)
    nw = max(1, int(w * scale))
    nh = max(1, int(h * scale))
    rgba = rgba.resize((nw, nh), Image.LANCZOS)
    canvas = Image.new('RGBA', (size, size), (255, 255, 255, 0))
    canvas.paste(rgba, ((size - nw) // 2, (size - nh) // 2), rgba)
    return canvas

def make_4bpp_dib(img_rgba, size):
    """Return the DIB bytes (BITMAPINFOHEADER + palette + XOR + AND masks)."""
    w = h = size

    # Strides (DWORD-aligned)
    xor_stride = ((w * 4 + 31) // 32) * 4   # 4bpp
    and_stride = ((w     + 31) // 32) * 4   # 1bpp

    xor_data = bytearray(xor_stride * h)
    and_data = bytearray(and_stride * h)

    for sy in range(h):
        dy = h - 1 - sy          # DIBs are bottom-up
        for x in range(w):
            r, g, b, a = img_rgba.getpixel((x, sy))
            transparent = (a < 128)
            idx = nearest(r, g, b) if not transparent else 15

            # XOR: two 4-bit nibbles per byte, high nibble = left pixel
            bp = dy * xor_stride + x // 2
            if x % 2 == 0:
                xor_data[bp]  = idx << 4
            else:
                xor_data[bp] |= idx

            # AND: 1 = transparent
            if transparent:
                bp = dy * and_stride + x // 8
                and_data[bp] |= 0x80 >> (x % 8)

    bih = struct.pack('<IiiHHIIiiII',
        40, w, h * 2, 1, 4, 0, 0, 0, 0, 16, 16)

    pal = bytearray()
    for r, g, b in WIN16_PAL:
        pal += bytes([b, g, r, 0])   # RGBQUAD is BGR + reserved

    return bytes(bih) + bytes(pal) + bytes(xor_data) + bytes(and_data)

def make_ico(src, dst):
    img   = Image.open(src)
    sizes = [32, 16]
    dibs  = [(sz, make_4bpp_dib(fit_square(img, sz), sz)) for sz in sizes]

    n          = len(dibs)
    dir_offset = 6 + 16 * n
    offsets    = []
    cur        = dir_offset
    for _, d in dibs:
        offsets.append(cur)
        cur += len(d)

    with open(dst, 'wb') as f:
        f.write(struct.pack('<HHH', 0, 1, n))       # ICONDIR
        for i, (sz, d) in enumerate(dibs):
            f.write(struct.pack('<BBBBHHII',         # ICONDIRENTRY
                sz, sz, 16, 0, 1, 4, len(d), offsets[i]))
        for _, d in dibs:
            f.write(d)

    print(f"  {src} -> {dst}  ({', '.join(f'{s}x{s}' for s,_ in dibs)}, 4bpp)")

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(f'Usage: {sys.argv[0]} <input> <output.ico>')
        sys.exit(1)
    make_ico(sys.argv[1], sys.argv[2])
