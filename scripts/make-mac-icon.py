#!/usr/bin/env python3
"""Generates mac/Resources/AppIcon.png (1024x1024), the source of the Mac host app icon.

scripts/build-mac.sh turns the PNG into AppIcon.icns with sips + iconutil. Re-run this script
only to change the design:  python3 scripts/make-mac-icon.py
Needs Pillow (pip install Pillow). Same motif as the client icon (tauri/app-icon.svg: a screen
with a heart), in teal so the Mac you control is easy to tell apart from the client app.
"""
import math
import os
import sys

from PIL import Image, ImageDraw, ImageFilter

SIZE = 1024
SS = 4  # supersampling factor
S = SIZE * SS


def lerp(a, b, t):
    return tuple(int(round(a[i] + (b[i] - a[i]) * t)) for i in range(len(a)))


def vertical_gradient(size, top, bottom):
    img = Image.new("RGBA", (size, size))
    draw = ImageDraw.Draw(img)
    for y in range(size):
        draw.line([(0, y), (size, y)], fill=lerp(top, bottom, y / (size - 1)) + (255,))
    return img


def rounded_mask(size, box, radius):
    mask = Image.new("L", (size, size), 0)
    ImageDraw.Draw(mask).rounded_rectangle(box, radius=radius, fill=255)
    return mask


def heart_points(cx, cy, scale, steps=720):
    pts = []
    for i in range(steps):
        t = 2 * math.pi * i / steps
        x = 16 * math.sin(t) ** 3
        y = 13 * math.cos(t) - 5 * math.cos(2 * t) - 2 * math.cos(3 * t) - math.cos(4 * t)
        pts.append((cx + x * scale, cy - y * scale))
    return pts


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "mac", "Resources", "AppIcon.png")

    canvas = Image.new("RGBA", (S, S), (0, 0, 0, 0))

    # macOS-style tile: 824/1024 with a soft drop shadow.
    tile = (100 * SS, 100 * SS, 924 * SS, 924 * SS)
    radius = 185 * SS
    shadow = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    ImageDraw.Draw(shadow).rounded_rectangle(
        (tile[0], tile[1] + 14 * SS, tile[2], tile[3] + 14 * SS), radius=radius, fill=(0, 0, 0, 90))
    shadow = shadow.filter(ImageFilter.GaussianBlur(18 * SS))
    canvas = Image.alpha_composite(canvas, shadow)

    gradient = vertical_gradient(S, (38, 196, 188), (12, 88, 112))
    canvas.paste(gradient, (0, 0), rounded_mask(S, tile, radius))

    glyph = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    draw = ImageDraw.Draw(glyph)
    white = (255, 255, 255, 255)
    # Screen
    draw.rounded_rectangle((226 * SS, 250 * SS, 798 * SS, 642 * SS), radius=48 * SS,
                           outline=white, width=40 * SS)
    # Stand
    stroke = 40 * SS
    for (x0, y0, x1, y1) in [(452, 646, 432, 726), (572, 646, 592, 726), (392, 734, 632, 734)]:
        draw.line((x0 * SS, y0 * SS, x1 * SS, y1 * SS), fill=white, width=stroke)
    for (x, y) in [(432, 726), (592, 726), (392, 734), (632, 734)]:
        r = stroke / 2
        draw.ellipse((x * SS - r, y * SS - r, x * SS + r, y * SS + r), fill=white)
    # Heart in the screen
    draw.polygon(heart_points(512 * SS, 440 * SS, 9.2 * SS), fill=white)
    # "Remote" waves at the top right of the screen
    cx, cy = 790, 258
    for i, radius_w in enumerate([78, 124]):
        box = ((cx - radius_w) * SS, (cy - radius_w) * SS, (cx + radius_w) * SS, (cy + radius_w) * SS)
        draw.arc(box, start=282, end=348, fill=(255, 255, 255, 235 - 60 * i), width=24 * SS)

    canvas = Image.alpha_composite(canvas, glyph)
    icon = canvas.resize((SIZE, SIZE), Image.LANCZOS)
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    icon.save(out, "PNG", optimize=True)
    print("wrote", os.path.abspath(out))


if __name__ == "__main__":
    main()
