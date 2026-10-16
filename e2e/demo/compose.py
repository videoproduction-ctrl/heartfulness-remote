#!/usr/bin/env python3
"""Composes demo/out/{phone,laptop}.webm + captions.json into one captioned MP4.

Layout: phone (scaled to 800 px tall) | laptop (1280x800), caption bar below.
"""
import json
import subprocess
import sys
from pathlib import Path

out = Path(__file__).resolve().parent / "out"
caps = json.loads((out / "captions.json").read_text())["captions"]
font = "/usr/share/fonts/opentype/inter/Inter-SemiBold.otf"
if not Path(font).exists():
    font = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"

def esc(s: str) -> str:
    return s.replace("\\", "\\\\").replace(":", "\\:").replace("'", "’").replace("%", "\\%").replace(",", "\\,")

draw = []
for c in caps:
    draw.append(
        f"drawtext=fontfile={font}:text='{esc(c['text'])}':fontcolor=white:fontsize=30:"
        f"x=(w-text_w)/2:y=h-75:enable='between(t,{c['start']:.2f},{c['end']:.2f})'"
    )
title = (
    f"drawtext=fontfile={font}:text='Heartfulness Remote — real system test (server + Mac agent + browsers)':"
    f"fontcolor=0xBBBBBB:fontsize=20:x=20:y=h-125"
)
fc = (
    "[0:v]scale=-2:800,setsar=1,fps=30[p];"
    "[1:v]scale=1280:800,setsar=1,fps=30[l];"
    "[p][l]hstack=inputs=2,pad=iw+40:ih+150:20:0:color=0x111111,"
    + title + "," + ",".join(draw) + "[v]"
)
dst = out / "heartfulness-remote-walkthrough.mp4"
cmd = [
    "ffmpeg", "-y", "-hide_banner", "-loglevel", "error",
    "-i", str(out / "phone.webm"), "-i", str(out / "laptop.webm"),
    "-filter_complex", fc, "-map", "[v]",
    "-c:v", "libx264", "-preset", "slow", "-crf", "20", "-pix_fmt", "yuv420p", "-movflags", "+faststart",
    str(dst),
]
subprocess.run(cmd, check=True)
print(dst)
sys.exit(0)
