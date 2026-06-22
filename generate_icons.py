"""
generate_icons.py — Standalone icon variant generator for EQ Guild Chat Client.

Run this script independently to generate or regenerate the three status
variant icons from your base Sarnak icon:

    python generate_icons.py
    python generate_icons.py --icon-dir icons --icon-name icon.png

The base icon should be a 74x74 transparent PNG with:
  - Black body   (#000000)
  - Yellow eye   (#E0B45A)

Output files (written to the same directory as the base icon):
  icon_r.png  -- red body,    disconnected
  icon_y.png  -- yellow body, connected / no clients
  icon_g.png  -- green body,  connected with active clients

These files are always overwritten when you run this script, so you can
re-run it any time you update the base icon.
"""

import argparse
import os
import sys

try:
    from PIL import Image
except ImportError:
    print("Pillow is required: pip install Pillow")
    sys.exit(1)


BODY_COLOUR = (0,   0,   0,   255)
EYE_COLOUR  = (224, 180, 90,  255)
EYE_DARK    = (120, 60,  10,  255)

VARIANTS = {
    "red":    {"suffix": "r", "body": (192, 57,  43,  255), "eye": None,     "label": "Disconnected"},
    "yellow": {"suffix": "y", "body": (212, 160, 23,  255), "eye": EYE_DARK, "label": "Connected / no clients"},
    "green":  {"suffix": "g", "body": (39,  174, 96,  255), "eye": None,     "label": "Connected with clients"},
}

TOLERANCE = 30


def recolour(src: Image.Image, new_body: tuple, new_eye: tuple | None) -> Image.Image:
    out    = src.copy()
    pixels = out.load()
    w, h   = out.size
    for y in range(h):
        for x in range(w):
            r, g, b, a = pixels[x, y]
            if a == 0:
                continue
            if colour_close((r, g, b, a), BODY_COLOUR, TOLERANCE):
                nr, ng, nb, _ = new_body
                pixels[x, y]  = (nr, ng, nb, a)
            elif new_eye and colour_close((r, g, b, a), EYE_COLOUR, TOLERANCE):
                er, eg, eb, _ = new_eye
                pixels[x, y]  = (er, eg, eb, a)
    return out


def colour_close(c1: tuple, c2: tuple, tol: int) -> bool:
    return all(abs(a - b) <= tol for a, b in zip(c1[:3], c2[:3]))


def variant_path(icon_dir: str, icon_name: str, suffix: str) -> str:
    name, ext = os.path.splitext(icon_name)
    return os.path.join(icon_dir, f"{name}_{suffix}{ext}")


def main():
    parser = argparse.ArgumentParser(description="Generate EQ Guild Chat Client tray icon variants.")
    parser.add_argument("--icon-dir",  default="icons",    help="Directory containing icon.png (default: icons)")
    parser.add_argument("--icon-name", default="icon.png", help="Base icon filename (default: icon.png)")
    args = parser.parse_args()

    base_path = os.path.join(args.icon_dir, args.icon_name)
    if not os.path.exists(base_path):
        print(f"Error: base icon not found at '{base_path}'")
        print("Place your Sarnak icon.png in the icons/ folder and try again.")
        sys.exit(1)

    print(f"Loading base icon: {base_path}")
    src = Image.open(base_path).convert("RGBA")
    print(f"  Size: {src.size[0]}x{src.size[1]}")

    for status, spec in VARIANTS.items():
        out_path = variant_path(args.icon_dir, args.icon_name, spec["suffix"])
        variant  = recolour(src, spec["body"], spec["eye"])
        variant.save(out_path)
        print(f"  Generated {out_path}  ({spec['label']})")

    print("\nDone. Place these files in the same icons/ folder as your exe.")


if __name__ == "__main__":
    main()