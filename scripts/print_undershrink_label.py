#!/usr/bin/env python3
"""
ZKNOT Under-Shrink Label Generator (DK-2251 Thermal Tape)
==========================================================

Produces a small 3-line label intended to be placed INSIDE the heat shrink,
on the back of the PCB. Three lines:

    ZKNOT
    PV1-XXXXX
    ZK-XXXX-XXX

Format choice rationale:
- No QR (label is invisible to customer; QR lives on insert card)
- Larger text than the back-label since this is the durable forensic ID
- Designed for 62mm tape (DK-2251 red/white thermal) but fills only the
  leftmost ~40mm to allow trimming or to stack two labels per cut
- Functions as both a forensic identifier AND a passive thermal tamper
  indicator: any sustained heat above ~70°C activates the red layer,
  visibly invalidating the unit

Usage:
    python3 print_undershrink_label.py --sn PV1-00001
    python3 print_undershrink_label.py --batch PV1-00001 PV1-00002 PV1-00003
    python3 print_undershrink_label.py --csv batch.csv --no-print

Reads the same sidecar JSON files written by provision_unit.py
(at ~/zknot-api/labels/{sn}_unit.json) so SN/ZK pairing is canonical.
"""
import argparse
import json
import sys
import time
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


# QL-820NWB on 62mm tape: 696px wide at 300dpi
LABEL_WIDTH_PX = 696

# Compact label height — keeps tape usage low.
# 200px ≈ 17mm physical height, perfect for the 17×22mm PCB area.
LABEL_HEIGHT_PX = 200

# Content lives in the left portion so user can trim if desired
CONTENT_LEFT_PX = 32
CONTENT_TOP_PX = 14


def compose_undershrink_label(sn: str, zk_code: str) -> Image.Image:
    """3-line forensic identifier label for under heat shrink."""
    img = Image.new("RGB", (LABEL_WIDTH_PX, LABEL_HEIGHT_PX), "white")
    draw = ImageDraw.Draw(img)

    try:
        font_brand = ImageFont.truetype(
            "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 56)
        font_mono_lg = ImageFont.truetype(
            "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf", 44)
        font_mono_lg_zk = ImageFont.truetype(
            "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf", 44)
    except OSError:
        font_brand = font_mono_lg = font_mono_lg_zk = ImageFont.load_default()

    # Line 1 — Brand
    draw.text((CONTENT_LEFT_PX, CONTENT_TOP_PX),
              "ZKNOT",
              fill="black", font=font_brand)

    # Line 2 — SN (the persistent device identifier)
    draw.text((CONTENT_LEFT_PX, CONTENT_TOP_PX + 64),
              sn,
              fill="black", font=font_mono_lg)

    # Line 3 — ZK short code (chain-resolvable)
    draw.text((CONTENT_LEFT_PX, CONTENT_TOP_PX + 120),
              zk_code,
              fill="black", font=font_mono_lg_zk)

    return img


def print_to_ql820(image: Image.Image, label_size: str = "62red") -> bool:
    """Print to Brother QL-820NWB over USB."""
    try:
        from brother_ql.conversion import convert
        from brother_ql.backends.helpers import send
        from brother_ql.raster import BrotherQLRaster
    except ImportError:
        print("  [error] brother_ql not installed: pip install brother_ql")
        return False

    qlr = BrotherQLRaster("QL-820NWB")
    qlr.exception_on_warning = True
    instructions = convert(
        qlr=qlr, images=[image], label=label_size, rotate="0",
        threshold=70.0, dither=False, compress=False, red=True,
        dpi_600=False, hq=True, cut=True,
    )
    result = send(
        instructions=instructions,
        printer_identifier="usb://0x04f9:0x209d",
        backend_identifier="pyusb",
        blocking=True,
    )
    return bool(result.get("did_print"))


def load_sidecar(sn: str, sidecar_dir: Path) -> dict:
    """Load the {sn}_unit.json sidecar written by provision_unit.py."""
    path = sidecar_dir / f"{sn}_unit.json"
    if not path.exists():
        raise FileNotFoundError(
            f"No sidecar at {path}. Run provision_unit.py for {sn} first.")
    return json.loads(path.read_text())


def process_unit(sn: str, sidecar_dir: Path, output_dir: Path,
                 no_print: bool) -> None:
    """Generate (and optionally print) the under-shrink label for one unit."""
    data = load_sidecar(sn, sidecar_dir)
    zk_code = data["short_code"]

    print(f"  {sn} → {zk_code}")

    img = compose_undershrink_label(sn, zk_code)
    output_path = output_dir / f"{sn}_undershrink.png"
    img.save(output_path)
    print(f"    Label saved: {output_path.name}")

    if not no_print:
        ok = print_to_ql820(img, label_size="62red")
        print(f"    Print: {'OK' if ok else 'FAILED'}")


def main():
    p = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,
                                 description=__doc__)
    p.add_argument("--sn", help="Single serial number to print")
    p.add_argument("--batch", nargs="+",
                   help="Multiple SNs (e.g. --batch PV1-00001 PV1-00002)")
    p.add_argument("--csv",
                   help="CSV file with serial_number column")
    p.add_argument("--no-print", action="store_true",
                   help="Generate PNG only, do not print")
    p.add_argument("--sidecar-dir", type=Path,
                   default=Path.home() / "zknot-api" / "labels",
                   help="Directory containing {sn}_unit.json files")
    p.add_argument("--output-dir", type=Path,
                   default=Path.home() / "zknot-api" / "labels",
                   help="Where to save generated label PNGs")
    p.add_argument("--delay", type=float, default=2.5,
                   help="Seconds to wait between prints in batch mode")
    args = p.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)

    # Build the SN list from whichever input mode was used
    sns = []
    if args.sn:
        sns.append(args.sn)
    if args.batch:
        sns.extend(args.batch)
    if args.csv:
        import csv
        with open(args.csv) as f:
            for row in csv.DictReader(f):
                sns.append(row["serial_number"])

    if not sns:
        p.error("Specify --sn, --batch, or --csv")

    print(f"Processing {len(sns)} under-shrink label(s)...")
    print()

    for i, sn in enumerate(sns):
        try:
            process_unit(sn, args.sidecar_dir, args.output_dir, args.no_print)
        except Exception as e:
            print(f"  ✗ {sn}: {e}")
            continue

        # Delay between prints to let the cutter clear
        if not args.no_print and i < len(sns) - 1:
            time.sleep(args.delay)

    print()
    print("Done.")


if __name__ == "__main__":
    main()
