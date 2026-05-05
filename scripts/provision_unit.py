#!/usr/bin/env python3
"""
ZKNOT PowerVerify Unit Provisioning + Label Printing
=====================================================

End-to-end QC workflow tool. For each finished unit:
  1. Calls POST /v1/units/provision on api.zknot.io (mints POWERVERIFY_UNIT,
     appends to ZK-LocalChain, returns ZK short code)
  2. Generates QR code image
  3. Composes printable labels
  4. Sends to Brother QL-820NWB over USB
  5. Optionally enrolls PUF baseline from a photo

Usage:
  # Provision + print labels
  ZKNOT_PROVISIONING_TOKEN=<token> python provision_unit.py \\
    --sn PV1-00001 --batch BATCH-001

  # Batch from CSV (columns: serial_number, batch_id, build_notes)
  python provision_unit.py --csv batch_001.csv

  # Provision + enroll PUF in one shot
  python provision_unit.py --sn PV1-00001 --batch BATCH-001 \\
    --puf-photo ./photos/PV1-00001.jpg

  # Re-print only (no provisioning)
  python provision_unit.py --sn PV1-00001 --reprint
"""
import argparse
import csv
import json
import os
import sys
from dataclasses import dataclass, asdict
from datetime import date
from pathlib import Path
from typing import Optional

import qrcode
import requests
from PIL import Image, ImageDraw, ImageFont


API_BASE = os.environ.get("ZKNOT_API_BASE", "https://api.zknot.io")
PROVISIONING_TOKEN = os.environ.get("ZKNOT_PROVISIONING_TOKEN")

# Brother QL-820NWB with 62mm continuous tape: 696px wide at 300dpi
LABEL_WIDTH_PX = 696
LABEL_HEIGHT_PX = 354


# ---------------------------------------------------------------------------
@dataclass
class UnitProvision:
    serial_number: str
    short_code: str          # ZK-XXXX-XXX
    qr_url: str
    chain_position: int
    artifact_id: str
    manufacture_date: str
    batch_id: str


# ---------------------------------------------------------------------------
class ZknotClient:
    def __init__(self, base: str = API_BASE, token: Optional[str] = None):
        self.base = base.rstrip("/")
        self.token = token or PROVISIONING_TOKEN
        if not self.token:
            raise RuntimeError("ZKNOT_PROVISIONING_TOKEN env var is required")
        self.session = requests.Session()
        self.session.headers["Authorization"] = f"Bearer {self.token}"

    def provision(self, sn: str, batch: str,
                  manufacture_date: Optional[date] = None,
                  build_notes: str = "") -> UnitProvision:
        if manufacture_date is None:
            manufacture_date = date.today()
        body = {
            "serial_number": sn,
            "batch_id": batch,
            "manufacture_date": manufacture_date.isoformat(),
            "build_notes": build_notes or None,
        }
        r = self.session.post(f"{self.base}/v1/units/provision", json=body, timeout=30)
        r.raise_for_status()
        d = r.json()
        return UnitProvision(
            serial_number=d["serial_number"],
            short_code=d["short_code"],
            qr_url=d["qr_url"],
            chain_position=d["chain_position"],
            artifact_id=d["artifact_id"],
            manufacture_date=d["label_payload"]["manufacture_date"],
            batch_id=d["label_payload"]["batch_id"],
        )

    def enroll_puf(self, short_code: str, photo_path: Path) -> dict:
        with photo_path.open("rb") as f:
            files = {"photo": (photo_path.name, f, "image/jpeg")}
            r = self.session.post(
                f"{self.base}/v1/units/{short_code}/puf/enroll",
                files=files,
                timeout=60,
            )
        r.raise_for_status()
        return r.json()


# ---------------------------------------------------------------------------
def make_qr(url: str, target_px: int = 290) -> Image.Image:
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=10,
        border=2,
    )
    qr.add_data(url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white").convert("RGB")
    return img.resize((target_px, target_px), Image.NEAREST)


def compose_back_label(unit: UnitProvision) -> Image.Image:
    """SN + ZK + QR composite for the back of the board."""
    img = Image.new("RGB", (LABEL_WIDTH_PX, LABEL_HEIGHT_PX), "white")
    draw = ImageDraw.Draw(img)
    img.paste(make_qr(unit.qr_url, 290), (32, 32))

    text_x = 360
    try:
        font_brand = ImageFont.truetype(
            "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 38)
        font_product = ImageFont.truetype(
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 22)
        font_mono = ImageFont.truetype(
            "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", 32)
        font_meta = ImageFont.truetype(
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 22)
    except OSError:
        font_brand = font_product = font_mono = font_meta = ImageFont.load_default()

    draw.text((text_x, 30), "ZKNOT", fill="black", font=font_brand)
    draw.text((text_x, 78), "PowerVerify Rev 1", fill="black", font=font_product)
    draw.text((text_x, 130), f"SN: {unit.serial_number}", fill="black", font=font_mono)
    draw.text((text_x, 175), f"ZK: {unit.short_code}", fill="black", font=font_mono)
    draw.text((text_x, 220), f"MFG: {unit.manufacture_date}", fill="black", font=font_meta)
    draw.text((text_x, 250), f"Chain #{unit.chain_position}", fill="black", font=font_meta)
    draw.text((text_x, 285), "verifyknot.io", fill="black", font=font_meta)
    return img


def compose_front_qr_label(unit: UnitProvision) -> Image.Image:
    """Small QR-only label for the front of the cured encapsulation."""
    return make_qr(unit.qr_url, 200)


# ---------------------------------------------------------------------------
def print_to_ql820(image: Image.Image, label_size: str = "62") -> bool:
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
        threshold=70.0, dither=False, compress=False, red=False,
        dpi_600=False, hq=True, cut=True,
    )
    result = send(
        instructions=instructions,
        printer_identifier="usb://0x04f9:0x209d",
        backend_identifier="pyusb",
        blocking=True,
    )
    return bool(result.get("did_print"))


def print_tamper_strip(unit: UnitProvision) -> bool:
    """Print a 6mm tamper strip on the PT-E560BT via ptouch-print CLI."""
    import subprocess
    text = f"ZKNOT VOID {unit.serial_number}"
    try:
        result = subprocess.run(
            ["ptouch-print", "--text", text],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            print(f"  [warn] tamper strip print failed: {result.stderr.strip()}")
            return False
        return True
    except FileNotFoundError:
        print("  [warn] ptouch-print not installed — skipping tamper strip")
        return False


# ---------------------------------------------------------------------------
def provision_and_print(sn: str, batch: str, build_notes: str = "",
                         puf_photo: Optional[Path] = None,
                         skip_print: bool = False,
                         output_dir: Path = Path("./labels")) -> UnitProvision:
    output_dir.mkdir(parents=True, exist_ok=True)
    client = ZknotClient()

    print(f"\n=== Provisioning {sn} (batch {batch}) ===")
    unit = client.provision(sn, batch, build_notes=build_notes)
    print(f"  Short code:     {unit.short_code}")
    print(f"  Chain position: #{unit.chain_position}")
    print(f"  Artifact ID:    {unit.artifact_id}")
    print(f"  QR URL:         {unit.qr_url}")

    # Save unit data sidecar for re-prints
    sidecar = output_dir / f"{sn}_unit.json"
    sidecar.write_text(json.dumps(asdict(unit), indent=2))

    # Compose & save labels
    back = compose_back_label(unit)
    front = compose_front_qr_label(unit)
    back_path = output_dir / f"{sn}_back.png"
    front_path = output_dir / f"{sn}_front_qr.png"
    back.save(back_path)
    front.save(front_path)
    print(f"  Labels saved: {back_path.name}, {front_path.name}")

    if not skip_print:
        print("  Printing back label (62mm)...")
        ok = print_to_ql820(back, label_size="62")
        print(f"    {'OK' if ok else 'FAILED'}")
        print("  Printing tamper strip (6mm)...")
        print_tamper_strip(unit)

    if puf_photo:
        print(f"  Enrolling PUF baseline from {puf_photo}...")
        result = client.enroll_puf(unit.short_code, puf_photo)
        print(f"    Enrolled. phash: {result['perceptual_hash']}")

    return unit


def reprint_labels(sn: str, output_dir: Path = Path("./labels")):
    sidecar = output_dir / f"{sn}_unit.json"
    if not sidecar.exists():
        print(f"  [error] No saved data at {sidecar}")
        sys.exit(1)
    unit = UnitProvision(**json.loads(sidecar.read_text()))
    back = compose_back_label(unit)
    front = compose_front_qr_label(unit)
    print_to_ql820(back, label_size="62")
    print_tamper_strip(unit)


# ---------------------------------------------------------------------------
def main():
    p = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,
                                 description=__doc__)
    p.add_argument("--sn")
    p.add_argument("--batch")
    p.add_argument("--notes", default="")
    p.add_argument("--puf-photo", type=Path)
    p.add_argument("--csv", type=Path)
    p.add_argument("--reprint", action="store_true")
    p.add_argument("--no-print", action="store_true")
    p.add_argument("--output-dir", type=Path, default=Path("./labels"))
    args = p.parse_args()

    if args.csv:
        with args.csv.open() as f:
            for row in csv.DictReader(f):
                provision_and_print(
                    sn=row["serial_number"],
                    batch=row["batch_id"],
                    build_notes=row.get("build_notes", ""),
                    skip_print=args.no_print,
                    output_dir=args.output_dir,
                )
        return

    if args.reprint:
        if not args.sn:
            p.error("--sn required for --reprint")
        reprint_labels(args.sn, args.output_dir)
        return

    if not args.sn or not args.batch:
        p.error("--sn and --batch required (or use --csv)")

    provision_and_print(
        sn=args.sn, batch=args.batch, build_notes=args.notes,
        puf_photo=args.puf_photo, skip_print=args.no_print,
        output_dir=args.output_dir,
    )


if __name__ == "__main__":
    main()
