"""
PUF (Physical Unclonable Function) service.

Computes perceptual hashes of holographic glitter photos for tamper-evidence
verification. The PUF lives separately from the chain — these are auxiliary
identity records, not signed events.

Tolerance threshold (in bits of Hamming distance) is empirically tuned:
photos of the SAME unit under varying conditions stay below threshold;
photos of DIFFERENT units stay above. Defaults below assume good QC rig
discipline (90° angle, ring light, fixed distance).
"""
import io
from typing import Tuple

from PIL import Image
import imagehash

# Tolerance bands, in Hamming distance over 256-bit phash:
#   <=4   = high confidence match
#   5-8   = medium
#   9-12  = low (warn user about photo conditions)
#   >12   = fail
PUF_THRESHOLD_HIGH = 4
PUF_THRESHOLD_MEDIUM = 8
PUF_THRESHOLD_LOW = 12


def compute_phash(file_bytes: bytes) -> Tuple[str, dict]:
    """Compute the perceptual hash + capture metadata from raw photo bytes."""
    img = Image.open(io.BytesIO(file_bytes))
    metadata = {
        "format": img.format,
        "size": img.size,
        "mode": img.mode,
    }
    # Normalize to grayscale + fixed size before hashing for consistency
    img_gray = img.convert("L").resize((256, 256), Image.LANCZOS)
    phash = imagehash.phash(img_gray, hash_size=16)  # 16x16 = 256 bits
    return str(phash), metadata


def compare_phashes(baseline_hex: str, candidate_hex: str) -> Tuple[int, bool, str]:
    """Compare two phashes. Returns (hamming_distance, matched, confidence)."""
    h_baseline = imagehash.hex_to_hash(baseline_hex)
    h_candidate = imagehash.hex_to_hash(candidate_hex)
    distance = int(h_baseline - h_candidate)  # coerce numpy.int64 -> int for psycopg2

    if distance <= PUF_THRESHOLD_HIGH:
        confidence = "high"
        matched = True
    elif distance <= PUF_THRESHOLD_MEDIUM:
        confidence = "medium"
        matched = True
    elif distance <= PUF_THRESHOLD_LOW:
        confidence = "low"
        matched = True
    else:
        confidence = "fail"
        matched = False

    return distance, matched, confidence
