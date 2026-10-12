#!/usr/bin/env python3
"""Nbte7m · Forensics Bench — five-capability digital forensics workbench.

Tools (left rail):
    NbExif      Full metadata extraction via ExifTool (every supported format)
    NbCorrupt   Damage / encrypt / truncate / overwrite files, symlinks and links
    MetaDelete  Metadata wipe, selective group wipe and metadata reproduction
    Shr3dder    Multi-pass secure overwrite + unlink (Linux `shred` semantics)
    HideMe      File-in-file steganography: embed / extract / check any file type

Requires: Python 3.9+, Tkinter, ExifTool on PATH, `cryptography`, `pillow`.
Run:     python3 app.py
"""

from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import hmac
import json
import math
import mimetypes
import os
import queue
import random
import re
import shutil
import stat
import subprocess
import threading
import time
from pathlib import Path
from typing import Callable, Iterable

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

try:  # Pillow is used only by HideMe's pixel (LSB) mode.
    from PIL import Image
    HAVE_PILLOW = True
except Exception:  # pragma: no cover - optional dependency
    Image = None  # type: ignore
    HAVE_PILLOW = False

try:  # cryptography powers AES for HideMe and NbCorrupt.
    from cryptography.hazmat.primitives import hashes, padding as sym_padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    HAVE_CRYPTO = True
except Exception:  # pragma: no cover - optional dependency
    HAVE_CRYPTO = False


# ══════════════════════════════════════════════════════════════════════════
#  Palette / typography  —  dark-blue forensic workstation
# ══════════════════════════════════════════════════════════════════════════
APP_NAME = "Forensics Bench"
BG = "#070f1c"
RAIL = "#0a1727"
SURFACE = "#0f1e30"
SURFACE_2 = "#0b1725"
FIELD = "#0c1b2c"
LINE = "#22374f"
LINE_SOFT = "#1a2b40"
TEXT = "#e9f1fb"
MUTED = "#8ea3ba"
DIM = "#6b8098"
ACCENT = "#5fd8cc"
ACCENT_DARK = "#04201f"
ACCENT_DEEP = "#123a44"
WARNING = "#ffb96c"
DANGER = "#ff7e82"
DANGER_BG = "#2c1d24"
DANGER_EDGE = "#6a3a45"
WARN_BG = "#2a211a"
WARN_EDGE = "#5c4432"
OK_BG = "#0f2620"
OK_EDGE = "#27503f"
OK_TEXT = "#b6e0d1"

FONT = ("Segoe UI", 10)
FONT_SM = ("Segoe UI", 9)
FONT_XS = ("Segoe UI", 8)
MONO = ("Consolas", 9)
MONO_SM = ("Consolas", 8)
MONO_LG = ("Consolas", 10)

PAGE_NAMES = {
    "exif": "NbExif",
    "corrupt": "NbCorrupt",
    "delete": "MetaDelete",
    "shred": "Shr3dder",
    "hide": "HideMe",
}

NAV_ITEMS = (
    ("exif", "NbExif", "EX"),
    ("corrupt", "NbCorrupt", "BC"),
    ("delete", "MetaDelete", "MD"),
    ("shred", "Shr3dder", "S3"),
    ("hide", "HideMe", "HM"),
)

SIGNATURES: tuple[tuple[bytes, str], ...] = (
    (b"\x89PNG\r\n\x1a\n", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"GIF87a", "GIF image"),
    (b"GIF89a", "GIF image"),
    (b"BM", "BMP image"),
    (b"II*\x00", "TIFF image (little endian)"),
    (b"MM\x00*", "TIFF image (big endian)"),
    (b"%PDF-", "PDF document"),
    (b"PK\x03\x04", "ZIP / OOXML / JAR archive"),
    (b"Rar!\x1a\x07", "RAR archive"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    (b"\x1f\x8b", "gzip stream"),
    (b"BZh", "bzip2 stream"),
    (b"\xfd7zXZ\x00", "XZ stream"),
    (b"MZ", "DOS/Windows executable"),
    (b"\x7fELF", "ELF executable"),
    (b"SQLite format 3\x00", "SQLite database"),
    (b"\xca\xfe\xba\xbe", "Java class / Mach-O fat binary"),
    (b"\x00\x00\x00\x18ftyp", "MP4 / ISO base media"),
    (b"\x00\x00\x00 ftyp", "MP4 / ISO base media"),
    (b"OggS", "Ogg container"),
    (b"ID3", "MP3 with ID3 tag"),
    (b"fLaC", "FLAC audio"),
    (b"\x25\x21PS", "PostScript"),
    (b"{\\rtf", "RTF document"),
    (b"ustar", "TAR archive"),
    (b"<?xml", "XML document"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE2 compound document (legacy Office)"),
    (b"wOFF", "WOFF web font"),
    (b"wOF2", "WOFF2 web font"),
    (b"\x1a\x45\xdf\xa3", "Matroska / WebM video"),
    (b"FLV\x01", "Flash video"),
)

TEXT_CONTAINERS = (".txt", ".csv", ".tsv", ".log", ".json", ".xml", ".md", ".py",
                   ".c", ".h", ".js", ".css", ".html", ".ini", ".yaml", ".yml")

# Header groups ExifTool understands for selective deletion / extraction.
GROUP_MENU = (
    "EXIF", "IPTC", "XMP", "XMP-dc", "XMP-photoshop", "XMP-xmp", "PNG", "JPEG",
    "TIFF", "ICC_Profile", "Photoshop", "PhotoshopIRB", "MakerNotes", "JFIF",
    "Trailer", "PICC", "QuickTime", "RIFF", "MIE", "File", "Adobe", "MP4",
    "Key", "App14", "Comment", "XMPToolkit", "Dump", "FLAC", "ID3",
)


# ══════════════════════════════════════════════════════════════════════════
#  Generic helpers
# ══════════════════════════════════════════════════════════════════════════
def exiftool_path() -> str | None:
    """Locate the ExifTool binary (system PATH, common install roots, perl)."""
    found = shutil.which("exiftool")
    if found:
        return found
    candidates = [
        "/usr/local/bin/exiftool",
        "/usr/bin/exiftool",
        "/opt/exiftool",
        str(Path.home() / "perl" / "bin" / "exiftool"),
        str(Path.home() / "bin" / "exiftool"),
    ]
    for candidate in candidates:
        if os.access(candidate, os.X_OK):
            return candidate
    for base in ("/usr/share/perl", "/usr/local/share/perl", str(Path.home() / "perl")):
        root = Path(base)
        if root.is_dir():
            try:
                for item in root.rglob("exiftool"):
                    if item.is_file():
                        return str(item)
            except OSError:
                continue
    return None


def run_exiftool(args: list[str], timeout: int | None = 600) -> subprocess.CompletedProcess:
    binary = exiftool_path()
    if not binary:
        raise RuntimeError(
            "ExifTool was not found. Install it (apt install libimage-exiftool-perl) "
            "or place the 'exiftool' executable on PATH."
        )
    command = [binary, "-charset", "filename=UTF8", "-api", "LargeFileSupport=1", *args]
    return subprocess.run(command, capture_output=True, text=True,
                          errors="replace", check=False, timeout=timeout)


def exiftool_version() -> str:
    try:
        proc = run_exiftool(["-ver"], timeout=30)
        return proc.stdout.strip() or "unknown"
    except Exception:
        return "not installed"


def format_bytes(size: float) -> str:
    value = float(size)
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if value < 1024 or unit == "PB":
            return f"{int(value)} {unit}" if unit == "B" else f"{value:.2f} {unit}"
        value /= 1024
    return f"{value:.2f} PB"


def now_iso() -> str:
    return _dt.datetime.now().astimezone().isoformat(timespec="seconds")


def hash_file(path: Path, algorithm: str = "sha256") -> str:
    """Digest a file; returns '' when the algorithm is unavailable (e.g. FIPS)."""
    try:
        digest = hashlib.new(algorithm)
    except ValueError:
        return ""
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(4 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def shannon_entropy(path: Path, sample: int = 4 * 1024 * 1024) -> float:
    """Entropy of (up to) the first `sample` bytes — 0..8 bits/byte."""
    counts = [0] * 256
    total = 0
    with path.open("rb") as stream:
        data = stream.read(sample)
    total = len(data)
    if not total:
        return 0.0
    for byte in data:
        counts[byte] += 1
    entropy = 0.0
    for count in counts:
        if count:
            p = count / total
            entropy -= p * math.log2(p)
    return entropy


def detect_signature(head: bytes) -> str | None:
    for marker, label in SIGNATURES:
        if head.startswith(marker):
            return label
    if head[:4] == b"RIFF":
        return f"RIFF container ({head[8:12].decode('latin1', 'replace') or 'unknown'})"
    return None


def carrier_end(path: Path) -> tuple[int | None, str]:
    """Walk well-known containers to their real logical end (carver aware)."""
    size = path.stat().st_size
    with path.open("rb") as stream:
        head = stream.read(4096)
        if head[:8] == b"\x89PNG\r\n\x1a\n":
            offset = 8
            while offset + 8 <= size:
                stream.seek(offset)
                header = stream.read(8)
                if len(header) < 8:
                    break
                length = int.from_bytes(header[:4], "big")
                kind = header[4:8]
                end = offset + 12 + length
                if end > size:
                    return None, "truncated PNG chunk"
                if kind == b"IEND":
                    return end, "PNG IEND chunk"
                offset = end
            return None, "PNG without IEND"
        if head[:2] == b"\xff\xd8":
            stream.seek(max(0, size - 65536))
            tail = stream.read()
            marker = tail.rfind(b"\xff\xd9")
            if marker >= 0:
                return size - len(tail) + marker + 2, "JPEG EOI marker"
            return None, "JPEG without EOI"
        if head[:6] in (b"GIF87a", b"GIF89a"):
            stream.seek(max(0, size - 65536))
            tail = stream.read()
            marker = tail.rfind(b"\x3b")
            if marker >= 0:
                return size - len(tail) + marker + 1, "GIF trailer"
            return None, "GIF without trailer"
        if head[:5] == b"%PDF-":
            stream.seek(max(0, size - 131072))
            tail = stream.read()
            marker = tail.rfind(b"%%EOF")
            if marker >= 0:
                end = size - len(tail) + marker + 5
                while end < size:
                    stream.seek(end)
                    nxt = stream.read(1)
                    if nxt not in (b"\r", b"\n", b"\t", b" ", b""):
                        break
                    end += 1
                return end, "PDF %%EOF marker"
            return None, "PDF without %%EOF"
    return None, "no supported logical end"


def is_within(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except (ValueError, OSError):
        return False


def human_permissions(path: Path) -> str:
    try:
        return stat.filemode(os.lstat(path).st_mode)
    except OSError:
        return "?"


def tail_bytes(path: Path, count: int = 16) -> bytes:
    try:
        with path.open("rb") as stream:
            size = path.stat().st_size
            stream.seek(max(0, size - count))
            return stream.read(count)
    except OSError:
        return b""


# ══════════════════════════════════════════════════════════════════════════
#  Cryptography helpers (AES-256-CBC + HMAC-SHA256, PBKDF2)  — shared by
#  HideMe payload sealing and NbCorrupt file encryption.
# ══════════════════════════════════════════════════════════════════════════
PBKDF2_ITERATIONS = 210_000


def _require_crypto() -> None:
    if not HAVE_CRYPTO:
        raise RuntimeError("The 'cryptography' package is required for this operation. "
                           "Install it with: pip install cryptography")


def _derive_keys(password: str, salt: bytes) -> tuple[bytes, bytes]:
    _require_crypto()
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=64, salt=salt,
                     iterations=PBKDF2_ITERATIONS)
    material = kdf.derive(password.encode("utf-8"))
    return material[:32], material[32:]


def seal_bytes(plain: bytes, password: str | None) -> tuple[bytes, dict]:
    """Encrypt+sign `plain`. Returns (ciphertext, header fragment)."""
    if not password:
        return plain, {"cipher": "none"}
    _require_crypto()
    salt = os.urandom(16)
    iv = os.urandom(16)
    enc_key, mac_key = _derive_keys(password, salt)
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(plain) + padder.finalize()
    encryptor = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    tag = hmac.new(mac_key, salt + iv + ciphertext, hashlib.sha256).digest()
    fragment = {
        "cipher": "aes-256-cbc+hmac-sha256",
        "kdf": "pbkdf2-hmac-sha256",
        "iterations": PBKDF2_ITERATIONS,
        "salt": base64.b64encode(salt).decode(),
        "iv": base64.b64encode(iv).decode(),
        "hmac": base64.b64encode(tag).decode(),
    }
    return ciphertext, fragment


def open_bytes(blob: bytes, password: str | None, fragment: dict) -> bytes:
    """Inverse of seal_bytes; verifies the HMAC before decrypting."""
    cipher = fragment.get("cipher", "none")
    if cipher in ("none", None, ""):
        return blob
    _require_crypto()
    if cipher != "aes-256-cbc+hmac-sha256":
        raise RuntimeError(f"Unsupported payload cipher: {cipher}")
    salt = base64.b64decode(fragment["salt"])
    iv = base64.b64decode(fragment["iv"])
    expected = base64.b64decode(fragment["hmac"])
    enc_key, mac_key = _derive_keys(password or "", salt)
    tag = hmac.new(mac_key, salt + iv + blob, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected):
        raise RuntimeError("Payload authentication failed — wrong passphrase or tampered data.")
    decryptor = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(blob) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    try:
        return unpadder.update(padded) + unpadder.finalize()
    except ValueError as exc:
        raise RuntimeError(f"Payload decryption failed: {exc}") from exc


# ══════════════════════════════════════════════════════════════════════════
#  HideMe — file-in-file steganography container (works with ANY file pair)
# ══════════════════════════════════════════════════════════════════════════
NB_MAGIC = b"NBHIDE\x00\x01"      # appended-stream entry marker (8 bytes)
NB_TRAILER = b"NBEND\x00\x01\x00"  # entry terminator (8 bytes)
LSB_MAGIC = b"NBLSB\x00\x01"      # pixel LSB entry marker
NB_MAX_HEADER = 1 << 20


def build_nb_header(payload_name: str, payload_size: int, cipher_fragment: dict,
                    carrier: Path | None, comment: str, extra: dict | None = None) -> dict:
    header = {
        "format": "NbHide/1",
        "created": now_iso(),
        "payload_name": payload_name,
        "payload_size": payload_size,
        "carrier_name": carrier.name if carrier else None,
        "carrier_size": carrier.stat().st_size if carrier and carrier.exists() else None,
        "carrier_sha256": hash_file(carrier, "sha256") if carrier and carrier.exists() else None,
        "comment": comment or "",
    }
    header.update(cipher_fragment)
    if extra:
        header.update(extra)
    return header


def pack_nb_entry(payload: bytes, header: dict) -> bytes:
    raw = json.dumps(header, ensure_ascii=False).encode("utf-8")
    if len(raw) > NB_MAX_HEADER:
        raise RuntimeError("HideMe header is too large.")
    return NB_MAGIC + len(raw).to_bytes(4, "big") + raw + payload + NB_TRAILER


def nb_scan_bytes(data: bytes, magic: bytes = NB_MAGIC) -> list[dict]:
    """Locate every NbHide entry inside `data` (pure bytes, no file needed)."""
    entries: list[dict] = []
    cursor = 0
    while True:
        pos = data.find(magic, cursor)
        if pos < 0:
            break
        header_at = pos + len(magic)
        if header_at + 4 > len(data):
            break
        header_len = int.from_bytes(data[header_at:header_at + 4], "big")
        header_end = header_at + 4 + header_len
        if header_len > NB_MAX_HEADER or header_end > len(data):
            cursor = pos + len(magic)
            continue
        try:
            header = json.loads(data[header_at + 4:header_end].decode("utf-8"))
        except Exception:
            cursor = pos + len(magic)
            continue
        payload_start = header_end
        stored_size = header.get("payload_size")
        if header.get("cipher", "none") != "none":
            stored_size = header.get("cipher_size", stored_size)
        if not isinstance(stored_size, int):
            stored_size = 0
        payload_end = payload_start + stored_size
        trailer_ok = data[payload_end:payload_end + len(NB_TRAILER)] == NB_TRAILER
        entries.append({
            "offset": pos,
            "magic": magic,
            "header": header,
            "payload_start": payload_start,
            "payload_end": payload_end,
            "cipher_size": stored_size,
            "trailer_ok": trailer_ok,
            "file_size": len(data),
        })
        cursor = max(payload_end, pos + len(magic))
    return entries


SCAN_CHUNK = 32 * 1024 * 1024
LSB_MAX_BYTES = 512 * 1024 * 1024   # pixel scan reads the image whole


def nb_scan_file(path: Path) -> list[dict]:
    """Scan a container for appended HideMe entries (streaming) and pixel payloads."""
    entries: list[dict] = []
    size = path.stat().st_size
    overlap = NB_MAX_HEADER + len(NB_MAGIC) + 16
    base = 0
    buffer = b""
    with path.open("rb") as stream:
        while True:
            block = stream.read(SCAN_CHUNK)
            if not block:
                break
            buffer += block
            found = nb_scan_bytes(buffer, NB_MAGIC)
            complete = [item for item in found if item["payload_end"] <= len(buffer)]
            for item in complete:
                item["offset"] += base
                entries.append(item)
            keep_from = (max(item["payload_end"] for item in complete)
                         if complete else max(0, len(buffer) - overlap))
            buffer = buffer[keep_from:]
            base += keep_from
    if HAVE_PILLOW and size <= LSB_MAX_BYTES:
        try:
            entries.extend(nb_scan_lsb(path))
        except Exception:
            pass
    entries.sort(key=lambda item: item["offset"])
    return entries


def nb_extract_entry(container: Path, entry: dict, out_dir: Path,
                     password: str | None) -> tuple[Path, bytes]:
    header = entry["header"]
    size = entry["cipher_size"]
    with container.open("rb") as stream:
        stream.seek(entry["payload_start"])
        blob = stream.read(size)
    if len(blob) != size:
        raise RuntimeError("Payload is truncated inside the container.")
    plain = open_bytes(blob, password, header)
    name = str(header.get("payload_name") or "payload.bin")
    safe = re.sub(r"[^\w.\- ]+", "_", name) or "payload.bin"
    target = out_dir / safe
    counter = 1
    stem, suffix = target.stem, target.suffix
    while target.exists():
        target = out_dir / f"{stem}_{counter}{suffix}"
        counter += 1
    target.write_bytes(plain)
    return target, plain


def nb_embed_append(carrier: Path, payload: Path, out: Path, password: str | None,
                    comment: str) -> dict:
    """Append an encrypted payload to any carrier file (format agnostic)."""
    data = payload.read_bytes()
    sealed, fragment = seal_bytes(data, password)
    header = build_nb_header(payload.name, len(data), fragment, carrier, comment,
                             {"cipher_size": len(sealed), "mode": "append"})
    entry = pack_nb_entry(sealed, header)
    with carrier.open("rb") as src, out.open("wb") as dst:
        shutil.copyfileobj(src, dst, 4 * 1024 * 1024)
        dst.write(entry)
        dst.flush()
        os.fsync(dst.fileno())
    return {"header": header, "bytes_added": len(entry), "out": out}


# ── HideMe pixel (LSB) mode ────────────────────────────────────────────────
LSB_BITS = (1, 2, 4)   # divisors of 8 keep the packing exact and reversible


def lsb_normalise(image: "Image.Image") -> "Image.Image":
    """Force a mode whose channels we can address directly."""
    if image.mode in ("RGB", "RGBA", "L", "LA"):
        return image
    return image.convert("RGBA" if ("A" in image.mode or image.mode == "P") else "RGB")


def lsb_capacity(path: Path, bits: int) -> tuple[int, tuple[int, int], str]:
    """(payload bytes that fit, (width, height), mode) for a pixel carrier."""
    if not HAVE_PILLOW:
        raise RuntimeError("Pillow is required for pixel (LSB) mode: pip install pillow")
    with Image.open(path) as image:
        image = lsb_normalise(image)
        mode, size = image.mode, image.size
    carrier_bytes = size[0] * size[1] * len(mode)
    return (carrier_bytes * max(1, bits)) // 8, size, mode


_PACK_TABLES: dict[int, list[bytes]] = {}


def _pack_table(bits: int) -> list[bytes]:
    """Per-source-byte expansion table: 1 byte -> `per` carrier bytes."""
    table = _PACK_TABLES.get(bits)
    if table is None:
        per = 8 // bits
        mask = (1 << bits) - 1
        table = [bytes(((byte >> (8 - bits * (slot + 1))) & mask) for slot in range(per))
                 for byte in range(256)]
        _PACK_TABLES[bits] = table
    return table


def bit_pack(data: bytes, bits: int) -> bytes:
    """Split the payload bit stream into groups of `bits`, one group per carrier byte.

    Lossless: the 8 bits of each of `per = 8 // bits` source bytes fill one carrier
    byte, so every payload bit survives the round trip.
    """
    table = _pack_table(bits)
    per = 8 // bits
    packed = [table[byte] for byte in data]
    pad = (-len(data)) % per
    if pad:
        packed.append(b"\x00" * (pad * per))
    return b"".join(packed)


def bit_unpack(stream: bytes, bits: int, length: int) -> bytes:
    """Inverse of bit_pack — rebuild `length` payload bytes from the packed stream."""
    per = 8 // bits
    mask = (1 << bits) - 1
    out = bytearray(length)
    for index in range(length):
        base = index * per
        value = 0
        for slot in range(per):
            value |= (stream[base + slot] & mask) << (8 - bits * (slot + 1))
        out[index] = value
    return bytes(out)


_MASK_TABLES: dict[int, bytes] = {}


def lsb_pack_bytes(raw: bytes, bits: int) -> bytes:
    """Collect the low `bits` bits of every carrier byte into a packed byte stream."""
    table = _MASK_TABLES.get(bits)
    if table is None:
        mask = (1 << bits) - 1
        table = bytes(byte & mask for byte in range(256))
        _MASK_TABLES[bits] = table
    return raw.translate(table)


def lsb_embed(carrier: Path, payload: Path, out: Path, password: str | None,
              bits: int, comment: str) -> dict:
    """Write the payload into the low bits of the carrier's pixel bytes."""
    if not HAVE_PILLOW:
        raise RuntimeError("Pillow is required for pixel (LSB) mode: pip install pillow")
    if bits not in LSB_BITS:
        raise RuntimeError(f"Bit depth must be one of {LSB_BITS} (divisors of 8).")
    if out.suffix.lower() in (".jpg", ".jpeg"):
        raise RuntimeError("JPEG re-encoding destroys the low bit channel. "
                           "Use a PNG, BMP or TGA carrier for pixel mode.")
    plain = payload.read_bytes()
    sealed, fragment = seal_bytes(plain, password)
    header = build_nb_header(payload.name, len(plain), fragment, carrier, comment,
                             {"cipher_size": len(sealed), "mode": "pixel-lsb",
                              "bits_per_byte": bits})
    raw_header = json.dumps(header, ensure_ascii=False).encode("utf-8")
    blob = LSB_MAGIC + len(raw_header).to_bytes(4, "big") + raw_header + sealed
    if out.suffix.lower() == ".bmp":
        out = out.with_suffix(".png")
    with Image.open(carrier) as image:
        image = lsb_normalise(image)
        mode, size = image.mode, image.size
        original = image.tobytes()
    packed = bit_pack(blob, bits)
    if len(packed) > len(original):
        raise RuntimeError(
            f"Payload does not fit: needs {len(packed)} carrier bytes "
            f"({format_bytes(len(blob))} payload) but the carrier only holds "
            f"{len(original)} bytes at {bits} bit(s)/byte. Use append mode, a "
            f"larger carrier, or fewer bits.")
    keep = 0xFF ^ ((1 << bits) - 1)
    cleared = int.from_bytes(original, "big") & int.from_bytes(bytes([keep]) * len(original), "big")
    shift = (len(original) - len(packed)) * 8
    merged = cleared | (int.from_bytes(packed, "big") << shift)
    result = Image.frombytes(mode, size, merged.to_bytes(len(original), "big"))
    result.save(out)
    return {"header": header, "out": out, "capacity_bytes": len(original),
            "used_bytes": len(packed), "size": size, "mode": mode, "bits": bits}


def nb_scan_lsb(container: Path) -> list[dict]:
    """Detect and describe a pixel-mode entry inside an image file."""
    if not HAVE_PILLOW:
        return []
    try:
        with Image.open(container) as image:
            image = lsb_normalise(image)
            mode, size = image.mode, image.size
            raw = image.tobytes()
    except Exception:
        return []
    for bits in LSB_BITS:
        capacity = (len(raw) * bits) // 8
        stream = lsb_pack_bytes(raw, bits)
        prologue_len = len(LSB_MAGIC) + 4
        if capacity < prologue_len:
            continue
        prologue = bit_unpack(stream, bits, prologue_len)
        if prologue[:len(LSB_MAGIC)] != LSB_MAGIC:
            continue
        header_len = int.from_bytes(prologue[len(LSB_MAGIC):prologue_len], "big")
        if header_len > NB_MAX_HEADER:
            continue
        head_len = prologue_len + header_len
        if head_len + 8 > capacity:
            continue
        try:
            head = bit_unpack(stream, bits, head_len)
            header = json.loads(head[prologue_len:head_len].decode("utf-8"))
        except Exception:
            continue
        if not isinstance(header, dict) or header.get("format") != "NbHide/1":
            continue
        cipher_size = int(header.get("cipher_size") or 0)
        if head_len + cipher_size > capacity:
            continue
        return [{
            "offset": 0,
            "magic": LSB_MAGIC,
            "header": header,
            "payload_start": head_len,
            "payload_end": head_len + cipher_size,
            "cipher_size": cipher_size,
            "trailer_ok": True,
            "file_size": container.stat().st_size,
            "pixel_mode": True,
            "bits": bits,
            "image_mode": f"{mode} {size[0]}x{size[1]}",
        }]
    return []


def nb_extract_lsb(container: Path, entry: dict, out_dir: Path,
                   password: str | None) -> tuple[Path, bytes]:
    """Recover a pixel-mode payload and write it to `out_dir`."""
    if not HAVE_PILLOW:
        raise RuntimeError("Pillow is required to read pixel payloads.")
    bits = int(entry.get("bits", 2))
    if bits not in LSB_BITS:
        raise RuntimeError(f"Unsupported bit depth: {bits}")
    with Image.open(container) as image:
        image = lsb_normalise(image)
        raw = image.tobytes()
    stream = lsb_pack_bytes(raw, bits)
    head_len = entry["payload_start"]
    cipher_size = entry["cipher_size"]
    if head_len + cipher_size > (len(raw) * bits) // 8:
        raise RuntimeError("Pixel payload is truncated.")
    blob = bit_unpack(stream, bits, head_len + cipher_size)
    sealed = blob[head_len:head_len + cipher_size]
    plain = open_bytes(sealed, password, entry["header"])
    name = re.sub(r"[^\w.\- ]+", "_", str(entry["header"].get("payload_name") or "payload.bin"))
    target = out_dir / (name or "payload.bin")
    counter = 1
    while target.exists():
        target = out_dir / f"{target.stem}_{counter}{target.suffix}"
        counter += 1
    target.write_bytes(plain)
    return target, plain


# ══════════════════════════════════════════════════════════════════════════
#  Shr3dder — multi-pass secure overwrite
# ══════════════════════════════════════════════════════════════════════════
# Classic Gutmann sequence: 24 alternating 0x00/0xFF passes, then the fixed
# 11-pass tail (0x55/0xAA pairs ending on 0x55) = 35 passes total.
GUTMANN = tuple([0x00, 0xFF] * 12
                + [0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55])
assert len(GUTMANN) == 35, "Gutmann pass sequence must contain exactly 35 passes"

SHRED_PATTERNS = {
    "Zero fill (0x00)": "zero",
    "Ones fill (0xFF)": "ones",
    "Random data (cryptographic)": "random",
    "DoE / NIST 800-88 (0x00, 0xFF, random)": "doe",
    "Gutmann 35-pass": "gutmann",
    "Alternating 0xAA/0x55": "aa55",
    "Custom: N passes of one pattern": "custom",
}

CHUNK = 1024 * 1024


def shred_pass_plan(pattern: str, passes: int) -> list[dict]:
    """Expand a pattern selection into concrete per-pass instructions."""
    if pattern == "doe":
        return [{"kind": "zero"}, {"kind": "ones"}, {"kind": "random"}]
    if pattern == "gutmann":
        return [{"kind": "byte", "value": value} for value in GUTMANN]
    if pattern == "custom":
        if passes < 1:
            raise ValueError("Custom pass count must be at least 1.")
        return [{"kind": pattern}] * passes
    return [{"kind": pattern}]


def shred_file(path: Path, pattern: str, passes: int, unlink: bool,
               truncate: bool, progress: Callable[[int, int, str], None] | None = None,
               cancel: threading.Event | None = None,
               rng: random.Random | None = None) -> dict:
    """Overwrite `path` in place with `pattern`, then optionally unlink."""
    generator = rng or random.SystemRandom()
    plan = shred_pass_plan(pattern, passes)
    if path.is_symlink():
        raise RuntimeError("Refusing to shred a symlink target implicitly. "
                           "Select the link itself or resolve it explicitly.")
    size = path.stat().st_size
    total_written = 0
    started = time.time()
    with path.open("r+b", buffering=0) as handle:
        for index, step in enumerate(plan, start=1):
            if cancel and cancel.is_set():
                raise RuntimeError("Operation cancelled by user.")
            kind = step["kind"]
            label = f"Pass {index}/{len(plan)} · {kind}"
            handle.seek(0)
            remaining = size
            while remaining > 0:
                if cancel and cancel.is_set():
                    raise RuntimeError("Operation cancelled by user.")
                block = min(CHUNK, remaining)
                if kind == "zero":
                    data = b"\x00" * block
                elif kind == "ones":
                    data = b"\xff" * block
                elif kind == "aa55":
                    unit = b"\xaa\x55" * ((block + 1) // 2)
                    data = unit[:block]
                elif kind == "random":
                    data = os.urandom(block)
                elif kind == "byte":
                    data = bytes([step["value" & 0xFF]]) * block
                else:
                    data = os.urandom(block)
                handle.write(data)
                remaining -= block
                total_written += block
                if progress:
                    progress(index, len(plan), label)
            handle.flush()
            os.fsync(handle.fileno())
    if truncate:
        with path.open("r+b") as handle:
            handle.truncate(0)
            os.fsync(handle.fileno())
    if unlink:
        path.unlink()
    elapsed = time.time() - started
    return {
        "path": str(path),
        "size": size,
        "passes": len(plan),
        "bytes_written": total_written,
        "unlinked": unlink,
        "truncated": truncate,
        "seconds": round(elapsed, 2),
        "done_at": now_iso(),
    }


def shred_verify(path: Path, original_head: bytes) -> str:
    """Confirm the original leading bytes are gone (and optionally the file)."""
    if not path.exists():
        return "File no longer exists — unlink completed."
    head = path.read_bytes()[:len(original_head)] if path.stat().st_size else b""
    size = path.stat().st_size
    if size == 0:
        return "File is zero-length after shredding."
    if original_head and head == original_head:
        return "WARNING: original header bytes still present — storage stack may be caching/remapping."
    digest = hash_file(path, "sha256")
    return f"Post-shred SHA-256 {digest[:32]}… ({format_bytes(size)} remaining)."


# ══════════════════════════════════════════════════════════════════════════
#  NbCorrupt — damage / encrypt / truncate / overwrite
# ══════════════════════════════════════════════════════════════════════════
CORRUPT_MODES = (
    "Random byte corruption (percentage)",
    "Header wipe (first N bytes)",
    "Signature/magic destruction",
    "Truncate file (absolute or % size)",
    "Whole-file zero fill",
    "Whole-file pattern overwrite",
    "AES-256 encrypt (passphrase)",
    "AES-256 decrypt (recover NbCorrupt file)",
    "Symlink: break link (unlink)",
    "Symlink: repoint target",
    "Symlink: corrupt the target file",
)

NB_ENCRYPT_MAGIC = b"NBCENC\x00\x01"


def corrupt_random(src: Path, dst: Path, percent: float, seed: int | None = None,
                   progress: Callable[[int, int, str], None] | None = None) -> dict:
    rng = random.Random(seed) if seed is not None else random.SystemRandom()
    probability = max(0.0, min(100.0, percent)) / 100.0
    size = src.stat().st_size
    corrupted = 0
    with src.open("rb") as fin, dst.open("wb") as fout:
        while True:
            chunk = fin.read(CHUNK)
            if not chunk:
                break
            buffer = bytearray(chunk)
            for index, value in enumerate(buffer):
                if rng.random() < probability:
                    buffer[index] = value ^ rng.randint(1, 255)
                    corrupted += 1
            fout.write(buffer)
            if progress:
                progress(0, 0, "corrupting")
    fout_digest = hash_file(dst, "sha256")
    return {"mode": "random", "corrupted_bytes": corrupted, "percent": percent,
            "size": size, "out": str(dst), "sha256": fout_digest}


def corrupt_header(src: Path, dst: Path, count: int, fill: str = "random") -> dict:
    count = max(0, count)
    with src.open("rb") as fin, dst.open("wb") as fout:
        head = fin.read(count)
        if fill == "zero":
            replacement = b"\x00" * len(head)
        elif fill == "ff":
            replacement = b"\xff" * len(head)
        else:
            replacement = os.urandom(len(head))
        fout.write(replacement)
        shutil.copyfileobj(fin, fout, CHUNK)
    return {"mode": "header", "bytes_overwritten": len(head), "fill": fill, "out": str(dst),
            "sha256": hash_file(dst, "sha256")}


def corrupt_magic(src: Path, dst: Path) -> dict:
    head = src.read_bytes()[:64]
    label = detect_signature(head)
    length = 0
    for marker, _ in SIGNATURES:
        if head.startswith(marker):
            length = len(marker)
            break
    if not length:
        length = min(8, len(head))
    replacement = os.urandom(length)
    with src.open("rb") as fin, dst.open("wb") as fout:
        original = fin.read(length)
        fout.write(replacement)
        shutil.copyfileobj(fin, fout, CHUNK)
    return {"mode": "magic", "identified_as": label or "unknown", "bytes_overwritten": length,
            "original": original.hex(), "replacement": replacement.hex(), "out": str(dst),
            "sha256": hash_file(dst, "sha256")}


def corrupt_truncate(src: Path, dst: Path, size: int) -> dict:
    original = src.stat().st_size
    with src.open("rb") as fin, dst.open("wb") as fout:
        written = 0
        while written < size:
            chunk = fin.read(min(CHUNK, size - written))
            if not chunk:
                break
            fout.write(chunk)
            written += len(chunk)
    return {"mode": "truncate", "original_size": original, "new_size": dst.stat().st_size,
            "out": str(dst), "sha256": hash_file(dst, "sha256")}


def corrupt_fill(src: Path, dst: Path, kind: str) -> dict:
    size = src.stat().st_size
    with dst.open("wb") as fout:
        remaining = size
        while remaining > 0:
            block = min(CHUNK, remaining)
            if kind == "zero":
                data = b"\x00" * block
            elif kind == "ff":
                data = b"\xff" * block
            else:
                data = os.urandom(block)
            fout.write(data)
            remaining -= block
    return {"mode": "fill", "fill": kind, "size": size, "out": str(dst),
            "sha256": hash_file(dst, "sha256")}


def corrupt_encrypt(src: Path, dst: Path, password: str) -> dict:
    plain = src.read_bytes()
    sealed, fragment = seal_bytes(plain, password)
    manifest = {"format": "NbCorrupt/1", "created": now_iso(),
                "source_name": src.name, "source_size": len(plain),
                "source_sha256": hashlib.sha256(plain).hexdigest(), **fragment}
    raw = json.dumps(manifest, ensure_ascii=False).encode("utf-8")
    payload = (NB_ENCRYPT_MAGIC + len(raw).to_bytes(4, "big") + raw + sealed)
    dst.write_bytes(payload)
    return {"mode": "encrypt", "out": str(dst), "container": manifest["cipher"],
            "bytes_written": len(payload), "sha256": hash_file(dst, "sha256")}


def corrupt_decrypt(src: Path, dst: Path, password: str) -> dict:
    data = src.read_bytes()
    if not data.startswith(NB_ENCRYPT_MAGIC):
        raise RuntimeError("Not an NbCorrupt container (missing NBCENC magic).")
    header_len = int.from_bytes(data[len(NB_ENCRYPT_MAGIC):len(NB_ENCRYPT_MAGIC) + 4], "big")
    start = len(NB_ENCRYPT_MAGIC) + 4
    manifest = json.loads(data[start:start + header_len].decode("utf-8"))
    blob = data[start + header_len:]
    plain = open_bytes(blob, password, manifest)
    dst.write_bytes(plain)
    return {"mode": "decrypt", "out": str(dst), "recovered_size": len(plain),
            "source_sha256": manifest.get("source_sha256"),
            "verified": hashlib.sha256(plain).hexdigest() == manifest.get("source_sha256")}


# ExifTool prints one tag per line, separating tag from value with two spaces or
# with " : " when the tag carries a print conversion. Tags are prefixed with the
# group in square brackets under -G (or curly braces when the group is ambiguous).
EXIFTOOL_LINE = re.compile(
    r"^(?:\[(?P<braced>[^\]]+)\]|\{(?P<curly>[^\}]+)\})?\s*"
    r"(?P<tag>\S+?)"
    r"(?:\s+:\s|\s\s+)"
    r"(?P<value>.*)$"
)


def parse_exiftool_line(line: str) -> tuple[str, str, str] | None:
    """Return (short_tag, value, group) for an ExifTool output line, else None."""
    match = EXIFTOOL_LINE.match(line)
    if not match:
        return None
    tag = match.group("tag").strip()
    if not tag or " " in tag:
        return None
    group = match.group("braced") or match.group("curly") or ""
    return tag, match.group("value"), group


def render_metadata_value(value: object) -> str:
    """Flatten a JSON metadata value into a single readable cell."""
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)


# ══════════════════════════════════════════════════════════════════════════
#  GUI
# ══════════════════════════════════════════════════════════════════════════
class ForensicsBench:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(f"Nbte7m · {APP_NAME}")
        self.root.geometry("1420x900")
        self.root.minsize(1040, 700)
        self.root.configure(bg=BG)

        # session state
        self.selected_path: Path | None = None
        self.metadata_rows: list[tuple[str, str]] = []
        self.metadata_json: list[dict] | None = None
        self.pages: dict[str, ttk.Frame] = {}
        self.nav_buttons: dict[str, tk.Button] = {}
        self.case_log: list[tuple[str, str]] = []
        self.shred_targets: list[Path] = []
        self.corrupt_target: Path | None = None
        self.corrupt_outputs: list[Path] = []
        self.hide_entries: list[dict] = []
        self.busy = False
        self._queue: queue.Queue = queue.Queue()

        # HideMe state
        self.hide_carrier: Path | None = None
        self.hide_payload: Path | None = None

        # MetaDelete state
        self.md_target: Path | None = None
        self.md_groups = tk.StringVar(value="all metadata (every group)")
        self.md_erase_appended = tk.BooleanVar(value=False)
        self.md_reset_times = tk.BooleanVar(value=False)
        self.md_inplace = tk.BooleanVar(value=False)
        self.md_sidecar: Path | None = None
        self._repoint_entry: tk.Entry | None = None

        # Shr3dder state
        self.shred_pattern = tk.StringVar(value="DoE / NIST 800-88 (0x00, 0xFF, random)")
        self.shred_passes = tk.IntVar(value=3)
        self.shred_unlink = tk.BooleanVar(value=True)
        self.shred_truncate = tk.BooleanVar(value=False)
        self.shred_verify = tk.BooleanVar(value=True)
        self.shred_follow_links = tk.BooleanVar(value=False)
        self._shred_cancel = threading.Event()
        self._shred_running = False

        # NbCorrupt state
        self.corrupt_mode = tk.StringVar(value=CORRUPT_MODES[0])
        self.corrupt_percent = tk.DoubleVar(value=10.0)
        self.corrupt_header_bytes = tk.IntVar(value=1024)
        self.corrupt_fill = tk.StringVar(value="random")
        self.corrupt_trunc_size = tk.IntVar(value=1024)
        self.corrupt_trunc_unit = tk.StringVar(value="bytes")
        self.corrupt_overwrite_byte = tk.StringVar(value="0x00")
        self.corrupt_passphrase = tk.StringVar(value="")
        self.corrupt_inplace = tk.BooleanVar(value=False)

        # HideMe state
        self.hide_mode = tk.StringVar(value="append")
        self.hide_passphrase = tk.StringVar(value="")
        self.hide_bits = tk.IntVar(value=2)
        self.hide_comment = tk.StringVar(value="")
        self.hide_overwrite = tk.BooleanVar(value=False)

        # NbExif state
        self.exif_filter = tk.StringVar(value="")
        self.exif_group_filter = tk.StringVar(value="All groups")
        self.exif_deep = tk.BooleanVar(value=True)
        self.exif_mode = tk.StringVar(value="Everything (all groups, duplicates, binary)")

        self._configure_styles()
        self._build_shell()
        self._build_pages()
        self.show_page("exif")
        self._refresh_target_states()
        self.root.after(80, self._drain_queue)

    # ── styling ────────────────────────────────────────────────────────────
    def _configure_styles(self) -> None:
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("TFrame", background=BG)
        style.configure("Surface.TFrame", background=SURFACE)
        style.configure("TLabel", background=BG, foreground=TEXT, font=FONT)
        style.configure("Muted.TLabel", background=BG, foreground=MUTED, font=FONT_SM)
        style.configure("Surface.TLabel", background=SURFACE, foreground=TEXT, font=FONT)
        style.configure("SurfaceMuted.TLabel", background=SURFACE, foreground=MUTED, font=FONT_SM)
        style.configure("Title.TLabel", background=BG, foreground=TEXT,
                        font=("Georgia", 25, "bold"))
        style.configure("Eyebrow.TLabel", background=BG, foreground=ACCENT,
                        font=("Segoe UI", 8, "bold"))
        style.configure("PanelTitle.TLabel", background=SURFACE, foreground=TEXT,
                        font=("Segoe UI", 10, "bold"))
        style.configure("Treeview", background=SURFACE_2, foreground=TEXT,
                        fieldbackground=SURFACE_2, rowheight=24, bordercolor=LINE,
                        font=MONO, borderwidth=0)
        style.configure("Treeview.Heading", background="#14283c", foreground="#c3d6e8",
                        font=("Segoe UI", 9, "bold"), relief="flat")
        style.map("Treeview", background=[("selected", "#1a4d63")],
                  foreground=[("selected", "#ffffff")])
        style.configure("Vertical.TScrollbar", background="#1b3046", troughcolor=BG,
                        bordercolor=BG, arrowcolor=MUTED, borderwidth=0)
        style.configure("Horizontal.TScrollbar", background="#1b3046", troughcolor=BG,
                        bordercolor=BG, arrowcolor=MUTED, borderwidth=0)
        style.configure("TProgressbar", background=ACCENT, troughcolor=SURFACE_2,
                        bordercolor=LINE, lightcolor=ACCENT, darkcolor=ACCENT)
        style.configure("TNotebook", background=BG, bordercolor=LINE)
        style.configure("TCombobox", fieldbackground=FIELD, background=FIELD,
                        foreground=TEXT, arrowcolor=MUTED, bordercolor=LINE,
                        selectbackground=FIELD, selectforeground=TEXT)
        style.map("TCombobox", fieldbackground=[("readonly", FIELD)],
                  foreground=[("readonly", TEXT)])

    # ── reusable widgets ───────────────────────────────────────────────────
    def btn(self, parent: tk.Misc, text: str, command: Callable[[], None],
            kind: str = "default", width: int | None = None) -> tk.Button:
        palette = {
            "default": ("#13253a", TEXT, "#1d3a58"),
            "primary": (ACCENT, ACCENT_DARK, ACCENT),
            "danger": (DANGER_BG, DANGER, DANGER_EDGE),
            "warn": (WARN_BG, WARNING, WARN_EDGE),
            "ghost": (SURFACE, MUTED, LINE),
        }
        bg, fg, active = palette.get(kind, palette["default"])
        return tk.Button(parent, text=text, command=command, bg=bg, fg=fg,
                         activebackground=active, activeforeground=fg,
                         disabledforeground=DIM, relief="flat", bd=0, padx=14, pady=8,
                         font=("Segoe UI", 9, "bold"), cursor="hand2",
                         highlightthickness=0, takefocus=True, width=width)

    def entry(self, parent: tk.Misc, variable: tk.Variable | None = None,
              width: int = 32, show: str | None = None) -> tk.Entry:
        widget = tk.Entry(parent, width=width, bg=FIELD, fg=TEXT,
                          insertbackground=TEXT, relief="flat", font=MONO,
                          highlightthickness=1, highlightbackground=LINE,
                          highlightcolor=ACCENT, show=show, insertwidth=2)
        if variable is not None:
            widget.configure(textvariable=variable)
        return widget

    def combo(self, parent: tk.Misc, variable: tk.Variable, values: Iterable[str],
              width: int = 30) -> ttk.Combobox:
        widget = ttk.Combobox(parent, textvariable=variable, values=list(values),
                              state="readonly", width=width, font=FONT_SM)
        return widget

    def check(self, parent: tk.Misc, text: str, variable: tk.Variable) -> tk.Checkbutton:
        return tk.Checkbutton(parent, text=text, variable=variable, bg=SURFACE,
                              fg=TEXT, activebackground=SURFACE, activeforeground=ACCENT,
                              selectcolor=FIELD, font=FONT_SM, anchor="w",
                              highlightthickness=0, bd=0)

    def radio(self, parent: tk.Misc, text: str, value: str,
              variable: tk.Variable) -> tk.Radiobutton:
        return tk.Radiobutton(parent, text=text, value=value, variable=variable,
                              bg=SURFACE, fg=TEXT, activebackground=SURFACE,
                              activeforeground=ACCENT, selectcolor=FIELD,
                              font=FONT_SM, anchor="w", highlightthickness=0, bd=0)

    def _heading(self, parent: tk.Misc, section: str, title: str, description: str) -> None:
        head = tk.Frame(parent, bg=BG)
        head.pack(fill="x", pady=(0, 16))
        tk.Label(head, text=section.upper(), bg=BG, fg=ACCENT,
                 font=("Segoe UI", 8, "bold")).pack(anchor="w", pady=(0, 6))
        tk.Label(head, text=title, bg=BG, fg=TEXT, font=("Georgia", 24)).pack(anchor="w")
        tk.Label(head, text=description, bg=BG, fg=MUTED, font=FONT_SM,
                 wraplength=920, justify="left").pack(anchor="w", pady=(6, 0))

    def _panel(self, parent: tk.Misc, title: str, kicker: str = "",
               expand: bool = True) -> tuple[tk.Frame, tk.Frame]:
        outer = tk.Frame(parent, bg=SURFACE, highlightbackground=LINE, highlightthickness=1)
        outer.pack(fill="both" if expand else "x", expand=expand, pady=(0, 12))
        header = tk.Frame(outer, bg=SURFACE, height=40)
        header.pack(fill="x", padx=14)
        header.pack_propagate(False)
        tk.Label(header, text=title, bg=SURFACE, fg=TEXT,
                 font=("Segoe UI", 10, "bold")).pack(side="left", anchor="w")
        if kicker:
            tk.Label(header, text=kicker.upper(), bg=SURFACE, fg=DIM,
                     font=MONO_SM).pack(side="right", anchor="e")
        tk.Frame(outer, bg=LINE, height=1).pack(fill="x")
        body = tk.Frame(outer, bg=SURFACE, padx=14, pady=12)
        body.pack(fill="both", expand=True)
        return outer, body

    def _notice(self, parent: tk.Misc, title: str, body: str, kind: str = "info") -> None:
        scheme = {
            "info": (OK_BG, OK_EDGE, "#d4f4eb", OK_TEXT),
            "warn": (WARN_BG, WARN_EDGE, "#ffd0aa", "#e6bca7"),
            "danger": (DANGER_BG, DANGER_EDGE, "#ffc0c3", "#e7b3b7"),
        }[kind]
        box = tk.Frame(parent, bg=scheme[0], highlightbackground=scheme[1],
                       highlightthickness=1)
        box.pack(fill="x", pady=(0, 11))
        tk.Label(box, text=title, bg=scheme[0], fg=scheme[2],
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=11, pady=(8, 2))
        tk.Label(box, text=body, bg=scheme[0], fg=scheme[3], justify="left",
                 wraplength=880, font=FONT_XS).pack(anchor="w", padx=11, pady=(0, 9))

    def _row(self, parent: tk.Misc) -> tk.Frame:
        row = tk.Frame(parent, bg=SURFACE)
        row.pack(fill="x", pady=(4, 2))
        return row

    def _status(self, parent: tk.Misc, variable: tk.StringVar) -> tk.Label:
        label = tk.Label(parent, textvariable=variable, bg=SURFACE, fg=MUTED, anchor="w",
                         justify="left", wraplength=900, font=FONT_XS)
        label.pack(fill="x", pady=(8, 0))
        return label

    def _field(self, parent: tk.Misc, label: str, variable: tk.Variable,
               widget: tk.Misc) -> None:
        """Label + widget on one line (caller packs the row)."""
        tk.Label(parent, text=label, bg=SURFACE, fg=MUTED, font=FONT_SM,
                 width=22, anchor="w").pack(side="left")
        widget.pack(side="left", fill="x", expand=True, padx=(0, 8))

    def _console(self, parent: tk.Misc, height: int = 8) -> tk.Text:
        holder = tk.Frame(parent, bg=SURFACE)
        holder.pack(fill="both", expand=True, pady=(8, 0))
        text = tk.Text(holder, height=height, bg=SURFACE_2, fg="#cfe0f2",
                       insertbackground=TEXT, relief="flat", font=MONO_SM, wrap="word",
                       padx=10, pady=8, highlightthickness=1, highlightbackground=LINE)
        bar = ttk.Scrollbar(holder, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=bar.set)
        text.pack(side="left", fill="both", expand=True)
        bar.pack(side="right", fill="y")
        text.configure(state="disabled")
        text.tag_configure("warn", foreground=WARNING)
        text.tag_configure("danger", foreground=DANGER)
        text.tag_configure("ok", foreground=ACCENT)
        text.tag_configure("head", foreground="#ffffff", font=("Consolas", 8, "bold"))
        return text

    def _tree(self, parent: tk.Misc, columns: tuple[str, ...], headings: tuple[str, ...],
              widths: tuple[int, ...], height: int = 14,
              stretch: tuple[bool, ...] | None = None) -> ttk.Treeview:
        holder = tk.Frame(parent, bg=SURFACE)
        holder.pack(fill="both", expand=True)
        tree = ttk.Treeview(holder, columns=columns, show="headings", height=height,
                            selectmode="browse")
        if stretch is None:
            stretch = tuple(index == len(columns) - 1 for index in range(len(columns)))
        for column, heading, width, grows in zip(columns, headings, widths, stretch):
            tree.heading(column, text=heading)
            tree.column(column, width=width, minwidth=60, stretch=grows)
        ybar = ttk.Scrollbar(holder, orient="vertical", command=tree.yview)
        xbar = ttk.Scrollbar(holder, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=ybar.set, xscrollcommand=xbar.set)
        tree.grid(row=0, column=0, sticky="nsew")
        ybar.grid(row=0, column=1, sticky="ns")
        xbar.grid(row=1, column=0, sticky="ew")
        holder.grid_rowconfigure(0, weight=1)
        holder.grid_columnconfigure(0, weight=1)
        tree.tag_configure("dup", foreground=WARNING)
        tree.tag_configure("gps", foreground="#8fd4ff")
        return tree

    # ── shell ──────────────────────────────────────────────────────────────
    def _build_shell(self) -> None:
        self.shell = tk.Frame(self.root, bg=BG)
        self.shell.pack(fill="both", expand=True)

        self.rail = tk.Frame(self.shell, bg=RAIL, width=240,
                             highlightbackground=LINE, highlightthickness=1)
        self.rail.pack(side="left", fill="y")
        self.rail.pack_propagate(False)

        brand = tk.Frame(self.rail, bg=RAIL)
        brand.pack(fill="x", padx=18, pady=(22, 26))
        mark = tk.Label(brand, text="NB", bg="#153653", fg=ACCENT, width=4, height=2,
                        font=("Consolas", 10, "bold"))
        mark.pack(side="left", padx=(0, 10))
        names = tk.Frame(brand, bg=RAIL)
        names.pack(side="left")
        tk.Label(names, text="Nbte7m", bg=RAIL, fg=TEXT,
                 font=("Segoe UI", 14, "bold")).pack(anchor="w")
        tk.Label(names, text="FORENSICS BENCH", bg=RAIL, fg=MUTED,
                 font=("Segoe UI", 7, "bold")).pack(anchor="w")

        tk.Label(self.rail, text="ANALYSIS TOOLS", bg=RAIL, fg=DIM,
                 font=("Segoe UI", 8, "bold")).pack(anchor="w", padx=18, pady=(0, 8))
        for key, label, icon in NAV_ITEMS:
            button = tk.Button(self.rail, text=f"  {icon}    {label}", anchor="w", bg=RAIL,
                               fg="#a8b8ca", activebackground="#14283c",
                               activeforeground=TEXT, relief="flat", bd=0, padx=17,
                               pady=10, font=("Segoe UI", 10), cursor="hand2",
                               highlightthickness=0,
                               command=lambda k=key: self.show_page(k))
            button.pack(fill="x", padx=9, pady=2)
            self.nav_buttons[key] = button

        self.rail_bottom = tk.Frame(self.rail, bg="#0c1a2b", highlightbackground=LINE,
                                    highlightthickness=1)
        self.rail_bottom.pack(side="bottom", fill="x", padx=12, pady=14)
        tk.Label(self.rail_bottom, text="●  LOCAL ENGINE", bg="#0c1a2b", fg=ACCENT,
                 font=("Segoe UI", 8, "bold")).pack(anchor="w", padx=12, pady=(10, 3))
        self.env_label = tk.Label(self.rail_bottom, text="", bg="#0c1a2b", fg=MUTED,
                                  justify="left", font=FONT_XS, wraplength=190)
        self.env_label.pack(anchor="w", padx=12, pady=(0, 10))
        self._refresh_env_label()

        self.main = tk.Frame(self.shell, bg=BG)
        self.main.pack(side="left", fill="both", expand=True)

        self.topbar = tk.Frame(self.main, bg=BG, height=58, highlightbackground=LINE,
                               highlightthickness=1)
        self.topbar.pack(fill="x")
        self.topbar.pack_propagate(False)
        self.breadcrumb = tk.Label(self.topbar, text="Workbench  /  NbExif", bg=BG,
                                   fg=MUTED, font=FONT_SM)
        self.breadcrumb.pack(side="left", padx=24)
        self.btn(self.topbar, "Save activity log…", self.save_case_log,
                 "ghost").pack(side="right", padx=(6, 14), pady=11)
        self.btn(self.topbar, "Clear session", self.clear_session,
                 "ghost").pack(side="right", padx=6, pady=11)
        self.btn(self.topbar, "Choose evidence file", self.choose_file,
                 "primary").pack(side="right", pady=11)

        self.content = tk.Frame(self.main, bg=BG)
        self.content.pack(fill="both", expand=True)

        self.file_status = tk.StringVar(value="No evidence file selected")
        self.statusbar = tk.Label(self.main, textvariable=self.file_status, bg="#091624",
                                  fg=MUTED, anchor="w", padx=16, pady=7, font=FONT_XS)
        self.statusbar.pack(fill="x", side="bottom")

    def _refresh_env_label(self) -> None:
        lines = [f"ExifTool: {exiftool_version()}",
                 f"crypto: {'ready' if HAVE_CRYPTO else 'MISSING'}",
                 f"pillow: {'ready' if HAVE_PILLOW else 'MISSING'}",
                 "Destructive tools operate on a copy unless you explicitly confirm in-place."]
        self.env_label.configure(text="\n".join(lines))

    def _build_pages(self) -> None:
        self._build_exif_page()
        self._build_corrupt_page()
        self._build_delete_page()
        self._build_shred_page()
        self._build_hide_page()

    def _page(self, key: str) -> ttk.Frame:
        frame = ttk.Frame(self.content, padding=(24, 20, 24, 10))
        self.pages[key] = frame
        return frame

    # ── page 1: NbExif ─────────────────────────────────────────────────────
    def _build_exif_page(self) -> None:
        page = self._page("exif")
        self._heading(page, "Evidence intake / 01", "NbExif",
                      "Reads every metadata tag ExifTool can reach — all groups, duplicates, "
                      "binary blocks, IPTC/XMP/GPS/MAKER, unknown tags, embedded thumbnails — "
                      "for any format ExifTool supports.")

        _, body = self._panel(page, "Evidence file", "ExifTool driver")
        self.file_summary = tk.StringVar(value="Choose an evidence file to inspect.")
        tk.Label(body, textvariable=self.file_summary, bg=SURFACE, fg=MUTED, anchor="w",
                 font=MONO_SM, wraplength=900).pack(fill="x")

        row = self._row(body)
        tk.Label(row, text="Extraction profile", bg=SURFACE, fg=MUTED, font=FONT_SM,
                 width=22, anchor="w").pack(side="left")
        self.combo(row, self.exif_mode, (
            "Everything (all groups, duplicates, binary)",
            "Deep (adds embedded files + RequestAll)",
            "EXIF only", "GPS only", "IPTC only", "XMP only",
            "Composite/File system info", "Quick — no duplicates"),
            width=44).pack(side="left", fill="x", expand=True)

        row = self._row(body)
        self.btn(row, "Extract ALL metadata", self.extract_metadata,
                 "primary").pack(side="left")
        self.btn(row, "Export JSON…", lambda: self.export_metadata("json")).pack(side="left", padx=7)
        self.btn(row, "Export XML…", lambda: self.export_metadata("xml")).pack(side="left")
        self.btn(row, "Export CSV…", lambda: self.export_metadata("csv")).pack(side="left", padx=7)
        self.btn(row, "Export selected binary block…",
                 self.export_binary_tag, "ghost").pack(side="left")

        self.exif_status = tk.StringVar(value="Select a file, then extract. ExifTool coverage "
                                              "varies by format; unknown tags are included.")
        self._status(body, self.exif_status)

        filter_row = tk.Frame(body, bg=SURFACE)
        filter_row.pack(fill="x", pady=(10, 4))
        tk.Label(filter_row, text="Filter", bg=SURFACE, fg=MUTED, font=FONT_SM,
                 width=22, anchor="w").pack(side="left")
        self.entry(filter_row, self.exif_filter, width=34).pack(side="left")
        self.exif_group_combo = self.combo(filter_row, self.exif_group_filter,
                                           ["All groups"] + list(GROUP_MENU), width=22)
        self.exif_group_combo.pack(side="left", padx=8)
        self.check(filter_row, "deep (-ee)", self.exif_deep).pack(side="left", padx=6)

        _, result = self._panel(page, "Extracted metadata", "tag/group → value")
        self.metadata_tree = self._tree(result, ("tag", "value", "note"),
                                        ("TAG / GROUP", "VALUE", ""),
                                        (300, 760, 70), height=17,
                                        stretch=(False, True, False))
        self.metadata_tree.bind("<Double-1>", self._copy_selection)
        self.metadata_tree.bind("<Button-3>", self._popup_tag_menu)

        _, side = self._panel(page, "Technical summary", "independent of ExifTool", expand=False)
        self.tech_summary = tk.StringVar(value="No file inspected yet.")
        tk.Label(side, textvariable=self.tech_summary, bg=SURFACE, fg="#b9cde1",
                 anchor="w", justify="left", font=MONO_SM, wraplength=900).pack(fill="x")

    # ── page 2: NbCorrupt ──────────────────────────────────────────────────
    def _build_corrupt_page(self) -> None:
        page = self._page("corrupt")
        self._heading(page, "Damage simulation / 02", "NbCorrupt",
                      "Damages, encrypts, truncates or overwrites any file type — and breaks, "
                      "repoints or corrupts the target of a symbolic link. Every action is "
                      "logged with before/after hashes for the case file.")

        top = tk.Frame(page, bg=BG)
        top.pack(fill="x")
        left, right = tk.Frame(top, bg=BG), tk.Frame(top, bg=BG)
        left.pack(side="left", fill="both", expand=True, padx=(0, 7))
        right.pack(side="left", fill="both", expand=True, padx=(7, 0))

        _, body = self._panel(left, "Target", "file or symlink")
        self.corrupt_target_label = tk.StringVar(value="No target selected.")
        tk.Label(body, textvariable=self.corrupt_target_label, bg=SURFACE, fg=MUTED,
                 anchor="w", font=MONO_SM, wraplength=600).pack(fill="x")
        row = self._row(body)
        self.btn(row, "Choose target…", self.choose_corrupt_target,
                 "default").pack(side="left")
        self.btn(row, "Inspect target", self.inspect_corrupt_target,
                 "ghost").pack(side="left", padx=7)
        self.corrupt_intro = tk.StringVar(value="")
        self._status(body, self.corrupt_intro)

        _, ops = self._panel(left, "Operation", "NbCorrupt", expand=False)
        self.combo(ops, self.corrupt_mode, CORRUPT_MODES, width=44).pack(anchor="w")

        opt = tk.Frame(ops, bg=SURFACE)
        opt.pack(fill="x", pady=(9, 4))
        tk.Label(opt, text="Percent of bytes", bg=SURFACE, fg=MUTED, font=FONT_SM,
                 width=22, anchor="w").pack(side="left")
        self.entry(opt, self.corrupt_percent, width=10).pack(side="left")
        tk.Label(opt, text="bytes", bg=SURFACE, fg=MUTED, font=FONT_SM,
                 width=22, anchor="w").pack(side="left", padx=(22, 0))
        self.entry(opt, self.corrupt_header_bytes, width=10).pack(side="left")
        tk.Label(opt, text="truncate", bg=SURFACE, fg=MUTED, font=FONT_SM,
                 width=22, anchor="w").pack(side="left", padx=(22, 0))
        self.entry(opt, self.corrupt_trunc_size, width=10).pack(side="left")
        self.combo(opt, self.corrupt_trunc_unit, ("bytes", "percent"), width=10).pack(side="left", padx=4)

        opt2 = tk.Frame(ops, bg=SURFACE)
        opt2.pack(fill="x", pady=4)
        tk.Label(opt2, text="fill / overwrite byte", bg=SURFACE, fg=MUTED, font=FONT_SM,
                 width=22, anchor="w").pack(side="left")
        self.combo(opt2, self.corrupt_fill, ("random", "zero", "ff"), width=10).pack(side="left")
        self.entry(opt2, self.corrupt_overwrite_byte, width=10).pack(side="left", padx=4)
        tk.Label(opt2, text="passphrase (AES)", bg=SURFACE, fg=MUTED, font=FONT_SM,
                 width=20, anchor="w").pack(side="left", padx=(22, 0))
        self.entry(opt2, self.corrupt_passphrase, width=22, show="•").pack(side="left")

        opt3 = tk.Frame(ops, bg=SURFACE)
        opt3.pack(fill="x", pady=6)
        self.check(opt3, "Operate in place (destructive)", self.corrupt_inplace).pack(side="left")
        tk.Label(opt3, text="symlink re-point target:", bg=SURFACE, fg=MUTED, font=FONT_SM
                 ).pack(side="left", padx=(22, 6))
        self._repoint_entry = self.entry(opt3, None, width=26)
        self._repoint_entry.pack(side="left")

        row = self._row(ops)
        self.btn(row, "Run NbCorrupt", self.run_corrupt, "danger").pack(side="left")
        self.btn(row, "Clean up outputs", self.cleanup_outputs, "ghost").pack(side="left", padx=7)
        self.corrupt_status = tk.StringVar(value="Select a target. Default output is a new file; "
                                                "in-place mode asks for typed confirmation.")
        self._status(ops, self.corrupt_status)

        _, logpanel = self._panel(right, "Activity log", "case trail", expand=True)
        self.corrupt_log = self._console(logpanel, height=18)

        _, ref = self._panel(right, "Corruption reference", "for examiners", expand=False)
        text = ("Random  — flip bits across the file; simulates transport/media decay.\n"
                "Header  — obliterate the first bytes; structure parsers fail immediately.\n"
                "Magic   — replace the file signature so type detection misidentifies it.\n"
                "Truncate— remove the tail; salvage/carving tools lose the tail segment.\n"
                "AES     — CBC + HMAC-SHA256, PBKDF2-SHA256 210k iterations, self-describing\n"
                "          container so an examiner can prove recovery of the plaintext.\n"
                "Symlink — break, repoint, or damage the resolved target.")
        tk.Label(ref, text=text, bg=SURFACE, fg=MUTED, justify="left", anchor="w",
                 font=MONO_SM).pack(fill="x")

    # ── page 3: MetaDelete ─────────────────────────────────────────────────
    def _build_delete_page(self) -> None:
        page = self._page("delete")
        self._heading(page, "Privacy handling / 03", "MetaDelete",
                      "Removes metadata from any format, wipes selected tag groups only, "
                      "erases appended/carver data and timestamps — and reproduces a full "
                      "metadata profile from a saved sidecar or a typed template.")

        top = tk.Frame(page, bg=BG)
        top.pack(fill="x")
        left, right = tk.Frame(top, bg=BG), tk.Frame(top, bg=BG)
        left.pack(side="left", fill="both", expand=True, padx=(0, 7))
        right.pack(side="left", fill="both", expand=True, padx=(7, 0))

        _, body = self._panel(left, "Target file", "ExifTool writer")
        self.md_target_label = tk.StringVar(value="No target selected.")
        tk.Label(body, textvariable=self.md_target_label, bg=SURFACE, fg=MUTED, anchor="w",
                 font=MONO_SM, wraplength=600).pack(fill="x")
        row = self._row(body)
        self.btn(row, "Choose target…", self.choose_md_target, "default").pack(side="left")
        self.btn(row, "Use evidence file", self.use_evidence_for_md,
                 "ghost").pack(side="left", padx=7)

        _, wipe = self._panel(left, "Wipe scope", "output copy by default")
        self.combo(wipe, self.md_groups, ("all metadata (every group)",) + GROUP_MENU,
                   width=40).pack(anchor="w")
        self.md_extra = tk.StringVar(value="")
        row = self._row(wipe)
        self.check(row, "Erase appended data after container end (anti-carve)",
                   self.md_erase_appended).pack(side="left")
        self.check(row, "Reset mtime/atime", self.md_reset_times).pack(side="left", padx=12)
        self.check(row, "In place", self.md_inplace).pack(side="left")
        row = self._row(wipe)
        self.btn(row, "Wipe metadata → new copy", self.md_wipe, "primary").pack(side="left")
        self.btn(row, "Batch folder…", self.md_batch, "default").pack(side="left", padx=7)
        self.md_status = tk.StringVar(value="Select a target. A sidecar of the original "
                                            "metadata is written next to the output.")
        self._status(wipe, self.md_status)

        _, repro = self._panel(left, "Reproduce metadata", "restore or synthesise")
        row = self._row(repro)
        self.btn(row, "Restore from sidecar JSON…", self.md_restore, "default").pack(side="left")
        self.btn(row, "Write manual tags…", self.md_manual, "default").pack(side="left", padx=7)
        tk.Label(repro, text=(
            "Restore re-applies every saved tag through ExifTool (-json sidecar). "
            "Manual mode writes arbitrary Group:Tag=Value pairs to a copy, for rebuilding "
            "a source profile that was stripped elsewhere."),
            bg=SURFACE, fg=MUTED, justify="left", anchor="w", wraplength=620,
            font=FONT_XS).pack(fill="x", pady=(8, 0))

        _, logpanel = self._panel(right, "Activity log", "case trail", expand=True)
        self.md_log = self._console(logpanel, height=18)

        _, ref = self._panel(right, "Wipe notes", "what ExifTool will and will not remove",
                             expand=False)
        tk.Label(ref, text=(
            "• -all= removes every writable tag group ExifTool knows for the format.\n"
            "• Group selection builds -GROUP:all= for surgical wipes (keep GPS, drop XMP…).\n"
            "• Anti-carve mode truncates at the container's true end, deleting data\n"
            "  appended after IEND/EOI/%%EOF that a carver would otherwise recover.\n"
            "• Formats ExifTool cannot write are refused rather than silently passed."),
            bg=SURFACE, fg=MUTED, justify="left", anchor="w", font=MONO_SM).pack(fill="x")

    # ── page 4: Shr3dder ───────────────────────────────────────────────────
    def _build_shred_page(self) -> None:
        page = self._page("shred")
        self._heading(page, "Secure erasure / 04", "Shr3dder",
                      "Overwrites the chosen file(s) repeatedly with the selected pattern, "
                      "flushes each pass to the device, optionally truncates and unlinks — "
                      "the multi-pass semantics of Linux shred, driven from a real filesystem.")

        top = tk.Frame(page, bg=BG)
        top.pack(fill="x")
        left, right = tk.Frame(top, bg=BG), tk.Frame(top, bg=BG)
        left.pack(side="left", fill="both", expand=True, padx=(0, 7))
        right.pack(side="left", fill="both", expand=True, padx=(7, 0))

        _, body = self._panel(left, "Targets", "multi-select supported")
        self.shred_list = tk.Listbox(body, bg=SURFACE_2, fg="#cfe0f2", relief="flat",
                                     font=MONO_SM, highlightthickness=1,
                                     highlightbackground=LINE, selectbackground="#1a4d63",
                                     selectforeground="#ffffff", height=9,
                                     exportselection=False)
        self.shred_list.pack(fill="both", expand=True)
        row = self._row(body)
        self.btn(row, "Add file(s)…", self.add_shred_targets, "default").pack(side="left")
        self.btn(row, "Add folder…", self.add_shred_folder, "default").pack(side="left", padx=7)
        self.btn(row, "Remove selected", self.remove_shred_targets, "ghost").pack(side="left")
        self.btn(row, "Clear list", self.clear_shred_targets, "ghost").pack(side="left", padx=7)

        _, opts = self._panel(left, "Overwrite plan", "Shred", expand=False)
        row = self._row(opts)
        tk.Label(row, text="Pattern", bg=SURFACE, fg=MUTED, font=FONT_SM, width=22,
                 anchor="w").pack(side="left")
        self.combo(row, self.shred_pattern, list(SHRED_PATTERNS), width=42).pack(side="left")
        row = self._row(opts)
        tk.Label(row, text="Passes (custom)", bg=SURFACE, fg=MUTED, font=FONT_SM, width=22,
                 anchor="w").pack(side="left")
        self.entry(row, self.shred_passes, width=8).pack(side="left")
        self.check(row, "fsync after every pass", tk.BooleanVar(value=True)).pack(side="left", padx=14)
        row = self._row(opts)
        self.check(row, "Truncate to zero length after passes", self.shred_truncate).pack(side="left")
        self.check(row, "Unlink (remove directory entry) after passes",
                   self.shred_unlink).pack(side="left", padx=12)
        row = self._row(opts)
        self.check(row, "Verify afterwards (re-hash + header probe)",
                   self.shred_verify).pack(side="left")
        self.check(row, "Follow symlinks (shred the target)",
                   self.shred_follow_links).pack(side="left", padx=12)

        self._notice(opts, "Storage-layer reality check",
                     "Overwrite is effective on magnetic media and plain filesystems. On SSDs, "
                     "NVMe, copy-on-write (btrfs/ZFS), thin provisioning and cloud-synced "
                     "folders, the controller may remap blocks so old data survives. For "
                     "assurance, pair this with full-device encryption or the vendor's "
                     "sanitize command.", "warn")

        row = self._row(opts)
        self.btn(row, "Shred selected file(s)", self.run_shred, "danger").pack(side="left")
        self.btn(row, "Stop", self.cancel_shred, "ghost").pack(side="left", padx=7)
        self.shred_status = tk.StringVar(value="Add files, choose a plan, then shred. "
                                               "Confirmation is required before the first pass.")
        self._status(opts, self.shred_status)
        self.shred_progress = ttk.Progressbar(opts, mode="determinate", maximum=100,
                                              length=400)
        self.shred_progress.pack(fill="x", pady=(8, 0))

        _, logpanel = self._panel(right, "Shred log", "per-file results", expand=True)
        self.shred_log = self._console(logpanel, height=20)

        _, ref = self._panel(right, "Pattern reference", "Shred", expand=False)
        tk.Label(ref, text=(
            "Zero / Ones      single pass, fastest, defeats casual recovery.\n"
            "Random           cryptographic entropy, defeats statistical carving.\n"
            "DoE / NIST 800-88  0x00, 0xFF, random — the accepted 3-pass baseline.\n"
            "Gutmann          35 passes, for pre-2001 MFM/RLL drives.\n"
            "0xAA/0x55        alternating bit pattern, exposes weak termination.\n"
            "Custom N         repeat one pattern N times (your choice)."),
            bg=SURFACE, fg=MUTED, justify="left", anchor="w", font=MONO_SM).pack(fill="x")

    # ── page 5: HideMe ─────────────────────────────────────────────────────
    def _build_hide_page(self) -> None:
        page = self._page("hide")
        self._heading(page, "Concealment / 05", "HideMe",
                      "Steganography for arbitrary files: embed any payload into any carrier "
                      "(append stream works with every file type), or into image pixels with "
                      "LSB encoding. Encrypt the payload with a passphrase, then extract, "
                      "check, or audit what a container is hiding.")

        top = tk.Frame(page, bg=BG)
        top.pack(fill="x")
        left, right = tk.Frame(top, bg=BG), tk.Frame(top, bg=BG)
        left.pack(side="left", fill="both", expand=True, padx=(0, 7))
        right.pack(side="left", fill="both", expand=True, padx=(7, 0))

        _, pick = self._panel(left, "1 · Carrier and payload", "any file type", expand=False)
        self.hide_carrier_label = tk.StringVar(value="Carrier: —")
        self.hide_payload_label = tk.StringVar(value="Payload: —")
        tk.Label(pick, textvariable=self.hide_carrier_label, bg=SURFACE, fg="#b9cde1",
                 anchor="w", font=MONO_SM).pack(fill="x")
        tk.Label(pick, textvariable=self.hide_payload_label, bg=SURFACE, fg="#b9cde1",
                 anchor="w", font=MONO_SM).pack(fill="x", pady=(2, 8))
        row = self._row(pick)
        self.btn(row, "Carrier…", self.choose_hide_carrier, "default").pack(side="left")
        self.btn(row, "Payload…", self.choose_hide_payload, "default").pack(side="left", padx=7)
        self.btn(row, "Use evidence file as carrier", self.use_evidence_for_hide,
                 "ghost").pack(side="left")

        _, do = self._panel(left, "2 · Method and protection", "HideMe", expand=False)
        row = self._row(do)
        self.radio(row, "Append stream (works with ANY carrier)", "append",
                   self.hide_mode).pack(side="left")
        self.radio(row, "Pixel LSB (PNG / BMP / TGA carrier)", "lsb",
                   self.hide_mode).pack(side="left", padx=12)
        row = self._row(do)
        tk.Label(row, text="Passphrase", bg=SURFACE, fg=MUTED, font=FONT_SM, width=18,
                 anchor="w").pack(side="left")
        self.entry(row, self.hide_passphrase, width=26, show="•").pack(side="left")
        tk.Label(row, text="bits/byte", bg=SURFACE, fg=MUTED, font=FONT_SM,
                 ).pack(side="left", padx=(12, 4))
        self.combo(row, self.hide_bits, [str(value) for value in LSB_BITS], width=5).pack(side="left")
        row = self._row(do)
        tk.Label(row, text="Comment (stored in header)", bg=SURFACE, fg=MUTED, font=FONT_SM,
                 width=18, anchor="w").pack(side="left")
        self.entry(row, self.hide_comment, width=42).pack(side="left")
        self.hide_capacity = tk.StringVar(value="")
        tk.Label(do, textvariable=self.hide_capacity, bg=SURFACE, fg=DIM, anchor="w",
                 font=FONT_XS, justify="left", wraplength=620).pack(fill="x", pady=(8, 0))

        row = self._row(do)
        self.btn(row, "Embed payload → new carrier", self.run_hide_embed, "primary").pack(side="left")
        self.btn(row, "Check container", self.run_hide_check, "default").pack(side="left", padx=7)
        self.btn(row, "Extract payload…", self.run_hide_extract, "default").pack(side="left")
        self.check(row, "Overwrite carrier in place", self.hide_overwrite).pack(side="left", padx=10)
        self.hide_status = tk.StringVar(value="Choose a carrier and a payload, then embed. "
                                              "Check audits any file for hidden entries.")
        self._status(do, self.hide_status)

        _, res = self._panel(left, "3 · Results", "what the container holds", expand=True)
        self.hide_result = self._console(res, height=9)

        _, logpanel = self._panel(right, "Activity log", "case trail", expand=True)
        self.hide_log = self._console(logpanel, height=12)

        _, ref = self._panel(right, "Container anatomy", "NbHide/1", expand=False)
        tk.Label(ref, text=(
            "carrier bytes │ NBHIDE\\x00\\x01 │ u32 header length │ JSON header │\n"
            "payload (AES-256-CBC + HMAC-SHA256 when a passphrase is set) │ NBEND trailer\n\n"
            "The JSON header records payload name, size, SHA-256, creation time, carrier\n"
            "hash, cipher parameters and your comment. Append mode leaves the carrier's own\n"
            "bytes byte-for-byte intact, so the host file still opens normally. Pixel mode\n"
            "spreads the same payload across the least significant bits of the image data,\n"
            "with capacity = width × height × channels × 8 ÷ bits."),
            bg=SURFACE, fg=MUTED, justify="left", anchor="w", font=MONO_SM).pack(fill="x")

    # ── navigation / session ───────────────────────────────────────────────
    def show_page(self, key: str) -> None:
        for child in self.content.winfo_children():
            child.pack_forget()
        self.pages[key].pack(fill="both", expand=True)
        self.breadcrumb.configure(text=f"Workbench  /  {PAGE_NAMES[key]}")
        for item, button in self.nav_buttons.items():
            active = item == key
            button.configure(bg="#122b40" if active else RAIL,
                             fg=TEXT if active else "#a8b8ca",
                             font=("Segoe UI", 10, "bold" if active else "normal"))

    def choose_file(self) -> None:
        name = filedialog.askopenfilename(title="Select local evidence file")
        if name:
            self.select_path(Path(name))

    def select_path(self, path: Path) -> None:
        try:
            resolved = path.expanduser().resolve(strict=True)
        except Exception as exc:
            messagebox.showerror("Cannot select file", str(exc), parent=self.root)
            return
        if resolved.is_dir():
            messagebox.showerror("Cannot select file", "Select a regular file, not a folder.",
                                 parent=self.root)
            return
        self.selected_path = resolved
        self.metadata_rows = []
        self.metadata_json = None
        self.hide_entries = []
        self._fill_tree(self.metadata_tree, [])
        self.file_status.set(f"Evidence: {resolved}  ·  {format_bytes(resolved.stat().st_size)}"
                             f"  ·  {human_permissions(resolved)}")
        self.file_summary.set(
            f"Name: {resolved.name}\nPath: {resolved}\nSize: {format_bytes(resolved.stat().st_size)}"
            f"  ({resolved.stat().st_size} bytes)\nType: {mimetypes.guess_type(resolved.name)[0] or 'unknown'}"
            f"  ·  {detect_signature(resolved.read_bytes()[:64]) or 'unknown signature'}\n"
            f"Modified: {_dt.datetime.fromtimestamp(resolved.stat().st_mtime).astimezone().isoformat(timespec='seconds')}")
        self.tech_summary.set("Run 'Extract ALL metadata' for the technical summary.")
        self.exif_status.set("File selected — extract to begin.")
        self._set_text(self.hide_result, "")
        self.hide_status.set("Carrier ready. Choose a payload and embed.")
        self._log(self.hide_log, f"Evidence file selected: {resolved}")

    def clear_session(self) -> None:
        self.selected_path = None
        self.metadata_rows = []
        self.metadata_json = None
        self.shred_targets = []
        self.corrupt_target = None
        self.corrupt_outputs = []
        self.md_target = None
        self.hide_entries = []
        self.hide_carrier = None
        self.hide_payload = None
        self.file_status.set("No evidence file selected")
        self.file_summary.set("Choose an evidence file to inspect.")
        self.tech_summary.set("No file inspected yet.")
        self.corrupt_target_label.set("No target selected.")
        self.md_target_label.set("No target selected.")
        self.hide_carrier_label.set("Carrier: —")
        self.hide_payload_label.set("Payload: —")
        self._fill_tree(self.metadata_tree, [])
        self.shred_list.delete(0, "end")
        self.exif_status.set("Session cleared.")
        self.corrupt_status.set("Session cleared — select a target.")
        self.md_status.set("Session cleared — select a target.")
        self.shred_status.set("Session cleared — add files to the queue.")
        self.hide_status.set("Session cleared.")
        self._set_text(self.hide_result, "")
        for widget in (self.corrupt_log, self.md_log, self.shred_log, self.hide_log):
            self._set_text(widget, "")

    # ── logging ────────────────────────────────────────────────────────────
    def _log(self, widget: tk.Text, message: str, level: str = "") -> None:
        stamp = _dt.datetime.now().strftime("%H:%M:%S")
        line = f"[{stamp}] {message}"
        widget.configure(state="normal")
        widget.insert("end", line + "\n", level)
        widget.see("end")
        widget.configure(state="disabled")
        self.case_log.append((now_iso(), line))

    def save_case_log(self) -> None:
        if not self.case_log:
            messagebox.showinfo("Activity log", "No activity recorded yet.", parent=self.root)
            return
        target = filedialog.asksaveasfilename(
            title="Save activity log", initialfile=f"nbexif-activity-{_dt.date.today()}.log",
            defaultextension=".log", filetypes=[("Log", "*.log"), ("Text", "*.txt")])
        if not target:
            return
        with open(target, "w", encoding="utf-8") as stream:
            stream.write(f"NbExif Forensics Bench activity log — {now_iso()}\n")
            stream.write(f"ExifTool {exiftool_version()}\n{'=' * 70}\n")
            for stamp, line in self.case_log:
                stream.write(f"{stamp} {line}\n")
        self._log(self.corrupt_log, f"Activity log saved to {target}", "ok")

    def _busy_on(self, on: bool) -> None:
        self.busy = on
        self.root.configure(cursor="watch" if on else "")

    # ── threading ──────────────────────────────────────────────────────────
    # Tk is not thread-safe and Python 3.12+ rejects `after()` from a worker
    # thread ("main thread is not in main loop"), so workers only ever push
    # plain tuples onto this queue; `_drain_queue` runs on the UI thread.
    def _worker(self, work: Callable[[], object], done: Callable[[object], None],
                fail: Callable[[Exception], None] | None = None) -> None:
        self._busy_on(True)

        def target() -> None:
            try:
                result = work()
            except Exception as exc:  # noqa: BLE001 - surfaced to the UI thread
                self._queue.put(("fail", (fail, exc)))
            else:
                self._queue.put(("done", (done, result)))

        threading.Thread(target=target, daemon=True).start()

    def _drain_queue(self) -> None:
        """Main-thread pump for worker results. Scheduled with root.after()."""
        try:
            while True:
                kind, payload = self._queue.get_nowait()
                if kind == "progress":
                    self._on_progress(*payload)
                elif kind == "done":
                    done, value = payload
                    self._busy_on(False)
                    done(value)
                elif kind == "fail":
                    fail, exc = payload
                    self._busy_on(False)
                    if fail:
                        fail(exc)
                    else:
                        messagebox.showerror("Operation failed", str(exc), parent=self.root)
        except queue.Empty:
            pass
        except Exception as exc:  # never let the pump die
            messagebox.showerror("Internal error", f"{type(exc).__name__}: {exc}",
                                 parent=self.root)
        finally:
            self.root.after(80, self._drain_queue)

    @staticmethod
    def _set_text(widget: tk.Text, text: str) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", text)
        widget.configure(state="disabled")

    @staticmethod
    def _fill_tree(tree: ttk.Treeview, rows: Iterable[tuple[str, ...]]) -> None:
        for item in tree.get_children():
            tree.delete(item)
        for row in rows:
            tree.insert("", "end", values=row)

    def _copy_selection(self, _event: object = None) -> None:
        selection = self.metadata_tree.selection()
        if not selection:
            return
        values = self.metadata_tree.item(selection[0], "values")
        self.root.clipboard_clear()
        self.root.clipboard_append(str(values[1]))
        self.exif_status.set(f"Copied value of {values[0]} to the clipboard.")

    def _popup_tag_menu(self, event: tk.Event) -> None:
        selection = self.metadata_tree.selection()
        if not selection:
            return
        values = self.metadata_tree.item(selection[0], "values")
        menu = tk.Menu(self.root, tearoff=0, bg=SURFACE, fg=TEXT, activebackground="#1a4d63",
                       activeforeground="#ffffff", font=MONO_SM)
        menu.add_command(label="Copy value", command=self._copy_selection)
        menu.add_command(label="Copy tag", command=lambda: (
            self.root.clipboard_clear(), self.root.clipboard_append(str(values[0]))))
        menu.add_command(label="Show only this group", command=lambda: self._filter_group(
            str(values[0]).split(":")[0]))
        menu.add_separator()
        menu.add_command(label="Filter by this tag name", command=lambda: self._filter_text(
            str(values[0]).split(":")[-1]))
        menu.add_command(label="Clear filter", command=self._clear_filter)
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def _filter_text(self, text: str) -> None:
        self.exif_filter.set(text)
        self._apply_filter()

    def _filter_group(self, group: str) -> None:
        self.exif_group_filter.set(group)
        self._apply_filter()

    def _clear_filter(self) -> None:
        self.exif_filter.set("")
        self.exif_group_filter.set("All groups")
        self._apply_filter()

    def _apply_filter(self) -> None:
        needle = self.exif_filter.get().strip().lower()
        group = self.exif_group_filter.get()
        rows = []
        for tag, value, note in self.metadata_rows:
            if group != "All groups" and not tag.startswith(group + ":"):
                continue
            if needle and needle not in tag.lower() and needle not in value.lower():
                continue
            rows.append((tag, value, note))
        self._fill_tree(self.metadata_tree, rows)
        self.exif_status.set(f"{len(rows)} of {len(self.metadata_rows)} tags shown "
                             f"(filter: {group if group != 'All groups' else 'all groups'}"
                             f"{', ' + needle if needle else ''}).")

    # ══ NbExif implementation ══════════════════════════════════════════════
    _PROFILE_ARGS = {
        "Everything (all groups, duplicates, binary)": [],
        "Deep (adds embedded files + RequestAll)": ["-api", "RequestAll=3"],
        "EXIF only": ["-EXIF:all"],
        "GPS only": ["-GPS:all"],
        "IPTC only": ["-IPTC:all"],
        "XMP only": ["-XMP:all"],
        "Composite/File system info": ["-Composite:all", "-File:all", "-EXIF:all"],
        "Quick — no duplicates": [],
    }

    def extract_metadata(self) -> None:
        path = self.selected_path
        if path is None or not path.exists():
            messagebox.showinfo("No evidence file", "Choose an evidence file in the top bar first.",
                                parent=self.root)
            return
        profile = self.exif_mode.get()
        extra = list(self._PROFILE_ARGS.get(profile, []))
        keep_duplicates = not profile.startswith("Quick")
        deep = bool(self.exif_deep.get())   # read Tk state now, never in the worker
        self.exif_status.set("ExifTool is reading every tag…")
        self._fill_tree(self.metadata_tree, [])
        self.metadata_rows = []

        def work() -> dict:
            # 1. JSON pass — authoritative for Group:Tag names and values.
            json_args = ["-json", "-G", "-u", "-s", "-struct"]
            if keep_duplicates:
                json_args.append("-a")
            if deep:
                json_args.append("-ee")
            json_args += extra
            json_proc = run_exiftool([*json_args, str(path)])
            records = []
            if json_proc.stdout.strip():
                try:
                    records = json.loads(json_proc.stdout)
                except json.JSONDecodeError:
                    records = []

            # 2. text pass — recovers duplicate values the JSON pass collapsed.
            text_args = ["-G", "-u", "-s", "-struct"]
            if keep_duplicates:
                text_args.append("-a")
            if deep:
                text_args.append("-ee")
            text_args += extra
            text_proc = run_exiftool([*text_args, str(path)])

            rows: list[tuple[str, str, str]] = []
            # (a) primary rows from JSON, preserving ExifTool's tag ordering
            json_names: dict[str, str] = {}          # short tag -> Group:Tag as JSON sees it
            json_count: dict[str, int] = {}
            json_rows: list[list[str]] = []
            for record in records if isinstance(records, list) else []:
                if not isinstance(record, dict):
                    continue
                for key, value in record.items():
                    if key == "SourceFile":
                        continue
                    short = key.split(":")[-1]
                    json_names.setdefault(short, key)
                    json_count[short] = json_count.get(short, 0) + 1
                    json_rows.append([key, render_metadata_value(value), ""])

            # (b) single text pass: count repeats, keep the values JSON dropped
            seen_text: dict[str, int] = {}
            extras: list[tuple[str, str, str]] = []
            unknown: list[tuple[str, str, str]] = []
            dup_names: set[str] = set()
            for line in text_proc.stdout.splitlines():
                parsed = parse_exiftool_line(line)
                if not parsed:
                    continue
                short, value, group = parsed
                if short in ("ExifToolVersion", "Error", "Warning"):
                    continue
                seen_text[short] = seen_text.get(short, 0) + 1
                occurrence = seen_text[short]
                if short not in json_count:
                    unknown.append((f"{group}:{short}" if group else short, value, ""))
                elif occurrence > json_count[short]:
                    full = json_names.get(short) or (f"{group}:{short}" if group else short)
                    extras.append((full, value, f"dup {occurrence}"))
                    dup_names.add(short)

            # mark primary rows only when this exact tag genuinely repeated
            for row in json_rows:
                if row[0].split(":")[-1] in dup_names:
                    row[2] = "dup"
            rows = [tuple(row) for row in json_rows] + extras + unknown

            warnings = (json_proc.stderr.strip() + "\n" + text_proc.stderr.strip()).strip()
            # 3. technical summary (independent of ExifTool)
            size = path.stat().st_size
            summary = (
                f"path        {path}\n"
                f"size        {size} bytes ({format_bytes(size)})\n"
                f"signature   {detect_signature(path.read_bytes()[:64]) or 'unknown'}\n"
                f"permissions {human_permissions(path)}  owner uid={os.lstat(path).st_uid} gid={os.lstat(path).st_gid}\n"
                f"created     {_dt.datetime.fromtimestamp(os.lstat(path).st_ctime).astimezone().isoformat(timespec='seconds')}\n"
                f"modified    {_dt.datetime.fromtimestamp(path.stat().st_mtime).astimezone().isoformat(timespec='seconds')}\n"
                f"accessed    {_dt.datetime.fromtimestamp(path.stat().st_atime).astimezone().isoformat(timespec='seconds')}\n"
                f"entropy     {shannon_entropy(path):.3f} bits/byte (first 4 MB)\n"
                f"md5         {hash_file(path, 'md5') or 'unavailable (FIPS)'}\n"
                f"sha1        {hash_file(path, 'sha1') or 'unavailable (FIPS)'}\n"
                f"sha256      {hash_file(path, 'sha256')}\n"
                f"tags found  {len(rows)} (unique {len(set(r[0] for r in rows))})"
            )
            return {"rows": rows, "records": records, "warnings": warnings, "summary": summary}

        def done(result: dict) -> None:
            self.metadata_rows = [(tag, value, note) for tag, value, note in result["rows"]]
            self.metadata_json = result["records"] or None
            # offer only the tag groups this file actually contains
            found = sorted({tag.split(":")[0] for tag, _, _ in self.metadata_rows if ":" in tag})
            self.exif_group_combo.configure(values=["All groups"] + found)
            if self.exif_group_filter.get() not in ["All groups"] + found:
                self.exif_group_filter.set("All groups")
            self._apply_filter()
            self.tech_summary.set(result["summary"])
            message = f"{len(self.metadata_rows)} tags extracted from {path.name}"
            if result["warnings"]:
                message += f" — ExifTool notes: {result['warnings'][:400]}"
            self.exif_status.set(message)
            self._log(self.hide_log, f"NbExif extracted {len(self.metadata_rows)} tags from {path}")

        self._worker(work, done, lambda err: self.exif_status.set(f"Extraction failed: {err}"))

    def export_metadata(self, kind: str) -> None:
        if not self.metadata_rows:
            messagebox.showinfo("Nothing to export", "Extract metadata first.", parent=self.root)
            return
        default = f"{self.selected_path.stem}.metadata.{kind}"
        target = filedialog.asksaveasfilename(title=f"Export metadata ({kind.upper()})",
                                              initialfile=default,
                                              defaultextension=f".{kind}",
                                              filetypes=[(kind.upper(), f"*.{kind}")])
        if not target:
            return
        if kind == "json":
            payload = self.metadata_json if self.metadata_json else [
                {"SourceFile": str(self.selected_path),
                 **{tag: value for tag, value, _ in self.metadata_rows}}]
            Path(target).write_text(json.dumps(payload, ensure_ascii=False, indent=2),
                                    encoding="utf-8")
        elif kind == "csv":
            import csv
            with open(target, "w", newline="", encoding="utf-8") as stream:
                writer = csv.writer(stream)
                writer.writerow(["tag", "value"])
                writer.writerows((tag, value) for tag, value, _ in self.metadata_rows)
        else:
            esc = lambda s: (str(s).replace("&", "&amp;").replace("<", "&lt;")
                             .replace(">", "&gt;"))
            body = "\n".join(f"  <tag name=\"{esc(tag)}\" note=\"{note}\">{esc(value)}</tag>"
                             for tag, value, note in self.metadata_rows)
            Path(target).write_text(
                '<?xml version="1.0" encoding="utf-8"?>\n'
                f'<metadata file="{esc(self.selected_path)}" rows="{len(self.metadata_rows)}">\n'
                f"{body}\n</metadata>\n", encoding="utf-8")
        self.exif_status.set(f"Metadata exported ({kind.upper()}): {target}")
        self._log(self.hide_log, f"Exported metadata sidecar: {target}", "ok")

    def export_binary_tag(self) -> None:
        selection = self.metadata_tree.selection()
        if not selection:
            messagebox.showinfo("Select a tag", "Select a tag row first, then export its "
                                                "binary block.", parent=self.root)
            return
        tag = str(self.metadata_tree.item(selection[0], "values")[0])
        target = filedialog.asksaveasfilename(title=f"Export binary block for {tag}",
                                              initialfile=f"{tag.replace(':', '_')}.bin",
                                              defaultextension=".bin",
                                              filetypes=[("Binary", "*.bin")])
        if not target:
            return
        proc = run_exiftool(["-b", f"-{tag}", str(self.selected_path)])
        if proc.returncode != 0 and not proc.stdout:
            messagebox.showerror("ExifTool", proc.stderr.strip() or "No binary data for this tag.",
                                 parent=self.root)
            return
        Path(target).write_text(proc.stdout, encoding="utf-8", errors="replace")
        self.exif_status.set(f"Binary block for {tag} exported to {target}")

    # ══ NbCorrupt implementation ═══════════════════════════════════════════
    def choose_corrupt_target(self) -> None:
        name = filedialog.askopenfilename(title="Select target file or symlink")
        if name:
            self.corrupt_target = Path(name).expanduser().absolute()
            self.corrupt_target_label.set(f"Target: {self.corrupt_target}")
            self.inspect_corrupt_target()

    def inspect_corrupt_target(self) -> None:
        path = self.corrupt_target
        if path is None or not path.exists():
            self.corrupt_intro.set("Target is missing or a broken link.")
            return
        info = [f"path        {path}",
                f"exists     yes (symlink: {path.is_symlink()})",
                f"size       {format_bytes(path.stat().st_size)}",
                f"signature  {detect_signature(path.read_bytes()[:64]) or 'unknown'}"]
        if path.is_symlink():
            info.append(f"link target {os.readlink(path)}")
        self.corrupt_intro.set("\n".join(info))

    def _ask_confirmation(self, title: str, message: str, token: str) -> bool:
        window = tk.Toplevel(self.root)
        window.title(title)
        window.configure(bg=SURFACE)
        window.transient(self.root)
        window.resizable(False, False)
        tk.Label(window, text=title, bg=SURFACE, fg=DANGER, font=("Segoe UI", 12, "bold")
                 ).pack(anchor="w", padx=18, pady=(18, 6))
        tk.Label(window, text=message, bg=SURFACE, fg=MUTED, justify="left", wraplength=460,
                 font=FONT_SM).pack(anchor="w", padx=18)
        entry = self.entry(window, None, width=32)
        entry.pack(fill="x", padx=18, pady=12)
        result = {"ok": False}

        def accept() -> None:
            if entry.get().strip() == token:
                result["ok"] = True
                window.destroy()

        row = tk.Frame(window, bg=SURFACE)
        row.pack(fill="x", padx=18, pady=(0, 16))
        self.btn(row, f"Type “{token}” to confirm", accept, "danger").pack(side="left")
        self.btn(row, "Cancel", window.destroy, "ghost").pack(side="left", padx=8)
        entry.focus_set()
        window.grab_set()
        self.root.wait_window(window)
        return result["ok"]

    def _resolve_output(self, path: Path, suffix: str = "") -> Path:
        if self.corrupt_inplace.get():
            if not self._ask_confirmation("Destructive confirmation",
                                          f"This will modify {path} in place and cannot be "
                                          f"undone. Confirm the operation.",
                                          path.name):
                raise RuntimeError("Cancelled by the operator.")
            return path
        base = filedialog.asksaveasfilename(
            title="Save corrupted copy", initialfile=f"{path.stem}{suffix}{path.suffix}",
            filetypes=[("Output", f"*{path.suffix}" if path.suffix else "*.*")])
        if not base:
            raise RuntimeError("No output path selected.")
        out = Path(base)
        if out.exists():
            raise RuntimeError(f"{out} already exists — refusing to overwrite.")
        return out

    def run_corrupt(self) -> None:
        path = self.corrupt_target
        if path is None or not path.exists():
            messagebox.showinfo("No target", "Choose a target file or symlink first.",
                                parent=self.root)
            return
        mode = self.corrupt_mode.get()
        password = self.corrupt_passphrase.get()
        if mode.startswith("AES") and not password:
            messagebox.showerror("Passphrase required", "Set a passphrase for the AES operation.",
                                 parent=self.root)
            return
        # ── resolve every input on the UI thread (Tk dialogs are not thread-safe) ──
        symlink_only = mode.startswith("Symlink: break") or mode.startswith("Symlink: repoint")
        repoint_to = self._repoint_entry.get().strip() if self._repoint_entry else ""
        if mode.startswith("Symlink: break") and not path.is_symlink():
            messagebox.showerror("Not a symlink", "The selected target is not a symbolic link.",
                                 parent=self.root)
            return
        if mode.startswith("Symlink: repoint"):
            if not path.is_symlink():
                messagebox.showerror("Not a symlink", "The selected target is not a symbolic link.",
                                     parent=self.root)
                return
            if not repoint_to:
                messagebox.showerror("New target required",
                                     "Type the new symlink target in the re-point field.",
                                     parent=self.root)
                return
        effective = path.resolve() if mode.startswith("Symlink: corrupt the target") else path
        try:
            out = None if symlink_only else self._resolve_output(
                effective, ".linktarget" if mode.startswith("Symlink: corrupt") else ".corrupt")
        except RuntimeError as exc:
            self.corrupt_status.set(str(exc))
            return
        percent = float(self.corrupt_percent.get())
        header_bytes = int(self.corrupt_header_bytes.get() or 0)
        fill_kind = self.corrupt_fill.get()
        try:
            trunc_size = int(self.corrupt_trunc_size.get() or 0)
        except ValueError:
            trunc_size = 0
        trunc_unit = self.corrupt_trunc_unit.get()
        try:
            pattern_byte = int(self.corrupt_overwrite_byte.get(), 0) & 0xFF
        except ValueError:
            pattern_byte = 0

        self.corrupt_status.set(f"Running: {mode}…")
        self._log(self.corrupt_log, f"▶ {mode} on {path}"
                                   + (" (in place)" if self.corrupt_inplace.get() else ""))
        if out is not None:
            self._log(self.corrupt_log, f"  output → {out}")

        def work() -> dict:
            before = {"sha256": hash_file(effective, "sha256"), "size": effective.stat().st_size}
            if mode.startswith("Symlink: break"):
                old = os.readlink(path)
                path.unlink()
                return {"mode": mode, "link_target": old, "out": "(link removed)", "before": before}
            if mode.startswith("Symlink: repoint"):
                old = os.readlink(path)
                path.unlink()
                path.symlink_to(repoint_to)
                return {"mode": mode, "old_target": old, "new_target": repoint_to,
                        "out": "(link repointed)", "before": before}
            if mode.startswith("Symlink: corrupt the target"):
                result = corrupt_random(effective, out, percent, seed=None)
                result["via_link"] = str(path)
            elif mode.startswith("Random"):
                result = corrupt_random(effective, out, percent, seed=None)
            elif mode.startswith("Header"):
                result = corrupt_header(effective, out, header_bytes, fill_kind)
            elif mode.startswith("Signature"):
                result = corrupt_magic(effective, out)
            elif mode.startswith("Truncate"):
                size = (int(effective.stat().st_size * trunc_size / 100)
                        if trunc_unit == "percent" else trunc_size)
                result = corrupt_truncate(effective, out, max(0, size))
            elif mode.startswith("Whole-file zero"):
                result = corrupt_fill(effective, out, "zero")
            elif mode.startswith("Whole-file pattern"):
                with out.open("wb") as handle:
                    for _ in range(max(1, effective.stat().st_size // CHUNK + 1)):
                        handle.write(bytes([pattern_byte]) * min(CHUNK, effective.stat().st_size))
                result = {"mode": "overwrite", "byte": f"0x{pattern_byte:02x}", "out": str(out),
                          "sha256": hash_file(out, "sha256")}
            elif mode.startswith("AES-256 encrypt"):
                result = corrupt_encrypt(effective, out, password)
            elif mode.startswith("AES-256 decrypt"):
                result = corrupt_decrypt(effective, out, password)
            else:
                raise RuntimeError(f"Unknown mode: {mode}")
            result["before"] = before
            return result

        def done(result: dict) -> None:
            before = result.get("before", {})
            written = result.get("out")
            if written and not str(written).startswith("(link"):
                try:
                    produced = Path(written)
                    if produced not in self.corrupt_outputs and produced.exists():
                        self.corrupt_outputs.append(produced)
                except OSError:
                    pass
            self._log(self.corrupt_log, f"  before  size {before.get('size')}  "
                                        f"sha256 {str(before.get('sha256'))[:32]}…", "head")
            for key, value in result.items():
                if key in ("mode", "out", "before"):
                    continue
                self._log(self.corrupt_log, f"  {key:<9} {value}")
            self.corrupt_status.set(f"{mode} complete — output: {result.get('out')}")

        def fail(err: Exception) -> None:
            self.corrupt_status.set(f"{mode} failed: {err}")
            self._log(self.corrupt_log, f"✗ {mode} failed: {err}", "danger")

        self._worker(work, done, fail)

    def cleanup_outputs(self) -> None:
        """Delete the output files this session created (never originals or targets).

        Defence in depth: a path only qualifies if it (a) is in the tracked list,
        (b) exists, (c) is not a symlink, and (d) differs from the current target
        and from the session's evidence file.
        """
        protected = {p for p in (self.corrupt_target, self.selected_path) if p is not None}
        protected = {p.resolve() for p in protected}
        outputs = []
        for path in self.corrupt_outputs:
            try:
                if not path.exists() or path.is_symlink():
                    continue
                if path.resolve() in protected:
                    continue
                outputs.append(path)
            except OSError:
                continue
        if not outputs:
            self.corrupt_status.set("No removable NbCorrupt outputs from this session remain.")
            return
        listing = "\n".join(f"  {p}  ({format_bytes(p.stat().st_size)})" for p in outputs)
        if not self._ask_confirmation(
                "Remove generated outputs",
                f"These {len(outputs)} file(s) were produced by this session and will be "
                f"deleted. Original evidence is not touched.\n\n{listing}", "DELETE"):
            self.corrupt_status.set("Cancelled — nothing was deleted.")
            return
        removed, failed = 0, []
        for path in outputs:
            try:
                path.unlink()
                removed += 1
            except OSError as exc:
                failed.append(f"{path}: {exc}")
        self.corrupt_outputs = [p for p in self.corrupt_outputs if p.exists()]
        for line in failed:
            self._log(self.corrupt_log, f"could not remove {line}", "danger")
        self._log(self.corrupt_log, f"removed {removed} generated output(s)", "ok")
        self.corrupt_status.set(f"Removed {removed} generated output(s).")

    # ══ MetaDelete implementation ══════════════════════════════════════════
    def choose_md_target(self) -> None:
        name = filedialog.askopenfilename(title="Select target file")
        if name:
            self.md_target = Path(name).expanduser().absolute()
            self.md_target_label.set(f"Target: {self.md_target}")
            self._log(self.md_log, f"MetaDelete target: {self.md_target}")

    def use_evidence_for_md(self) -> None:
        if self.selected_path:
            self.md_target = self.selected_path
            self.md_target_label.set(f"Target: {self.selected_path}")
            self._log(self.md_log, f"Using evidence file: {self.selected_path}")
        else:
            messagebox.showinfo("No evidence", "Choose an evidence file first.", parent=self.root)

    def _md_output_path(self, source: Path, suffix: str) -> Path:
        if self.md_inplace.get():
            return source
        target = filedialog.asksaveasfilename(
            title="Save metadata-stripped copy", initialfile=f"{source.stem}{suffix}{source.suffix}",
            filetypes=[("Same type", f"*{source.suffix}" if source.suffix else "*.*")])
        if not target:
            raise RuntimeError("No output path selected.")
        out = Path(target)
        if out.exists() and out.resolve() != source.resolve():
            raise RuntimeError(f"{out} exists — refusing to overwrite.")
        return out

    def md_wipe(self) -> None:
        source = self.md_target
        if source is None or not source.exists():
            messagebox.showinfo("No target", "Choose a target file first.", parent=self.root)
            return
        if self.md_inplace.get() and not self._ask_confirmation(
                "In-place wipe", f"Metadata will be erased from {source.name} in place.",
                source.name):
            self.md_status.set("Cancelled — nothing was changed.")
            return
        group = self.md_groups.get()
        try:
            out = self._md_output_path(source, "-nometa")
        except RuntimeError as exc:
            self.md_status.set(str(exc))
            return
        erase_appended = self.md_erase_appended.get()
        reset_times = self.md_reset_times.get()
        self.md_status.set("Removing metadata…")

        def work() -> dict:
            sidecar = source.with_suffix(source.suffix + ".metadata.json")
            proc_dump = run_exiftool(["-json", "-G", "-a", "-u", "-s", "-struct", str(source)])
            sidecar.write_text(proc_dump.stdout or "[]", encoding="utf-8")
            if out.resolve() != source.resolve():
                shutil.copy2(source, out)
            args = ["-overwrite_original"]
            args.append("-all=" if group.startswith("all metadata") else f"-{group}:all=")
            proc = run_exiftool([*args, str(out)])
            if proc.returncode != 0:
                raise RuntimeError(proc.stderr.strip() or proc.stdout.strip()
                                   or "ExifTool could not write this format.")
            notes = []
            if erase_appended:
                end, label = carrier_end(out)
                if end is not None and end < out.stat().st_size:
                    removed = out.stat().st_size - end
                    with out.open("r+b") as handle:
                        handle.truncate(end)
                        os.fsync(handle.fileno())
                    notes.append(f"truncated {removed} appended bytes at {label}")
                else:
                    notes.append("no appended data detected")
            if reset_times:
                stamp = time.time()
                os.utime(out, (stamp, stamp))
                notes.append("mtime/atime reset to now")
            notes.append(f"sidecar saved: {sidecar}")
            return {"out": str(out), "exiftool": proc.stdout.strip(), "notes": notes,
                    "sha256": hash_file(out, "sha256"), "before": hash_file(source, "sha256")}

        def done(result: dict) -> None:
            self._log(self.md_log, f"Wipe {group} on {source.name} → {result['out']}", "ok")
            self._log(self.md_log, f"  before sha256 {result['before'][:32]}…", "head")
            self._log(self.md_log, f"  after  sha256 {result['sha256'][:32]}…", "head")
            for note in result["notes"]:
                self._log(self.md_log, f"  · {note}")
            if result["exiftool"]:
                self._log(self.md_log, f"  exiftool: {result['exiftool']}")
            self.md_status.set(f"Metadata removed → {result['out']}")

        self._worker(work, done, lambda err: (self.md_status.set(f"Wipe failed: {err}"),
                                              self._log(self.md_log, f"✗ {err}", "danger")))

    def md_batch(self) -> None:
        folder = filedialog.askdirectory(title="Choose folder for batch metadata wipe")
        if not folder:
            return
        if not self._ask_confirmation(
                "Batch wipe confirmation",
                f"Every writable file under {folder} will be rewritten IN PLACE. "
                f"Type FOLDER to continue.", "FOLDER"):
            self.md_status.set("Cancelled — nothing was changed.")
            return
        group = self.md_groups.get()
        self.md_status.set("Batch wipe running…")
        arg = "-all=" if group.startswith("all metadata") else f"-{group}:all="

        def work() -> list[dict]:
            root = Path(folder)
            processed = []
            for item in sorted(root.rglob("*")):
                if not item.is_file() or item.name.endswith(".metadata.json"):
                    continue
                proc = run_exiftool(["-overwrite_original", arg, str(item)])
                processed.append({"file": str(item),
                                  "status": "ok" if proc.returncode == 0
                                  else (proc.stderr.strip().splitlines() or ["failed"])[0]})
            return processed

        def done(results: list[dict]) -> None:
            ok = sum(1 for r in results if r["status"] == "ok")
            for item in results:
                level = "ok" if item["status"] == "ok" else "warn"
                self._log(self.md_log, f"{item['status']:<8} {item['file']}", level)
            self.md_status.set(f"Batch complete: {ok}/{len(results)} files rewritten in place.")

        self._worker(work, done, lambda err: self.md_status.set(f"Batch failed: {err}"))

    def md_restore(self) -> None:
        source = self.md_target
        if source is None or not source.exists():
            messagebox.showinfo("No target", "Choose a target file first.", parent=self.root)
            return
        sidecar = filedialog.askopenfilename(title="Select metadata sidecar",
                                             filetypes=[("JSON sidecar", "*.json")])
        if not sidecar:
            return
        side_path = Path(sidecar)
        try:
            out = self._md_output_path(source, "-restored")
        except RuntimeError as exc:
            self.md_status.set(str(exc))
            return
        self.md_status.set("Re-applying saved metadata…")

        def work() -> dict:
            # ExifTool matches a JSON sidecar by SourceFile, so realign it with the
            # output path; otherwise it silently imports nothing.
            try:
                records = json.loads(side_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise RuntimeError(f"{side_path.name} is not a readable ExifTool JSON "
                                   f"sidecar: {exc}") from exc
            if not isinstance(records, list) or not records or not isinstance(records[0], dict):
                raise RuntimeError("Sidecar must be an ExifTool JSON export: a list "
                                   "containing one metadata object.")
            records[0]["SourceFile"] = str(out)
            temp = out.with_name(out.name + ".restore.json")
            temp.write_text(json.dumps(records, ensure_ascii=False), encoding="utf-8")
            try:
                if out.resolve() != source.resolve():
                    shutil.copy2(source, out)
                proc = run_exiftool([f"-json={temp}", "-overwrite_original", str(out)])
            finally:
                temp.unlink(missing_ok=True)
            if proc.returncode != 0:
                raise RuntimeError(proc.stderr.strip() or proc.stdout.strip()
                                   or "ExifTool could not apply this sidecar.")
            wanted = ("SourceFile",)
            restored = sum(1 for key in records[0] if key not in wanted)
            return {"out": str(out), "applied": restored,
                    "warning": proc.stderr.strip(), "stdout": proc.stdout.strip(),
                    "sha256": hash_file(out, "sha256")}

        def done(result: dict) -> None:
            self._log(self.md_log, f"Restored {result['applied']} tags from "
                                   f"{side_path.name} → {out}", "ok")
            if result["warning"]:
                self._log(self.md_log, f"  exiftool: {result['warning']}", "warn")
            self._log(self.md_log, f"  output sha256 {result['sha256'][:32]}…", "head")
            self.md_status.set(f"Metadata restored → {out}. Verify with NbExif.")

        def fail(err: Exception) -> None:
            self.md_status.set(f"Restore failed: {err}")
            self._log(self.md_log, f"✗ restore: {err}", "danger")

        self._worker(work, done, fail)

    def md_manual(self) -> None:
        source = self.md_target
        if source is None or not source.exists():
            messagebox.showinfo("No target", "Choose a target file first.", parent=self.root)
            return
        window = tk.Toplevel(self.root)
        window.title("Write manual metadata tags")
        window.configure(bg=SURFACE)
        window.geometry("560x340")
        window.transient(self.root)
        tk.Label(window, text="Write arbitrary Group:Tag = Value pairs into a copy of the target.",
                 bg=SURFACE, fg=MUTED, font=FONT_SM, wraplength=520, justify="left"
                 ).pack(anchor="w", padx=18, pady=(16, 8))
        listbox = tk.Listbox(window, bg=SURFACE_2, fg="#cfe0f2", font=MONO_SM, height=10,
                             highlightthickness=1, highlightbackground=LINE)
        listbox.pack(fill="both", expand=True, padx=18)
        row = tk.Frame(window, bg=SURFACE)
        row.pack(fill="x", padx=18, pady=10)
        tag_entry = self.entry(row, None, width=22)
        tag_entry.pack(side="left")
        value_entry = self.entry(row, None, width=24)
        value_entry.pack(side="left", padx=8)

        def add() -> None:
            tag = tag_entry.get().strip()
            value = value_entry.get()
            if ":" not in tag:
                tag = "XMP:" + tag
            listbox.insert("end", f"-{tag}={value}")
            tag_entry.delete(0, "end")
            value_entry.delete(0, "end")

        def apply() -> None:
            args = [item.strip() for item in listbox.get(0, "end") if item.strip()]
            if not args:
                return
            target = filedialog.asksaveasfilename(title="Save copy with written tags",
                                                  initialfile=f"{source.stem}-tagged{source.suffix}")
            if not target:
                return
            out = Path(target)
            shutil.copy2(source, out)
            proc = run_exiftool([*args, "-overwrite_original", str(out)])
            self._log(self.md_log, f"Manual tags written → {out}: {proc.stdout.strip()}"
                                   f"{' | ' + proc.stderr.strip() if proc.stderr.strip() else ''}", "ok")
            window.destroy()

        self.btn(row, "Add", add, "default").pack(side="left")
        row2 = tk.Frame(window, bg=SURFACE)
        row2.pack(fill="x", padx=18, pady=(0, 16))
        self.btn(row2, "Apply to copy", apply, "primary").pack(side="left")
        self.btn(row2, "Close", window.destroy, "ghost").pack(side="left", padx=8)

    # ══ Shr3dder implementation ════════════════════════════════════════════
    def add_shred_targets(self) -> None:
        names = filedialog.askopenfilenames(title="Select files to shred")
        for name in names:
            path = Path(name).expanduser().absolute()
            if path not in self.shred_targets:
                self.shred_targets.append(path)
        self._refresh_shred_list()

    def add_shred_folder(self) -> None:
        folder = filedialog.askdirectory(title="Add all files in folder")
        if not folder:
            return
        root = Path(folder)
        for item in root.rglob("*"):
            if item.is_file() and item not in self.shred_targets:
                self.shred_targets.append(item)
        self._refresh_shred_list()

    def remove_shred_targets(self) -> None:
        for index in reversed(self.shred_list.curselection()):
            if index < len(self.shred_targets):
                self.shred_targets.pop(index)
        self._refresh_shred_list()

    def clear_shred_targets(self) -> None:
        self.shred_targets = []
        self._refresh_shred_list()

    def _refresh_shred_list(self) -> None:
        self.shred_list.delete(0, "end")
        for path in self.shred_targets:
            try:
                size = format_bytes(path.stat().st_size)
            except OSError:
                size = "missing"
            self.shred_list.insert("end", f"{size:>10}  {path}")

    def run_shred(self) -> None:
        if self._shred_running:
            self.shred_status.set("A shred is already running.")
            return
        if not self.shred_targets:
            messagebox.showinfo("No targets", "Add one or more files to the queue first.",
                                parent=self.root)
            return
        if not self._ask_confirmation(
                "Secure erase confirmation",
                f"{len(self.shred_targets)} file(s) will be overwritten and removed. "
                f"Type QUEUE to proceed.",
                "QUEUE"):
            self.shred_status.set("Cancelled — nothing was overwritten.")
            return
        pattern = self.shred_pattern.get()
        passes = int(self.shred_passes.get() or 3)
        unlink = self.shred_unlink.get()
        truncate = self.shred_truncate.get()
        verify = self.shred_verify.get()
        follow = self.shred_follow_links.get()
        targets = list(self.shred_targets)
        self._shred_cancel.clear()
        self._shred_running = True
        self.shred_status.set("Shredding…")
        self.shred_progress.configure(value=0)

        def work() -> list[dict]:
            results = []
            total = len(targets)
            for index, path in enumerate(targets, start=1):
                if self._shred_cancel.is_set():
                    raise RuntimeError("Cancelled by the operator.")
                try:
                    real = path.resolve() if follow else path
                    if real.is_symlink() and not follow:
                        raise RuntimeError("symlink skipped (enable 'Follow symlinks')")
                    head = real.read_bytes()[:16] if real.stat().st_size else b""
                    report = shred_file(
                        real, SHRED_PATTERNS[pattern], passes, unlink, truncate,
                        progress=lambda p, total_p, label: self._queue.put(
                            ("progress", (index, total, p, total_p, label))),
                        cancel=self._shred_cancel)
                    report["name"] = path.name
                    if verify:
                        report["verify"] = shred_verify(real, head) if not unlink else \
                            "File unlinked after shredding."
                    results.append(report)
                except Exception as exc:  # keep going through the queue
                    results.append({"name": path.name, "path": str(path),
                                    "error": str(exc)})
            return results

        def done(results: list[dict]) -> None:
            self._shred_running = False
            self.shred_progress.configure(value=0)
            ok = 0
            for report in results:
                if "error" in report:
                    self._log(self.shred_log, f"✗ {report['name']}: {report['error']}", "danger")
                else:
                    ok += 1
                    self._log(self.shred_log, f"✔ {report['name']} · {report['passes']} passes · "
                                              f"{format_bytes(report['bytes_written'])} written · "
                                              f"{report['seconds']}s", "ok")
                    if report.get("verify"):
                        self._log(self.shred_log, f"  verify: {report['verify']}", "warn")
            if unlink:
                self.shred_targets = [p for p in self.shred_targets if p.exists()]
                self._refresh_shred_list()
            self.shred_status.set(f"Shred complete — {ok}/{len(results)} file(s).")

        def fail(err: Exception) -> None:
            self._shred_running = False
            self.shred_progress.configure(value=0)
            self.shred_status.set(f"Shred failed: {err}")
            self._log(self.shred_log, f"✗ {err}", "danger")

        self._worker(work, done, fail)

    def _on_progress(self, index: int, total: int, pass_index: int,
                      pass_total: int, label: str) -> None:
        """Main-thread handler for Shred progress ticks."""
        fraction = (index - 1 + (pass_index / max(pass_total, 1))) / max(total, 1)
        self.shred_progress.configure(value=max(0.0, min(100.0, fraction * 100)))
        self.shred_status.set(f"File {index}/{total} · {label}")

    def cancel_shred(self) -> None:
        if self._shred_running:
            self._shred_cancel.set()
            self.shred_status.set("Cancelling after the current block…")

    # ══ HideMe implementation ══════════════════════════════════════════════
    def choose_hide_carrier(self) -> None:
        name = filedialog.askopenfilename(title="Select carrier file (any type)")
        if name:
            self.hide_carrier = Path(name).expanduser().absolute()
            self.hide_carrier_label.set(f"Carrier: {self.hide_carrier}")
            self._update_capacity()

    def choose_hide_payload(self) -> None:
        name = filedialog.askopenfilename(title="Select payload file to hide")
        if name:
            self.hide_payload = Path(name).expanduser().absolute()
            self.hide_payload_label.set(f"Payload: {self.hide_payload}")
            self._update_capacity()

    def use_evidence_for_hide(self) -> None:
        if self.selected_path:
            self.hide_carrier = self.selected_path
            self.hide_carrier_label.set(f"Carrier: {self.selected_path}")
            self._update_capacity()

    def _update_capacity(self) -> None:
        carrier, payload = self.hide_carrier, self.hide_payload
        if carrier is None:
            self.hide_capacity.set("")
            return
        bits = self._hide_bits()
        if self.hide_mode.get() == "lsb":
            try:
                capacity, size, mode = lsb_capacity(carrier, bits)
                usage = f" · payload {format_bytes(payload.stat().st_size)}" if payload else ""
                self.hide_capacity.set(
                    f"Pixel capacity at {bits} bit(s)/byte: "
                    f"{format_bytes(capacity)} ({size[0]}×{size[1]} {mode}){usage}")
            except Exception as exc:
                self.hide_capacity.set(f"Capacity unavailable: {exc}")
        else:
            usage = f" · payload {format_bytes(payload.stat().st_size)}" if payload else ""
            self.hide_capacity.set(f"Append mode: container grows by payload + header bytes{usage}.")

    def _hide_bits(self) -> int:
        try:
            value = int(str(self.hide_bits.get()).strip())
        except (TypeError, ValueError):
            return 2
        return value if value in LSB_BITS else 2

    def run_hide_embed(self) -> None:
        carrier, payload = self.hide_carrier, self.hide_payload
        if carrier is None or payload is None:
            messagebox.showinfo("Choose files", "Select both a carrier and a payload.",
                                parent=self.root)
            return
        mode = self.hide_mode.get()
        password = self.hide_passphrase.get() or None
        comment = self.hide_comment.get()
        overwrite = self.hide_overwrite.get()
        out = carrier
        if not overwrite:
            suggestion = filedialog.asksaveasfilename(
                title="Save stego carrier",
                initialfile=f"{carrier.stem}-hidden{carrier.suffix}",
                filetypes=[("Container", f"*{carrier.suffix}" if carrier.suffix else "*.*")])
            if not suggestion:
                return
            out = Path(suggestion)
            if out.resolve() == carrier.resolve():
                overwrite = True
        self.hide_status.set("Embedding payload…")
        bits = self._hide_bits()

        def work() -> dict:
            if mode == "lsb":
                result = lsb_embed(carrier, payload, out, password, bits, comment)
            else:
                result = nb_embed_append(carrier, payload, out, password, comment)
            return result

        def done(result: dict) -> None:
            header = result["header"]
            added = result.get("bytes_added") or result.get("used_bytes", 0)
            lines = [f"carrier      {carrier}  ({format_bytes(carrier.stat().st_size)})",
                     f"payload      {payload.name}  ({header['payload_size']} bytes, "
                     f"sha256 {header.get('payload_sha256', 'n/a')})",
                     f"mode         {header.get('mode')}  cipher {header.get('cipher')}",
                     f"created      {header.get('created')}  comment: {header.get('comment') or '—'}",
                     f"output       {result['out']}  (+{format_bytes(added)})"]
            self._set_text(self.hide_result, "\n".join(lines))
            self.hide_status.set(f"Payload embedded → {result['out']}")
            self._log(self.hide_log, f"Embed [{header.get('mode')}] payload {payload.name} "
                                     f"→ {result['out']}", "ok")

        def fail(err: Exception) -> None:
            self.hide_status.set(f"Embed failed: {err}")
            self._log(self.hide_log, f"✗ embed: {err}", "danger")

        self._worker(work, done, fail)

    def run_hide_check(self) -> None:
        carrier = self.hide_carrier
        if carrier is None:
            messagebox.showinfo("No carrier", "Choose a carrier/container first.", parent=self.root)
            return
        self.hide_status.set("Scanning container…")

        def work() -> dict:
            entries = nb_scan_file(carrier)
            head = carrier.read_bytes()[:64]
            return {"entries": entries, "size": carrier.stat().st_size,
                    "signature": detect_signature(head), "sha256": hash_file(carrier, "sha256")}

        def done(result: dict) -> None:
            entries = result["entries"]
            self.hide_entries = entries
            lines = [f"container  {carrier.name} · {format_bytes(result['size'])} · "
                     f"signature {result['signature'] or 'unknown'}",
                     f"sha256    {result['sha256']}",
                     f"entries   {len(entries)}",
                     ""]
            for index, entry in enumerate(entries, start=1):
                header = entry["header"]
                lines += [f"── entry {index} ──────────────────────────────",
                          f"  offset      {entry['offset']} · marker {entry['magic']!r}"
                          + (f" · {entry['bits']} bit/byte · {entry.get('image_mode')}"
                             if entry.get("pixel_mode") else ""),
                          f"  payload     {header.get('payload_name')} "
                          f"({header.get('payload_size')} bytes)",
                          f"  cipher      {header.get('cipher')}",
                          f"  created     {header.get('created')}",
                          f"  comment     {header.get('comment') or '—'}",
                          f"  carrier     {header.get('carrier_name')} "
                          f"sha256 {str(header.get('carrier_sha256'))[:32]}…",
                          f"  trailer     {'ok' if entry['trailer_ok'] else 'MISSING'}"]
            if not entries:
                lines += ["No HideMe entries were found. Concealment may use a different scheme "
                          "(steghide, LSB, appended archive), or be absent."]
            self._set_text(self.hide_result, "\n".join(lines))
            self.hide_status.set(f"Check complete — {len(entries)} hidden entr(ies).")
            self._log(self.hide_log, f"HideMe check: {len(entries)} entr(ies) in {carrier.name}")

        self._worker(work, done, lambda err: (self.hide_status.set(f"Check failed: {err}"),
                                              self._set_text(self.hide_result, f"Check failed: {err}")))

    def run_hide_extract(self) -> None:
        carrier = self.hide_carrier
        if carrier is None:
            messagebox.showinfo("No carrier", "Choose a container first.", parent=self.root)
            return
        if not self.hide_entries:
            self.run_hide_check()
            return
        password = self.hide_passphrase.get() or None
        folder = filedialog.askdirectory(title="Choose folder for extracted payload(s)")
        if not folder:
            return
        out_dir = Path(folder)
        self.hide_status.set("Extracting payload(s)…")

        def work() -> list[dict]:
            outputs = []
            for entry in self.hide_entries:
                if entry.get("pixel_mode"):
                    target, plain = nb_extract_lsb(carrier, entry, out_dir, password)
                else:
                    target, plain = nb_extract_entry(carrier, entry, out_dir, password)
                outputs.append({"file": str(target), "size": len(plain),
                                "sha256": hashlib.sha256(plain).hexdigest(),
                                "name": entry["header"].get("payload_name")})
            return outputs

        def done(outputs: list[dict]) -> None:
            for item in outputs:
                self._log(self.hide_log, f"✔ extracted {item['name']} → {item['file']} "
                                         f"({format_bytes(item['size'])}, "
                                         f"sha256 {item['sha256'][:16]}…)", "ok")
            self.hide_status.set(f"Extracted {len(outputs)} payload(s) to {out_dir}")

        def fail(err: Exception) -> None:
            self.hide_status.set(f"Extract failed: {err}")
            self._log(self.hide_log, f"✗ extract: {err}", "danger")

        self._worker(work, done, fail)

    # ── refresh states ─────────────────────────────────────────────────────
    def _refresh_target_states(self) -> None:
        self.hide_status.set("Choose a carrier and a payload, then embed.")
        self.shred_status.set("Add files, choose a plan, then shred.")

    # repoint entry for NbCorrupt symlink mode
    _repoint_entry: tk.Entry | None = None


def main() -> None:
    root = tk.Tk()
    app = ForensicsBench(root)
    if not exiftool_path():
        root.after(300, lambda: messagebox.showwarning(
            "ExifTool not found",
            "Install ExifTool (apt install libimage-exiftool-perl) — NbExif extraction, "
            "MetaDelete wipe/restore and sidecars need it. Other tools still work.",
            parent=root))
    if not HAVE_CRYPTO:
        root.after(300, lambda: messagebox.showwarning(
            "cryptography missing",
            "AES encryption in HideMe and NbCorrupt needs: pip install cryptography",
            parent=root))
    root.mainloop()


if __name__ == "__main__":
    main()
