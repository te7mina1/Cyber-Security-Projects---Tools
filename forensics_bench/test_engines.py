#!/usr/bin/env python3
"""Headless functional test for the NbExif Forensics Bench engines."""
import os
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import app as nb

tmp = Path(tempfile.mkdtemp(prefix="nbtest-"))
results = []


def check(name, condition, detail=""):
    results.append((name, bool(condition), detail))
    print(f"{'PASS' if condition else 'FAIL'}  {name}" + (f"  — {detail}" if detail else ""))


# ── fixtures ─────────────────────────────────────────────────────────────
secret = tmp / "case-notes.txt"
secret.write_bytes("CASE 2026-014 · CONFIDENTIAL PAYMENT DETAILS\n".encode() * 40)
carrier = tmp / "evidence.dat"
carrier.write_bytes(os.urandom(64 * 1024))

# ── 1. crypto round-trip ─────────────────────────────────────────────────
plain = b"confidential payload \x00\xff binary" * 50
sealed, frag = nb.seal_bytes(plain, "correct horse")
check("seal/open round-trip", nb.open_bytes(sealed, "correct horse", frag) == plain)
try:
    nb.open_bytes(sealed, "wrong pass", frag)
    check("wrong passphrase rejected", False)
except RuntimeError as exc:
    check("wrong passphrase rejected", "authentication failed" in str(exc).lower())
sealed_none, frag_none = nb.seal_bytes(b"abc", None)
check("plaintext passthrough", nb.open_bytes(sealed_none, None, frag_none) == b"abc")

# ── 2. HideMe append mode ────────────────────────────────────────────────
res = nb.nb_embed_append(carrier, secret, tmp / "evidence-hidden.dat", "stego-pass", "op note 7")
out = res["out"]
check("append: carrier bytes preserved",
      out.read_bytes()[:64 * 1024] == carrier.read_bytes())
entries = nb.nb_scan_file(out)
check("append: scan finds 1 entry", len(entries) == 1, f"found {len(entries)}")
check("append: trailer intact", entries[0]["trailer_ok"])
check("append: cipher recorded", entries[0]["header"]["cipher"] == "aes-256-cbc+hmac-sha256")
try:
    nb.nb_extract_entry(out, entries[0], tmp, "not-the-passphrase")
    check("append: wrong passphrase blocked", False)
except RuntimeError:
    check("append: wrong passphrase blocked", True)
target, data = nb.nb_extract_entry(out, entries[0], tmp, "stego-pass")
check("append: payload recovered byte-exact", data == secret.read_bytes(),
      f"{len(data)} bytes")

# multiple entries in one container
nb.nb_embed_append(carrier, secret, tmp / "multi.dat", None, "")
multi = tmp / "multi.dat"
with multi.open("ab") as fh:
    fh.write(nb.pack_nb_entry(b"second payload", {"format": "NbHide/1", "payload_name": "b.bin",
                                                  "payload_size": 14, "cipher": "none",
                                                  "cipher_size": 14}))
check("append: multiple entries detected", len(nb.nb_scan_file(multi)) == 2)

# ── 3. HideMe pixel / LSB mode ───────────────────────────────────────────
try:
    from PIL import Image
    Image.new("RGB", (160, 160), (128, 64, 200)).save(tmp / "carrier.png")
    small = tmp / "tiny.bin"
    small.write_bytes(os.urandom(600))
    r = nb.lsb_embed(tmp / "carrier.png", small, tmp / "carrier-stego.png", "lsb-pass", 2, "pixel")
    with Image.open(tmp / "carrier-stego.png") as a, Image.open(tmp / "carrier.png") as b:
        diff = sum(1 for x, y in zip(a.tobytes(), b.tobytes()) if x != y)
        looks_image = a.size == b.size and a.mode == b.mode
    check("lsb: carrier still opens as an image", looks_image)
    check("lsb: low bits actually changed", diff > 0, f"{diff} differing bytes")
    found = nb.nb_scan_file(tmp / "carrier-stego.png")
    check("lsb: scan detects pixel entry",
          len(found) == 1 and found[0].get("pixel_mode"), f"{len(found)} entries")
    check("lsb: bit depth recovered", found and found[0]["bits"] == 2)
    t2, d2 = nb.nb_extract_lsb(tmp / "carrier-stego.png", found[0], tmp, "lsb-pass")
    check("lsb: payload recovered byte-exact", d2 == small.read_bytes(), f"{len(d2)} bytes")
    # capacity guard: a payload far larger than the carrier can hold
    (tmp / "huge.bin").write_bytes(os.urandom(200 * 1024))
    try:
        nb.lsb_embed(tmp / "carrier.png", tmp / "huge.bin", tmp / "x.png", None, 1, "")
        check("lsb: capacity guard triggers", False)
    except RuntimeError as exc:
        check("lsb: capacity guard triggers", "does not fit" in str(exc))
except ImportError:
    check("lsb tests skipped", True, "Pillow missing")

# ── 4. Shr3dder ──────────────────────────────────────────────────────────
victim = tmp / "burn-after-reading.txt"
victim.write_bytes(b"SECRET KEY MATERIAL " * 5000)
original = victim.read_bytes()
before_hash = nb.hash_file(victim)
report = nb.shred_file(victim, "doe", 3, unlink=True, truncate=False)
check("shred: 3 passes written", report["passes"] == 3)
check("shred: bytes written = size × passes",
      report["bytes_written"] == report["size"] * 3,
      f"{report['bytes_written']} vs {report['size'] * 3}")
check("shred: file unlinked", not victim.exists())
victim.write_bytes(original)
rep2 = nb.shred_file(victim, "zero", 1, unlink=False, truncate=True)
check("shred: truncate leaves zero length", victim.stat().st_size == 0)
check("shred: content destroyed", victim.read_bytes() != original)
plan = nb.shred_pass_plan("gutmann", 3)
check("shred: gutmann = 35 passes", len(plan) == 35)
check("shred: custom N passes", len(nb.shred_pass_plan("custom", 7)) == 7)

# ── 5. NbCorrupt ─────────────────────────────────────────────────────────
doc = tmp / "statement.pdf"
doc.write_bytes(b"%PDF-1.4\n" + b"financial rows\n" * 2000)
r = nb.corrupt_random(doc, tmp / "random.pdf", 5.0, seed=7)
size = doc.stat().st_size
rate = r["corrupted_bytes"] / size * 100
check("corrupt: random modifies output", r["sha256"] != nb.hash_file(doc))
check("corrupt: ~5% of bytes flipped", 3.0 < rate < 7.0,
      f"{r['corrupted_bytes']}/{size} = {rate:.2f}%")
check("corrupt: source untouched", doc.read_bytes().startswith(b"%PDF-1.4"))
r = nb.corrupt_magic(doc, tmp / "magic.pdf")
check("corrupt: magic destruction identified", r["identified_as"] == "PDF document")
check("corrupt: output unidentifiable",
      nb.detect_signature((tmp / "magic.pdf").read_bytes()[:16]) != "PDF document")
r = nb.corrupt_truncate(doc, tmp / "trunc.pdf", 500)
check("corrupt: truncate honoured", (tmp / "trunc.pdf").stat().st_size == 500)
r = nb.corrupt_encrypt(doc, tmp / "sealed.nbc", "aes-pass")
check("corrupt: AES container written", (tmp / "sealed.nbc").stat().st_size > 500)
r = nb.corrupt_decrypt(tmp / "sealed.nbc", tmp / "recovered.pdf", "aes-pass")
check("corrupt: decrypt restores byte-exact", r["verified"] is True)
try:
    nb.corrupt_decrypt(tmp / "sealed.nbc", tmp / "bad.pdf", "nope")
    check("corrupt: wrong passphrase rejected", False)
except RuntimeError:
    check("corrupt: wrong passphrase rejected", True)

# ── 6. carrier_end (anti-carve) ──────────────────────────────────────────
carrier_end_found = nb.carrier_end(tmp / "carrier.png")
check("carrier_end: PNG IEND located",
      carrier_end_found[0] == (tmp / "carrier.png").stat().st_size,
      f"{carrier_end_found}")
appended = b"APPENDED CARVER PAYLOAD" * 50
with (tmp / "appended.pdf").open("wb") as fh:
    fh.write(b"%PDF-1.4\nbody\n%%EOF\n")
    fh.write(appended)
end, label = nb.carrier_end(tmp / "appended.pdf")
check("carrier_end: PDF EOF located before appended data",
      end is not None and (tmp / "appended.pdf").stat().st_size - end == len(appended),
      f"{label}, tail={((tmp / 'appended.pdf').stat().st_size - end) if end else '?'} "
      f"(expected {len(appended)})")

# ── 7. ExifTool driver ───────────────────────────────────────────────────
proc = nb.run_exiftool(["-json", "-G", "-a", "-u", "-s", "-struct", str(tmp / "carrier.png")])
check("exiftool: JSON pass returns data", proc.returncode == 0 and proc.stdout.strip().startswith("["))
proc = nb.run_exiftool(["-G", "-a", "-u", "-s", "-struct", str(tmp / "carrier.png")])
rows = [l for l in proc.stdout.splitlines() if l.strip()]
check("exiftool: text pass returns tag rows", len(rows) > 5, f"{len(rows)} rows")
import re as _re
parsed = [(_re.match(r"^(\S+?)\s\s+(.*)$", l) or [None, l.strip(), ""]) for l in rows]
check("exiftool: tag/value lines parse cleanly",
      all(m and m.group(1) for m in parsed), f"{sum(1 for m in parsed if m and m.group(1))} parsed")
check("exiftool: version detected", nb.exiftool_version() != "not installed",
      nb.exiftool_version())

# ── summary ──────────────────────────────────────────────────────────────
passed = sum(1 for _, ok, _ in results if ok)
print("\n" + "=" * 62)
print(f"  {passed}/{len(results)} checks passed")
print("=" * 62)
if passed != len(results):
    for name, ok, detail in results:
        if not ok:
            print(f"  FAILED: {name} — {detail}")
shutil.rmtree(tmp, ignore_errors=True)
sys.exit(0 if passed == len(results) else 1)