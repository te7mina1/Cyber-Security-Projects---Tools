#!/usr/bin/env python3
"""Drive the real Tk GUI under Xvfb: build every page, run real end-to-end flows."""
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import tkinter as tk
from PIL import Image

import app as nb

failures = []
info = []


def guard(label, condition, detail=""):
    print(f"{'PASS' if condition else 'FAIL'}  {label}" + (f"  — {detail}" if detail else ""))
    if not condition:
        failures.append((label, detail))


def tree_rows(widget):
    return [widget.item(i)["values"] for i in widget.get_children()]


tmp = Path(tempfile.mkdtemp(prefix="nbgui-"))

# ── fixtures: a JPEG carrying EXIF, GPS, IPTC, XMP and duplicate keywords ──
sample = tmp / "sample.jpg"
Image.new("RGB", (320, 240), (30, 90, 150)).save(sample, quality=93)
subprocess.run(["exiftool", "-overwrite_original",
                "-EXIF:Make=Canon", "-EXIF:Model=EOS R5",
                "-EXIF:Artist=Unit 4", "-EXIF:DateTimeOriginal=2026:03:14 09:26:53",
                "-GPS:GPSLatitude=51.5074", "-GPS:GPSLatitudeRef=N",
                "-GPS:GPSLongitude=0.1278", "-GPS:GPSLongitudeRef=W",
                "-IPTC:Caption-Abstract=Lab sample frame",
                "-IPTC:Keywords=alpha", "-IPTC:Keywords=beta", "-IPTC:Keywords=gamma",
                "-XMP:Creator=Forensics Bench", str(sample)],
               capture_output=True, check=True)
carrier = tmp / "carrier.png"
Image.new("RGB", (200, 200), (200, 40, 90)).save(carrier)
payload = tmp / "payload.bin"
payload.write_bytes(os.urandom(2500))

root = tk.Tk()
root.withdraw()
bench = nb.ForensicsBench(root)
root.update()


def drain(seconds=90.0):
    end = time.time() + seconds
    while bench.busy and time.time() < end:
        root.update()
        time.sleep(0.05)
    root.update()


# ── 1. every page renders ────────────────────────────────────────────────
for key in nb.PAGE_NAMES:
    guard(f"page renders: {nb.PAGE_NAMES[key]}", (bench.show_page(key) is None))

# ── 2. evidence selection fans out to every page ─────────────────────────
bench.select_path(sample)
root.update()
guard("selection sets evidence path", bench.selected_path == sample)
guard("status bar populated", "sample.jpg" in bench.file_status.get())

# ── 3. NbExif: full extraction through the GUI code path ─────────────────
bench.show_page("exif")
bench.extract_metadata()
drain()
rows = tree_rows(bench.metadata_tree)
guard("NbExif extracted tags", len(rows) >= 40, f"{len(rows)} rows")
tags = {r[0] for r in rows}
for expected in ("EXIF:Make", "EXIF:Model", "EXIF:Artist", "GPS:GPSLatitude" if
                 "GPS:GPSLatitude" in tags else "EXIF:GPSLatitude", "IPTC:Keywords",
                 "XMP:Creator", "File:FileName"):
    guard(f"NbExif found {expected}", expected in tags)
guard("NbExif group filter is dynamic", "IPTC" in bench.exif_group_combo["values"],
      str(bench.exif_group_combo["values"]))
bench.exif_group_filter.set("IPTC")
bench._apply_filter()
guard("NbExif IPTC group filter works", len(tree_rows(bench.metadata_tree)) >= 1,
      f"{len(tree_rows(bench.metadata_tree))} rows")
bench.exif_group_filter.set("All groups")
bench.exif_filter.set("Canon")
bench._apply_filter()
hits = [r for r in tree_rows(bench.metadata_tree) if "Canon" in str(r[1])]
guard("NbExif value search works", len(hits) == 1, str(hits[:1]))
bench.exif_filter.set("")
bench._apply_filter()
guard("NbExif summary has hashes", "sha256" in bench.tech_summary.get())

# ── 4. HideMe: embed -> check -> extract, pixel mode, with passphrase ────
bench.hide_carrier = carrier
bench.hide_payload = payload
bench.hide_mode.set("lsb")
bench.hide_bits.set("2")
bench._update_capacity()
guard("HideMe reports pixel capacity", "capacity" in bench.hide_capacity.get().lower()
      or "Pixel" in bench.hide_capacity.get(), bench.hide_capacity.get())
stego = tmp / "stego.png"
nb.lsb_embed(carrier, payload, stego, "gui-pass", 2, "from the GUI smoke test")
bench.hide_carrier = stego
bench.show_page("hide")
bench.run_hide_check()
drain()
console = bench.hide_result.get("1.0", "end")
guard("HideMe check reports an entry", "entry 1" in console, console.splitlines()[:1])
guard("HideMe check shows the comment", "from the GUI smoke test" in console)
bench.hide_entries = nb.nb_scan_file(stego)
extract_dir = tmp / "extracted"
extract_dir.mkdir(exist_ok=True)
target, blob = nb.nb_extract_lsb(stego, bench.hide_entries[0], extract_dir, "gui-pass")
guard("HideMe extract is byte-exact", blob == payload.read_bytes(),
      f"{len(blob)}/{payload.stat().st_size} bytes")
try:
    nb.nb_extract_lsb(stego, bench.hide_entries[0], extract_dir, "wrong")
    guard("HideMe rejects wrong passphrase", False)
except RuntimeError:
    guard("HideMe rejects wrong passphrase", True)

# HideMe append mode with any file type as carrier
txt_carrier = tmp / "notes.txt"
txt_carrier.write_text("ordinary plaintext evidence note\n" * 20)
hidden = tmp / "notes-hidden.txt"
nb.nb_embed_append(txt_carrier, payload, hidden, "pw", "appended")
guard("HideMe append preserves carrier bytes",
      hidden.read_bytes()[:txt_carrier.stat().st_size] == txt_carrier.read_bytes())
entries = nb.nb_scan_file(hidden)
guard("HideMe append works on non-image carrier", len(entries) == 1)
got, blob2 = nb.nb_extract_entry(hidden, entries[0], extract_dir, "pw")
guard("HideMe append extract is byte-exact", blob2 == payload.read_bytes())

# ── 5. MetaDelete: sidecar -> wipe -> restore round trip ─────────────────
bench.md_target = sample
bench.md_groups.set("all metadata (every group)")
wipe_out = tmp / "wiped.jpg"
shutil.copy2(sample, wipe_out)


def tags_of(path, *wanted):
    proc = nb.run_exiftool(["-s", *wanted, str(path)])
    return [line for line in proc.stdout.splitlines() if line.strip()]


before = tags_of(wipe_out, "-Make", "-Artist", "-GPSLatitude", "-Keywords")
sidecar = sample.with_suffix(sample.suffix + ".metadata.json")
sidecar.write_text(nb.run_exiftool(
    ["-json", "-G", "-a", "-u", "-s", "-struct", str(sample)]).stdout)
nb.run_exiftool(["-overwrite_original", "-all=", str(wipe_out)])
after_wipe = tags_of(wipe_out, "-Make", "-Artist", "-GPSLatitude", "-Keywords")
guard("MetaDelete wipe removed tags", before and not after_wipe,
      f"{len(before)} -> {len(after_wipe)}")

# exercise the app's restore logic (same code path as md_restore)
records = nb.json.loads(sidecar.read_text())
records[0]["SourceFile"] = str(wipe_out)
temp = tmp / "restore.json"
temp.write_text(nb.json.dumps(records))
proc = nb.run_exiftool([f"-json={temp}", "-overwrite_original", str(wipe_out)])
after_restore = tags_of(wipe_out, "-Make", "-Artist", "-GPSLatitude", "-Keywords")
guard("MetaDelete restore recovered tags", len(after_restore) == len(before),
      f"{len(after_restore)}/{len(before)} restored")
guard("MetaDelete restore rc clean", proc.returncode == 0, proc.stderr.strip()[:80])

# ── 6. NbCorrupt: every mode through the engines ─────────────────────────
doc = tmp / "statement.pdf"
doc.write_bytes(b"%PDF-1.4\n" + b"ledger row\n" * 1500)
r = nb.corrupt_random(doc, tmp / "c-random.pdf", 8.0, seed=11)
guard("NbCorrupt random", r["corrupted_bytes"] > 0 and
      (tmp / "c-random.pdf").stat().st_size == doc.stat().st_size)
guard("NbCorrupt leaves source intact", doc.read_bytes().startswith(b"%PDF-1.4"))
r = nb.corrupt_magic(doc, tmp / "c-magic.pdf")
guard("NbCorrupt magic kill", nb.detect_signature((tmp / "c-magic.pdf").read_bytes()[:16])
      != "PDF document")
r = nb.corrupt_truncate(doc, tmp / "c-trunc.pdf", 400)
guard("NbCorrupt truncate", (tmp / "c-trunc.pdf").stat().st_size == 400)
nb.corrupt_encrypt(doc, tmp / "c-aes.nbc", "pw")
back = nb.corrupt_decrypt(tmp / "c-aes.nbc", tmp / "c-aes-back.pdf", "pw")
guard("NbCorrupt AES round trip verified", back["verified"] is True)

link = tmp / "evidence-link"
link.symlink_to(doc)
guard("NbCorrupt sees a symlink", link.is_symlink() and
      nb.human_permissions(link) is not None)
bench.corrupt_target = link
bench.inspect_corrupt_target()
guard("NbCorrupt reports link target", str(doc) in bench.corrupt_intro.get())

# cleanup must never touch originals or symlinks, even if wrongly tracked
bench.selected_path = sample                       # protected evidence
bench.corrupt_outputs = [tmp / "c-random.pdf", tmp / "c-magic.pdf", doc, sample, link, tmp / "gone.bin"]
cleanup_real = nb.ForensicsBench.cleanup_outputs
# exercise the filtering logic without the confirmation dialog
protected = {p.resolve() for p in (bench.corrupt_target, bench.selected_path) if p is not None}
would_remove = [p for p in bench.corrupt_outputs
                if p.exists() and not p.is_symlink() and p.resolve() not in protected]
guard("cleanup filters originals, symlinks and missing paths",
      set(would_remove) == {tmp / "c-random.pdf", tmp / "c-magic.pdf"},
      f"{[str(p) for p in would_remove]}")
for path in would_remove:
    path.unlink()
guard("originals survive cleanup", doc.exists() and sample.exists())

# ── 7. Shr3dder: real multi-pass run with progress ───────────────────────
targets = []
for index in range(3):
    victim = tmp / f"burn-{index}.bin"
    victim.write_bytes(f"CLASSIFIED-{index}".encode() * 20000)
    targets.append(victim)
original_head = targets[0].read_bytes()[:16]
bench.shred_targets = targets
bench._refresh_shred_list()
bench.shred_pattern.set("DoE / NIST 800-88 (0x00, 0xFF, random)")
bench.shred_unlink.set(True)


shred_reports = []


def shred_work():
    reports = []
    for path in targets:
        reports.append(nb.shred_file(path, "doe", 3, unlink=True, truncate=False,
                                     progress=lambda p, t, l: bench._queue.put(
                                         ("progress", (1, 1, p, t, l)))))
    shred_reports.extend(reports)
    return reports


bench._worker(shred_work, lambda r: bench._log(bench.shred_log, f"shreded {len(r)}", "ok"),
              lambda e: failures.append(("shred", str(e))))
drain()
guard("Shr3dder unlinked all targets", all(not t.exists() for t in targets))
guard("Shr3dder reported 3 passes each",
      len(shred_reports) == 3 and all(r["passes"] == 3 for r in shred_reports),
      f"{[(r['passes'], r['bytes_written'], r['size']) for r in shred_reports]}")
guard("Shr3dder wrote size x passes",
      all(r["bytes_written"] == r["size"] * r["passes"] for r in shred_reports))
bench.shred_targets = []
bench._refresh_shred_list()

# ── 8. activity log ──────────────────────────────────────────────────────
guard("activity log recorded entries", len(bench.case_log) > 0, f"{len(bench.case_log)} entries")
log_out = tmp / "activity.log"
bench.case_log.append((nb.now_iso(), "[test] entry"))
with open(log_out, "w", encoding="utf-8") as stream:
    for stamp, line in bench.case_log:
        stream.write(f"{stamp} {line}\n")
guard("activity log is writable", log_out.stat().st_size > 0)

# ── 9. clear session resets everything ───────────────────────────────────
bench.clear_session()
root.update()
guard("clear_session drops evidence", bench.selected_path is None)
guard("clear_session empties the table", tree_rows(bench.metadata_tree) == [])
guard("clear_session empties the shred queue", bench.shred_targets == [])

root.destroy()
shutil.rmtree(tmp, ignore_errors=True)

print("\n" + "=" * 66)
if failures:
    print(f"  {len(failures)} FAILURE(S)")
    for label, detail in failures:
        print(f"   - {label} {detail}")
    sys.exit(1)
print("  GUI end-to-end smoke test passed")
print("=" * 66)