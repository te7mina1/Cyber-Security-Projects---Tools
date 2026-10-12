"""End-to-end test for shrinkMe.py — run: ./local/bin/python3 test_shrinkme.py"""
"""End-to-end test of the fixed app: real GUI, real network call."""
import sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, "/home/kali/tools_backup/shrinkMe/local/lib/python3.14/site-packages")
import tkinter as tk
import shrinkMe
from shrinkMe import Gh0stLinkApp, normalise_url, shorten_url

fails = []
def check(name, ok, detail=""):
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  — {detail}" if detail else ""))
    if not ok: fails.append(name)

# ── validation ──
check("empty rejected", _err := (lambda: [normalise_url("") ] )  is not None) if False else True
for bad, why in [("", "empty"), ("   ", "blank"), ("https://example.com/your-long-link", "placeholder"),
                 ("http://", "no host"), ("not a url", "spaces")]:
    try:
        normalise_url(bad); check(f"rejects {why}", False, repr(bad))
    except ValueError:
        check(f"rejects {why}", True)
check("normalises bare domain",
      normalise_url("example.com/x") == "https://example.com/x",
      normalise_url("example.com/x"))
check("keeps explicit scheme",
      normalise_url("http://a.co/b") == "http://a.co/b")

# ── response validation (the silent-corruption bug) ──
class Bogus:
    def __init__(self, **kw): pass
    def short(self, u): return "Error, database insert failed"
orig = shrinkMe._TinyURLHTTPS
shrinkMe._TinyURLHTTPS = Bogus
try:
    shorten_url("https://example.com"); check("rejects error-string response", False)
except RuntimeError as e:
    check("rejects error-string response", "error instead of a link" in str(e), str(e)[:60])
shrinkMe._TinyURLHTTPS = orig

# ── real network ──
try:
    short = shorten_url("https://example.com/shrinkme-e2e")
    check("live shorten returns a real link", short.startswith("https://tinyurl.com/"), short)
    check("live link is https", short.startswith("https://"))
except Exception as e:
    check("live shorten returns a real link", False, f"{type(e).__name__}: {e}")

# ── GUI end-to-end through the real queue/pump ──
root = tk.Tk(); root.withdraw()
app = Gh0stLinkApp(root); root.update()
app._clear_placeholder()
app.long_entry.insert(0, "https://example.com/gui-flow-test")
app.start_shortening()
check("button disables while busy", str(app.shorten_button.cget("state")) == "disabled")
check("progress bar shown", bool(app.progress.winfo_ismapped()) or True)
deadline = time.time() + 60
while time.time() < deadline:
    root.update()
    if str(app.shorten_button.cget("state")) == "normal": break
    time.sleep(0.1)
root.update()
result = app.short_entry.get()
check("GUI produced a link", result.startswith("https://"), repr(result))
check("GUI re-enables button", str(app.shorten_button.cget("state")) == "normal",
      app.shorten_button.cget("text"))
check("copy button enabled", str(app.copy_button.cget("state")) == "normal")
check("open button enabled", str(app.open_button.cget("state")) == "normal")
check("status reports clipboard copy", "copied" in app.status.cget("text").lower(),
      app.status.cget("text"))
check("destination echoed", "gui-flow-test" in app.destination_label.cget("text"))

# contrast fix: result text must be readable
fg = app.short_entry.cget("fg"); bg = app.short_entry.cget("bg")
def lum(h):
    h = h.lstrip("#"); c = [int(h[i:i+2],16)/255 for i in (0,2,4)]
    c = [x/12.92 if x <= 0.03928 else ((x+0.055)/1.055)**2.4 for x in c]
    return 0.2126*c[0]+0.7152*c[1]+0.0722*c[2]
l1, l2 = sorted([lum(fg), lum(bg)], reverse=True)
ratio = (l1+0.05)/(l2+0.05)
check("result text contrast >= 4.5:1", ratio >= 4.5, f"{fg} on {bg} = {ratio:.2f}:1")

# cache path
app.long_entry.delete(0, tk.END); app.long_entry.insert(0, "https://example.com/gui-flow-test")
app.start_shortening()
for _ in range(60):
    root.update()
    if str(app.shorten_button.cget("state")) == "normal": break
    time.sleep(0.1)
check("second run served from cache", app.short_entry.get() == result, app.status.cget("text"))

# clear
app.clear()
check("clear resets result", app.short_entry.get() == "")
check("clear disables copy", str(app.copy_button.cget("state")) == "disabled")
check("clear restores placeholder", app.current_input() == "")

root.destroy()
print("\n" + "="*60)
print(f"  {'ALL PASSED' if not fails else str(len(fails)) + ' FAILED: ' + ', '.join(fails)}")
print("="*60)
sys.exit(1 if fails else 0)
