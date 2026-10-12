"""Gh0st Link | ShrinkMe — URL shortener desktop GUI.

Run with any Python 3:

    python3 shrinkMe.py

The tool ships its dependencies in ./local, so it transparently re-executes
itself with that virtualenv when pyshorteners is not importable.
"""

from __future__ import annotations

import os
import queue
import re
import sys
import threading
import webbrowser
from collections import OrderedDict
from pathlib import Path
from urllib.parse import urlparse


# ── dependency bootstrap ──────────────────────────────────────────────────
def _bootstrap() -> None:
    """Re-exec into the bundled virtualenv if pyshorteners is missing.

    Without this, `python3 shrinkMe.py` with the system interpreter dies on
    `import pyshorteners` even though the dependency is present in ./local.
    """
    try:
        import pyshorteners  # noqa: F401
        return
    except ModuleNotFoundError:
        pass

    venv = Path(__file__).resolve().parent / "local"
    interpreter = venv / "bin" / "python3"
    if interpreter.is_file() and Path(sys.prefix).resolve() != venv.resolve():
        try:
            os.execv(str(interpreter),
                     [str(interpreter), str(Path(__file__).resolve()), *sys.argv[1:]])
        except OSError as exc:  # fall through to the helpful message
            sys.exit(f"Could not start the bundled interpreter: {exc}")

    sys.exit(
        "pyshorteners is not installed.\n\n"
        f"Run with the bundled virtualenv:\n"
        f"    {interpreter} {Path(__file__).resolve()}\n\n"
        "or install it into your interpreter:\n"
        "    python3 -m pip install pyshorteners"
    )


_bootstrap()

import tkinter as tk  # noqa: E402
from tkinter import messagebox, ttk  # noqa: E402

import pyshorteners  # noqa: E402
import pyshorteners.shorteners.tinyurl as _tinyurl  # noqa: E402


# ── palette ───────────────────────────────────────────────────────────────
BG = "#10141d"
PANEL = "#191f2b"
FIELD = "#111722"
BORDER = "#293344"
TEXT = "#edf2fb"
MUTED = "#8995a8"
ACCENT = "#55e6a5"
ACCENT_HOVER = "#72f0b7"
DANGER = "#ff7b86"
PLACEHOLDER = "#5b6678"

REQUEST_TIMEOUT = 12       # pyshorteners defaults to 2s, which is too tight
MAX_CACHE = 200
PLACEHOLDER_URL = "https://example.com/your-long-link"
VALID_SHORT = re.compile(r"^https?://\S+$", re.IGNORECASE)

url_cache: "OrderedDict[str, str]" = OrderedDict()


class _TinyURLHTTPS(_tinyurl.Shortener):
    """TinyURL over HTTPS — the bundled module posts the destination in clear text."""

    api_url = "https://tinyurl.com/api-create.php"


def shorten_url(long_url: str) -> str:
    """Shorten and validate the provider's reply.

    Several services answer HTTP 200 with an error *string* in the body; the
    bundled client returns that text verbatim, which would otherwise be shown
    to the user as if it were a working short link.
    """
    shortener = _TinyURLHTTPS(timeout=REQUEST_TIMEOUT)
    result = shortener.short(long_url)

    if not isinstance(result, str):
        raise RuntimeError(f"Unexpected response type: {type(result).__name__}")
    result = result.strip()

    if not VALID_SHORT.match(result):
        raise RuntimeError(f"Service replied with an error instead of a link: {result[:120]}")
    return result


def normalise_url(raw: str) -> str:
    """Validate and canonicalise user input. Raises ValueError with a reason."""
    candidate = raw.strip()
    if not candidate:
        raise ValueError("Enter a URL to shorten.")
    if candidate == PLACEHOLDER_URL:
        raise ValueError("Replace the sample URL with your own destination.")
    if " " in candidate:
        raise ValueError("A URL cannot contain spaces.")

    if not candidate.startswith(("http://", "https://")):
        candidate = "https://" + candidate.lstrip("/")

    parsed = urlparse(candidate)
    if not parsed.netloc:
        raise ValueError("That does not look like a URL — a domain name is missing.")
    if "." not in parsed.netloc.split(":")[0] and parsed.netloc != "localhost":
        raise ValueError(f"'{parsed.netloc}' is not a valid domain name.")
    return candidate


class Gh0stLinkApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Gh0st Link | ShrinkMe")
        self.root.geometry("620x590")
        self.root.minsize(540, 540)
        self.root.configure(bg=BG)

        # Tk is not thread-safe and Python 3.12+ rejects after() from a worker
        # thread, so workers only push tuples and _pump() runs on the UI thread.
        self._queue: queue.Queue = queue.Queue()
        self._closing = False
        self._last_long_url = ""

        self.setup_styles()
        self.build_ui()
        self.root.bind("<Control-Return>", lambda _event: self.start_shortening())
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.after(80, self._pump)

    def setup_styles(self):
        style = ttk.Style()
        style.theme_use("clam")

        style.configure(
            "Accent.TButton",
            background=ACCENT,
            foreground="#10141d",
            font=("Segoe UI", 10, "bold"),
            padding=(16, 11),
            borderwidth=0,
        )
        style.map(
            "Accent.TButton",
            background=[("active", ACCENT_HOVER), ("disabled", "#46544f")],
            foreground=[("disabled", "#aab4af")],
        )

        style.configure(
            "Dark.TButton",
            background="#252e3d",
            foreground=TEXT,
            font=("Segoe UI", 10, "bold"),
            padding=(14, 10),
            borderwidth=0,
        )
        style.map("Dark.TButton", background=[("active", "#323e51")])

        style.configure(
            "Horizontal.TProgressbar",
            troughcolor=FIELD,
            background=ACCENT,
            bordercolor=FIELD,
            lightcolor=ACCENT,
            darkcolor=ACCENT,
        )

    def build_ui(self):
        page = tk.Frame(self.root, bg=BG)
        page.pack(fill="both", expand=True, padx=34, pady=26)

        header = tk.Frame(page, bg=BG)
        header.pack(fill="x", pady=(0, 28))

        logo = tk.Label(
            header,
            text="G",
            bg=ACCENT,
            fg=BG,
            font=("Segoe UI", 18, "bold"),
            width=2,
            height=1,
        )
        logo.pack(side="left", padx=(0, 12))

        brand = tk.Frame(header, bg=BG)
        brand.pack(side="left")

        tk.Label(
            brand, text="GH0ST LINK", bg=BG, fg=TEXT,
            font=("Segoe UI", 16, "bold")
        ).pack(anchor="w")
        tk.Label(
            brand, text="URL SHORTENER", bg=BG, fg=MUTED,
            font=("Segoe UI", 8, "bold")
        ).pack(anchor="w", pady=(2, 0))

        tk.Label(
            header,
            text="●  SERVICE READY",
            bg=BG,
            fg=ACCENT,
            font=("Segoe UI", 8, "bold"),
        ).pack(side="right", pady=8)

        tk.Label(
            page,
            text="Make your links\nshort and shareable.",
            bg=BG,
            fg=TEXT,
            font=("Segoe UI", 25, "bold"),
            justify="left",
        ).pack(anchor="w")

        tk.Label(
            page,
            text="Paste a destination URL below to create a compact 000 link.",
            bg=BG,
            fg=MUTED,
            font=("Segoe UI", 10),
        ).pack(anchor="w", pady=(9, 23))

        self.card = tk.Frame(
            page, bg=PANEL, highlightthickness=1, highlightbackground=BORDER
        )
        self.card.pack(fill="x")

        tk.Label(
            self.card, text="DESTINATION URL", bg=PANEL, fg=MUTED,
            font=("Segoe UI", 8, "bold")
        ).pack(anchor="w", padx=20, pady=(19, 8))

        self.long_entry = tk.Entry(
            self.card,
            bg=FIELD,
            fg=TEXT,
            insertbackground=ACCENT,
            relief="flat",
            font=("Segoe UI", 11),
            highlightthickness=1,
            highlightbackground=BORDER,
            highlightcolor=ACCENT,
        )
        self.long_entry.pack(fill="x", padx=20, ipady=12)
        # Real placeholder text (not a value), so the field is never mistaken
        # for the user's input and no magic-string comparison is needed.
        self._placeholder_active = True
        self._show_placeholder()
        self.long_entry.bind("<FocusIn>", self._clear_placeholder)
        self.long_entry.bind("<FocusOut>", self._restore_placeholder)
        self.long_entry.bind("<KeyPress>", self._on_typing)

        buttons = tk.Frame(self.card, bg=PANEL)
        buttons.pack(fill="x", padx=20, pady=18)

        self.shorten_button = ttk.Button(
            buttons,
            text="SHORTEN LINK  →",
            style="Accent.TButton",
            command=self.start_shortening,
        )
        self.shorten_button.pack(side="left")

        ttk.Button(
            buttons, text="CLEAR", style="Dark.TButton", command=self.clear
        ).pack(side="right")

        self.progress = ttk.Progressbar(
            self.card, mode="indeterminate", style="Horizontal.TProgressbar"
        )

        self.status = tk.Label(
            page, text="Ready when you are.", bg=BG, fg=MUTED,
            font=("Segoe UI", 9)
        )
        self.status.pack(anchor="w", pady=(15, 18))

        tk.Label(
            page, text="YOUR SHORT LINK", bg=BG, fg=MUTED,
            font=("Segoe UI", 8, "bold")
        ).pack(anchor="w", pady=(0, 8))

        result = tk.Frame(
            page, bg=PANEL, highlightthickness=1, highlightbackground=BORDER
        )
        result.pack(fill="x")

        # fg was previously the page background colour, rendering the link
        # invisible (1.12:1 contrast) while still being read-only.
        self.short_entry = tk.Entry(
            result,
            bg=FIELD,
            fg=ACCENT,
            insertbackground=ACCENT,
            relief="flat",
            font=("Segoe UI", 12, "bold"),
            state="readonly",
        )
        self.short_entry.pack(fill="x", padx=16, pady=(15, 12), ipady=5)

        self.destination_label = tk.Label(
            result, text="", bg=PANEL, fg=MUTED,
            font=("Segoe UI", 8), anchor="w", justify="left",
            wraplength=520,
        )
        self.destination_label.pack(fill="x", padx=16, pady=(0, 10))

        result_buttons = tk.Frame(result, bg=PANEL)
        result_buttons.pack(fill="x", padx=14, pady=(0, 14))

        self.copy_button = ttk.Button(
            result_buttons,
            text="COPY LINK",
            style="Dark.TButton",
            command=self.copy_link,
            state="disabled",
        )
        self.copy_button.pack(side="left", padx=(0, 8))

        self.open_button = ttk.Button(
            result_buttons,
            text="OPEN IN BROWSER",
            style="Dark.TButton",
            command=self.open_link,
            state="disabled",
        )
        self.open_button.pack(side="left")

        tk.Label(
            page,
            text="Powered by 000  ·  Links are created through the 000 service",
            bg=BG,
            fg="#647084",
            font=("Segoe UI", 8),
        ).pack(side="bottom", anchor="w", pady=(20, 0))

    # ── placeholder handling ───────────────────────────────────────────────
    def _show_placeholder(self) -> None:
        self.long_entry.insert(0, PLACEHOLDER_URL)
        self.long_entry.configure(fg=PLACEHOLDER)
        self._placeholder_active = True

    def _clear_placeholder(self, _event=None) -> None:
        if self._placeholder_active:
            self.long_entry.delete(0, tk.END)
            self.long_entry.configure(fg=TEXT)
            self._placeholder_active = False

    def _restore_placeholder(self, _event=None) -> None:
        if not self.long_entry.get().strip():
            self.long_entry.delete(0, tk.END)
            self._show_placeholder()

    def _on_typing(self, _event=None) -> None:
        if self._placeholder_active:
            self._placeholder_active = False

    def current_input(self) -> str:
        return "" if self._placeholder_active else self.long_entry.get().strip()

    # ── threading ──────────────────────────────────────────────────────────
    def _pump(self) -> None:
        """Drain worker results on the UI thread."""
        try:
            while True:
                kind, payload = self._queue.get_nowait()
                if kind == "done":
                    self._on_success(*payload)
                elif kind == "error":
                    self._on_failure(*payload)
        except queue.Empty:
            pass
        except Exception as exc:  # never let the pump die
            self._on_failure(exc, "")
        finally:
            if not self._closing:
                self.root.after(80, self._pump)

    def _on_close(self) -> None:
        self._closing = True
        self.root.destroy()

    # ── actions ────────────────────────────────────────────────────────────
    def start_shortening(self):
        try:
            long_url = normalise_url(self.current_input())
        except ValueError as exc:
            messagebox.showwarning("URL required", str(exc))
            self.status.configure(text="Ready when you are.", fg=MUTED)
            return

        if self._placeholder_active:
            return

        self._last_long_url = long_url
        if long_url in url_cache:
            self.status.configure(text="Loaded from this session's cache.", fg=ACCENT)
            self._on_success(url_cache[long_url], long_url)
            return

        self._set_busy(True, "Contacting the 000 service…")
        threading.Thread(target=self._worker, args=(long_url,), daemon=True).start()

    def _worker(self, long_url: str) -> None:
        """Runs off the UI thread; communicates only through the queue."""
        try:
            short_url = shorten_url(long_url)
        except Exception as exc:           # noqa: BLE001 - reported on the UI thread
            self._queue.put(("error", (exc, long_url)))
        else:
            self._queue.put(("done", (short_url, long_url)))

    def _set_busy(self, busy: bool, message: str = "") -> None:
        if busy:
            self.shorten_button.configure(state="disabled", text="SHORTENING…")
            self.progress.pack(fill="x", padx=20, pady=(0, 16))
            self.progress.start(12)
            self.status.configure(text=message, fg=ACCENT)
        else:
            self.progress.stop()
            self.progress.pack_forget()
            self.shorten_button.configure(state="normal", text="SHORTEN LINK  →")

    def _on_success(self, short_url: str, long_url: str) -> None:
        self._set_busy(False)
        url_cache[long_url] = short_url
        url_cache.move_to_end(long_url)
        while len(url_cache) > MAX_CACHE:
            url_cache.popitem(last=False)

        self.short_entry.configure(state="normal")
        self.short_entry.delete(0, tk.END)
        self.short_entry.insert(0, short_url)
        # self.short_entry.configure(state="readonly")

        self.destination_label.configure(text=f"→ {long_url}")
        self.copy_button.configure(state="normal")
        self.open_button.configure(state="normal")

        # Clipboard writes are a side effect — say so rather than doing it silently.
        self.root.clipboard_clear()
        self.root.clipboard_append(short_url)
        self.root.update_idletasks()
        self.status.configure(text="Link created and copied to clipboard.", fg=ACCENT)

    def _on_failure(self, error: Exception, long_url: str) -> None:
        self._set_busy(False)
        self.status.configure(text="Could not create the link.", fg=DANGER)
        detail = str(error).strip() or error.__class__.__name__
        messagebox.showerror(
            "Shortening failed",
            f"The 000 service did not return a usable link.\n\n{detail}",
        )

    def copy_link(self):
        short_url = self.short_entry.get()
        if short_url:
            self.root.clipboard_clear()
            self.root.clipboard_append(short_url)
            self.root.update_idletasks()
            self.status.configure(text="Short link copied to clipboard.", fg=ACCENT)

    def open_link(self):
        short_url = self.short_entry.get()
        if short_url:
            webbrowser.open(short_url)

    def clear(self):
        self.long_entry.delete(0, tk.END)
        self.long_entry.configure(fg=PLACEHOLDER)
        self._placeholder_active = True
        self.short_entry.configure(state="normal")
        self.short_entry.delete(0, tk.END)
        self.short_entry.configure(state="readonly")
        self.destination_label.configure(text="")
        self.copy_button.configure(state="disabled")
        self.open_button.configure(state="disabled")
        self.status.configure(text="Ready when you are.", fg=MUTED)
        self.long_entry.focus_set()


if __name__ == "__main__":
    root = tk.Tk()
    app = Gh0stLinkApp(root)
    root.mainloop()
