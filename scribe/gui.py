"""
scribe.gui
==========
Main application window for SCRIBE.

Architecture
------------
ScribeApp          — top-level controller; owns state and wires everything
  NavBar           — title, mode selector, buttons, search
  EditorPane       — input text area
  OutputPane       — scrollable output with find/highlight
  StatusBar        — progress, result count, file info
"""

from __future__ import annotations

import logging
import sys
import threading
import tkinter as tk
import tkinter.font as tkfont
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Callable

from scribe import __version__
from scribe.analysis import (
    AnalysisConfig,
    ExtractionResult,
    Mode,
    analyse,
    extract_strings_from_bytes,
    load_wordlist,
)
from scribe.export import export_csv, export_json, export_txt
from scribe.theme import ThemeManager

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_MODES: list[tuple[str, Mode]] = [
    ("Normal",  Mode.NORMAL),
    ("Strict",  Mode.STRICT),
    ("ASM",     Mode.ASM),
    ("UASM",    Mode.UASM),
    ("Paths",   Mode.PATHS),
    ("URL",     Mode.URL),
    ("Game",    Mode.GAME),
]

_EXPORT_TYPES = [
    ("Plain Text",        "*.txt",  "txt"),
    ("JSON",              "*.json", "json"),
    ("CSV (spreadsheet)", "*.csv",  "csv"),
]

_BATCH_SIZE = 80     # items per UI-update batch
_BATCH_MS   = 4      # ms delay between batches


# ---------------------------------------------------------------------------
# Reusable widget helpers
# ---------------------------------------------------------------------------

def _flat_button(
    parent: tk.Widget,
    text: str,
    command: Callable,
    *,
    padx: int = 14,
    pady: int = 6,
    font_args: tuple,
    bg: str,
    fg: str,
    active_bg: str,
) -> tk.Button:
    btn = tk.Button(
        parent,
        text=text,
        command=command,
        relief="flat",
        bd=0,
        padx=padx,
        pady=pady,
        font=font_args,
        bg=bg,
        fg=fg,
        activebackground=active_bg,
        activeforeground=fg,
        cursor="hand2",
    )
    return btn


# ---------------------------------------------------------------------------
# StatusBar
# ---------------------------------------------------------------------------

class StatusBar(tk.Frame):
    """Fixed-height bar at the bottom of the window."""

    def __init__(self, parent: tk.Widget, theme: ThemeManager) -> None:
        super().__init__(parent, height=28, bd=0)
        self.theme = theme
        self.pack_propagate(False)

        self._lbl_left  = tk.Label(self, text="Ready", anchor="w", font=theme.ui_font(9))
        self._lbl_left.pack(side=tk.LEFT, padx=12)

        self._lbl_right = tk.Label(self, text="", anchor="e", font=theme.ui_font(9))
        self._lbl_right.pack(side=tk.RIGHT, padx=12)

        self._progress = ttk.Progressbar(self, mode="determinate", length=120)
        self._progress.pack(side=tk.RIGHT, padx=8)
        self._progress.pack_forget()           # hidden until in use

    # ------------------------------------------------------------------
    def set_status(self, text: str) -> None:
        self._lbl_left.config(text=text)

    def set_info(self, text: str) -> None:
        self._lbl_right.config(text=text)

    def show_progress(self, value: int) -> None:
        self._progress["value"] = value
        if value == 0:
            self._progress.pack_forget()
        else:
            self._progress.pack(side=tk.RIGHT, padx=8)

    def apply_theme(self) -> None:
        p = self.theme.palette
        for w in [self, self._lbl_left, self._lbl_right]:
            w.configure(bg=p.bg)
        self._lbl_left.configure(fg=p.subtext)
        self._lbl_right.configure(fg=p.subtext)


# ---------------------------------------------------------------------------
# OutputPane
# ---------------------------------------------------------------------------

class OutputPane(tk.Frame):
    """Scrollable output text widget with search-highlight support."""

    def __init__(self, parent: tk.Widget, theme: ThemeManager) -> None:
        super().__init__(parent, bd=0, highlightthickness=1)
        self.theme = theme

        self._text = tk.Text(
            self,
            font=theme.code_font(12),
            bd=0,
            padx=16,
            pady=12,
            wrap=tk.NONE,
            undo=False,
            state=tk.DISABLED,
            cursor="arrow",
        )
        _sy = tk.Scrollbar(self, orient=tk.VERTICAL,   command=self._text.yview)
        _sx = tk.Scrollbar(self, orient=tk.HORIZONTAL, command=self._text.xview)
        self._text.configure(yscrollcommand=_sy.set, xscrollcommand=_sx.set)

        _sy.pack(side=tk.RIGHT,  fill=tk.Y)
        _sx.pack(side=tk.BOTTOM, fill=tk.X)
        self._text.pack(side=tk.LEFT, expand=True, fill=tk.BOTH)

        self._text.tag_configure("find",         background="#f59e0b", foreground="#000000")
        self._text.tag_configure("find_current", background="#ef4444", foreground="#ffffff")

        self._current_match: int = -1
        self._match_positions: list[str] = []

    # ------------------------------------------------------------------
    # Content management
    # ------------------------------------------------------------------

    def clear(self) -> None:
        self._text.configure(state=tk.NORMAL)
        self._text.delete("1.0", tk.END)
        self._text.configure(state=tk.DISABLED)
        self._match_positions = []
        self._current_match = -1

    def append(self, chunk: str) -> None:
        self._text.configure(state=tk.NORMAL)
        self._text.insert(tk.END, chunk)
        self._text.configure(state=tk.DISABLED)

    def get_all_text(self) -> str:
        return self._text.get("1.0", tk.END)

    # ------------------------------------------------------------------
    # Search / highlight
    # ------------------------------------------------------------------

    def highlight_query(self, query: str) -> int:
        """Highlight all occurrences of *query*.  Returns match count."""
        self._text.tag_remove("find",         "1.0", tk.END)
        self._text.tag_remove("find_current", "1.0", tk.END)
        self._match_positions = []
        self._current_match = -1
        if not query:
            return 0
        pos = "1.0"
        while True:
            pos = self._text.search(query, pos, stopindex=tk.END, nocase=True)
            if not pos:
                break
            end = f"{pos}+{len(query)}c"
            self._text.tag_add("find", pos, end)
            self._match_positions.append(pos)
            pos = end
        return len(self._match_positions)

    def jump_to_match(self, direction: int = 1) -> tuple[int, int]:
        """
        Advance to the next (direction=1) or previous (direction=-1) match.
        Returns (current_1indexed, total).
        """
        total = len(self._match_positions)
        if total == 0:
            return 0, 0

        # Remove old current highlight
        if self._current_match >= 0:
            old = self._match_positions[self._current_match]
            self._text.tag_remove("find_current", old, f"{old}+{len(self._get_query())}c")
            self._text.tag_add("find", old, f"{old}+{len(self._get_query())}c")

        self._current_match = (self._current_match + direction) % total
        pos = self._match_positions[self._current_match]
        q   = self._get_query()
        self._text.tag_remove("find", pos, f"{pos}+{len(q)}c")
        self._text.tag_add("find_current", pos, f"{pos}+{len(q)}c")
        self._text.see(pos)
        return self._current_match + 1, total

    def _get_query(self) -> str:
        # Hacky but avoids circular reference; overridden dynamically below.
        return ""

    # ------------------------------------------------------------------
    def apply_theme(self) -> None:
        p = self.theme.palette
        self.configure(highlightbackground=p.border)
        self._text.configure(
            bg=p.card, fg=p.text, insertbackground=p.text,
            selectbackground=p.accent, selectforeground="#ffffff",
        )
        self._text.tag_configure("find",         background=p.highlight, foreground="#000000")
        self._text.tag_configure("find_current", background=p.danger,    foreground="#ffffff")


# ---------------------------------------------------------------------------
# NavBar
# ---------------------------------------------------------------------------

class NavBar(tk.Frame):
    """Top navigation bar: title, mode pills, action buttons, search."""

    def __init__(
        self,
        parent: tk.Widget,
        theme: ThemeManager,
        mode_var: tk.IntVar,
        on_mode_change: Callable,
        on_open: Callable,
        on_export: Callable,
        on_toggle_theme: Callable,
        on_copy: Callable,
        search_var: tk.StringVar,
        on_search_next: Callable,
        on_search_prev: Callable,
    ) -> None:
        super().__init__(parent, height=64, bd=0)
        self.theme      = theme
        self.mode_var   = mode_var
        self._rbs: list[tk.Radiobutton] = []

        self.pack_propagate(False)

        # --- Title
        self._title = tk.Label(self, text="SCRIBE", font=theme.ui_font(18, "bold"))
        self._title.pack(side=tk.LEFT, padx=(24, 6))

        ver = tk.Label(self, text=f"v{__version__}", font=theme.ui_font(8))
        ver.pack(side=tk.LEFT, padx=(0, 20))
        self._ver_lbl = ver

        # --- Mode pills
        pill_frame = tk.Frame(self, bd=0)
        pill_frame.pack(side=tk.LEFT)
        self._pill_frame = pill_frame
        for label, val in _MODES:
            rb = tk.Radiobutton(
                pill_frame,
                text=label,
                variable=mode_var,
                value=int(val),
                command=on_mode_change,
                font=theme.ui_font(9, "bold"),
                indicatoron=0,
                bd=0,
                padx=11,
                pady=5,
                relief="flat",
                cursor="hand2",
            )
            rb.pack(side=tk.LEFT, padx=2)
            self._rbs.append(rb)

        # --- Right-side controls
        right = tk.Frame(self, bd=0)
        right.pack(side=tk.RIGHT, padx=16)
        self._right = right

        # Search
        search_frame = tk.Frame(right, bd=0)
        search_frame.pack(side=tk.RIGHT, padx=(12, 0))
        self._search_frame = search_frame

        self._search_entry = tk.Entry(
            search_frame,
            textvariable=search_var,
            font=theme.ui_font(10),
            bd=0,
            highlightthickness=1,
            width=22,
        )
        self._search_entry.pack(side=tk.LEFT, ipady=4, padx=(0, 2))
        self._search_entry.bind("<Return>",          lambda _e: on_search_next())
        self._search_entry.bind("<Shift-Return>",    lambda _e: on_search_prev())

        self._lbl_match = tk.Label(search_frame, text="", font=theme.ui_font(9), width=7, anchor="w")
        self._lbl_match.pack(side=tk.LEFT)

        # Action buttons
        btn_data = [
            ("Open File", on_open,          True),
            ("Export",    on_export,         False),
            ("Copy",      on_copy,           False),
            ("◐",         on_toggle_theme,   False),
        ]
        self._btns: dict[str, tk.Button] = {}
        for label, cmd, primary in btn_data:
            btn = _flat_button(
                right,
                label,
                cmd,
                font_args=theme.ui_font(9, "bold"),
                bg=theme.palette.accent if primary else theme.palette.nav,
                fg="#ffffff" if primary else theme.palette.text,
                active_bg=theme.palette.hover,
            )
            btn.pack(side=tk.RIGHT, padx=3)
            self._btns[label] = btn

    # ------------------------------------------------------------------
    def set_match_info(self, current: int, total: int, query: str) -> None:
        if not query:
            self._lbl_match.config(text="")
        elif total == 0:
            self._lbl_match.config(text="no match")
        else:
            self._lbl_match.config(text=f"{current}/{total}")

    def focus_search(self) -> None:
        self._search_entry.focus_set()

    # ------------------------------------------------------------------
    def apply_theme(self, active_mode: int) -> None:
        p = self.theme.palette
        for w in [self, self._pill_frame, self._right, self._search_frame, self._ver_lbl]:
            w.configure(bg=p.nav)
        self._title.configure(bg=p.nav, fg=p.text)
        self._ver_lbl.configure(bg=p.nav, fg=p.subtext)
        self._lbl_match.configure(bg=p.nav, fg=p.subtext)
        self._search_entry.configure(
            bg=p.bg, fg=p.text, insertbackground=p.text,
            highlightbackground=p.border, highlightcolor=p.accent,
        )
        for rb in self._rbs:
            is_active = self.mode_var.get() == int(rb["value"])
            rb.configure(
                bg=p.accent if is_active else p.nav,
                fg="#ffffff"  if is_active else p.text,
                activebackground=p.hover,
                activeforeground=p.text,
                selectcolor=p.accent,
            )
        self._btns["Open File"].configure(bg=p.accent, fg="#ffffff", activebackground=p.accent)
        for label in ("Export", "Copy", "◐"):
            self._btns[label].configure(bg=p.nav, fg=p.text, activebackground=p.hover)


# ---------------------------------------------------------------------------
# ScribeApp — main controller
# ---------------------------------------------------------------------------

class ScribeApp:
    """
    Top-level application controller.

    Owns all state, creates child widgets, and wires them together.
    """

    def __init__(self, root: tk.Tk) -> None:
        self.root   = root
        self.theme  = ThemeManager("dark")
        self._setup_window()

        # --- Application state
        self._raw_cache:   str | None   = None   # pre-extracted text from binary
        self._binary:      bytes | None = None   # original raw bytes
        self._source_path: str          = ""
        self._results:     list[ExtractionResult] = []
        self._is_busy:     bool         = False

        self._mode_var   = tk.IntVar(value=int(Mode.NORMAL))
        self._search_var = tk.StringVar()
        self._search_var.trace_add("write", self._on_search_changed)

        # --- Wordlist
        self._wordlist = load_wordlist()

        # --- Widgets
        self._build_ui()
        self._apply_theme()

        # --- Global bindings
        self.root.bind("<Control-f>",   lambda _e: self._navbar.focus_search())
        self.root.bind("<Control-o>",   lambda _e: self._cmd_open())
        self.root.bind("<Control-s>",   lambda _e: self._cmd_export())
        self.root.bind("<Control-c>",   lambda _e: None)   # let default work in text
        self.root.bind("<Escape>",      lambda _e: self._search_var.set(""))

        logger.info("SCRIBE %s initialised", __version__)

    # ------------------------------------------------------------------
    # Window setup
    # ------------------------------------------------------------------

    def _setup_window(self) -> None:
        self.root.title(f"SCRIBE  —  Binary String Extractor")
        self.root.geometry("1280x820")
        self.root.minsize(860, 560)
        try:
            from ctypes import windll
            windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        p = self.theme.palette

        self._navbar = NavBar(
            self.root,
            self.theme,
            mode_var       = self._mode_var,
            on_mode_change = self._cmd_reanalyse,
            on_open        = self._cmd_open,
            on_export      = self._cmd_export,
            on_toggle_theme= self._cmd_toggle_theme,
            on_copy        = self._cmd_copy,
            search_var     = self._search_var,
            on_search_next = self._cmd_search_next,
            on_search_prev = self._cmd_search_prev,
        )
        self._navbar.pack(side=tk.TOP, fill=tk.X)

        # Thin separator line
        self._sep = tk.Frame(self.root, height=1, bd=0)
        self._sep.pack(side=tk.TOP, fill=tk.X)

        # Main content area
        content = tk.Frame(self.root, bd=0)
        content.pack(expand=True, fill=tk.BOTH, padx=28, pady=(16, 0))
        self._content = content

        # Input / paste area
        self._input = tk.Text(
            content,
            height=4,
            font=self.theme.code_font(10),
            bd=0,
            highlightthickness=1,
            wrap=tk.WORD,
        )
        self._input.pack(fill=tk.X, pady=(0, 12))
        self._input.bind("<KeyRelease>", lambda _e: self._cmd_reanalyse())

        # Add placeholder text
        self._set_input_placeholder()

        # Output
        self._output = OutputPane(content, self.theme)
        self._output._get_query = lambda: self._search_var.get()   # wire query
        self._output.pack(expand=True, fill=tk.BOTH)

        # Status bar
        self._status = StatusBar(self.root, self.theme)
        self._status.pack(side=tk.BOTTOM, fill=tk.X)

    # ------------------------------------------------------------------
    def _set_input_placeholder(self) -> None:
        p = self.theme.palette
        if not self._input.get("1.0", tk.END).strip():
            self._input.configure(fg=p.subtext)
            self._input.insert("1.0", "Paste raw binary text here, or use Open File…")
            self._input.bind("<FocusIn>", self._clear_placeholder)
        else:
            self._input.configure(fg=p.text)

    def _clear_placeholder(self, _event: tk.Event) -> None:
        placeholder = "Paste raw binary text here, or use Open File…"
        if self._input.get("1.0", tk.END).strip() == placeholder:
            self._input.delete("1.0", tk.END)
            self._input.configure(fg=self.theme.palette.text)
            self._input.unbind("<FocusIn>")

    # ------------------------------------------------------------------
    # Commands (UI callbacks)
    # ------------------------------------------------------------------

    def _cmd_open(self) -> None:
        path = filedialog.askopenfilename(
            title="Open File",
            filetypes=[
                ("All files",     "*.*"),
                ("Executables",   "*.exe *.dll *.sys"),
                ("Libraries",     "*.so *.dylib"),
                ("Data files",    "*.bin *.dat"),
            ],
        )
        if not path:
            return
        self._source_path = path
        self._status.set_status(f"Loading  {Path(path).name}…")
        try:
            self._binary = Path(path).read_bytes()
            self._raw_cache = extract_strings_from_bytes(self._binary)
            self._input.configure(state=tk.NORMAL)
            self._input.delete("1.0", tk.END)
            self._input.insert("1.0", f"[FILE]  {path}")
            self._input.configure(fg=self.theme.palette.subtext)
            self._cmd_reanalyse()
        except OSError as exc:
            messagebox.showerror("SCRIBE — Open Error", str(exc))
            self._status.set_status("Error loading file")

    def _cmd_reanalyse(self) -> None:
        if self._is_busy:
            return
        self._output.clear()
        self._results = []
        self._status.set_status("Analysing…")
        self._status.show_progress(5)
        t = threading.Thread(target=self._analysis_worker, daemon=True)
        t.start()

    def _analysis_worker(self) -> None:
        self._is_busy = True
        try:
            mode = Mode(self._mode_var.get())

            # Determine source text
            source = self._raw_cache
            if source is None:
                raw_input = self._input.get("1.0", tk.END)
                placeholder = "Paste raw binary text here, or use Open File…"
                if raw_input.strip() in ("", placeholder):
                    self.root.after(0, lambda: self._status.set_status("Ready"))
                    return
                source = raw_input

            config = AnalysisConfig(
                mode       = mode,
                wordlist   = self._wordlist,
                deduplicate= True,
            )
            self._results = analyse(source, config, binary=self._binary)
            self.root.after(0, self._begin_batch_insert)
        except Exception as exc:
            logger.exception("Analysis failed")
            self.root.after(0, lambda: self._status.set_status(f"Error: {exc}"))
            self._is_busy = False

    def _begin_batch_insert(self) -> None:
        self._status.show_progress(10)
        self._batch_insert(0)

    def _batch_insert(self, index: int) -> None:
        end = index + _BATCH_SIZE
        chunk = self._results[index:end]
        if chunk:
            self._output.append("\n".join(str(r) for r in chunk) + "\n")
            pct = min(99, int((end / max(len(self._results), 1)) * 100))
            self._status.set_status(f"Rendering…  {pct}%")
            self._status.show_progress(pct)
            self.root.after(_BATCH_MS, lambda: self._batch_insert(end))
        else:
            n = len(self._results)
            self._status.set_status(f"{n:,} result{'s' if n != 1 else ''}  ·  {Mode(self._mode_var.get()).name}")
            self._status.show_progress(0)
            self._is_busy = False
            fname = Path(self._source_path).name if self._source_path else "—"
            self._status.set_info(fname)
            self._on_search_changed()      # re-apply any active search

    def _cmd_export(self) -> None:
        if not self._results:
            messagebox.showinfo("SCRIBE — Export", "No results to export.")
            return
        type_choices = " ".join(f'{{{"Plain Text"} {ext}}}'.replace("Plain Text", t) for t, ext, _ in _EXPORT_TYPES)

        path = filedialog.asksaveasfilename(
            title           = "Export Results",
            defaultextension= ".txt",
            filetypes       = [(label, ext) for label, ext, _ in _EXPORT_TYPES],
        )
        if not path:
            return
        p = Path(path)
        try:
            if p.suffix == ".json":
                export_json(self._results, p, Mode(self._mode_var.get()), self._source_path)
            elif p.suffix == ".csv":
                export_csv(self._results, p, Mode(self._mode_var.get()))
            else:
                export_txt(self._results, p)
            messagebox.showinfo("SCRIBE — Export", f"Saved {len(self._results):,} results to:\n{p}")
        except OSError as exc:
            messagebox.showerror("SCRIBE — Export Error", str(exc))

    def _cmd_copy(self) -> None:
        if not self._results:
            return
        text = "\n".join(r.value for r in self._results)
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self._status.set_status(f"Copied {len(self._results):,} results to clipboard")

    def _cmd_toggle_theme(self) -> None:
        self.theme.toggle()
        self._apply_theme()

    def _cmd_search_next(self) -> None:
        self._do_search(direction=1)

    def _cmd_search_prev(self) -> None:
        self._do_search(direction=-1)

    def _on_search_changed(self, *_args) -> None:
        query = self._search_var.get()
        total = self._output.highlight_query(query)
        self._navbar.set_match_info(0, total, query)

    def _do_search(self, direction: int) -> None:
        query = self._search_var.get()
        if not query:
            return
        cur, total = self._output.jump_to_match(direction)
        self._navbar.set_match_info(cur, total, query)
        if total == 0:
            self._status.set_status(f'No matches for "{query}"')

    # ------------------------------------------------------------------
    # Theming
    # ------------------------------------------------------------------

    def _apply_theme(self) -> None:
        p = self.theme.palette
        self.root.configure(bg=p.bg)
        self._sep.configure(bg=p.border)
        self._content.configure(bg=p.bg)
        self._input.configure(
            bg=p.card, fg=p.text, insertbackground=p.text,
            highlightbackground=p.border, highlightcolor=p.accent,
        )
        self._navbar.apply_theme(self._mode_var.get())
        self._output.apply_theme()
        self._status.apply_theme()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def launch() -> None:
    """Initialise logging, create the Tk root, and start the main loop."""
    logging.basicConfig(
        level  = logging.INFO,
        format = "%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
        datefmt= "%H:%M:%S",
    )

    root = tk.Tk()

    # Set taskbar / window icon (fails gracefully if no icon file)
    icon_path = Path(__file__).parent / "icon.png"
    if icon_path.exists():
        try:
            img = tk.PhotoImage(file=str(icon_path))
            root.iconphoto(True, img)
        except Exception:
            pass

    ScribeApp(root)
    root.mainloop()
