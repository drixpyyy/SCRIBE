"""
scribe.process_dialog
=====================
Modal process-picker dialog for the Live memory scan feature.

Shows a live-filterable list of all running processes alongside a manual
PID / process-name entry field.  Returns the selected PID via a callback.
"""

from __future__ import annotations

import logging
import sys
import threading
import tkinter as tk
from tkinter import messagebox, ttk
from typing import Callable

logger = logging.getLogger(__name__)


class ProcessDialog(tk.Toplevel):
    """
    Modal window for selecting a target process.

    Usage::

        def on_attach(pid: int, name: str) -> None:
            ...

        dlg = ProcessDialog(parent, theme_manager, on_attach)
        # dialog blocks until closed (grab_set makes it modal)
    """

    def __init__(
        self,
        parent:    tk.Widget,
        theme:     object,          # ThemeManager — avoid circular import
        on_attach: Callable[[int, str], None],
    ) -> None:
        super().__init__(parent)
        self._theme     = theme
        self._on_attach = on_attach
        self._processes: list = []      # list[ProcessInfo]
        self._filtered:  list = []

        self.title("SCRIBE — Attach to Process")
        self.resizable(False, False)
        self.grab_set()                 # modal

        # Centre over parent
        self.transient(parent)
        self.geometry("520x480")
        self._centre_on_parent(parent)

        self._build()
        self._apply_theme()
        self._refresh_list()

        self.bind("<Escape>", lambda _e: self.destroy())

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------

    def _build(self) -> None:
        p = self._theme.palette

        # ── Header ──────────────────────────────────────────────────────
        hdr = tk.Frame(self, height=48, bd=0)
        hdr.pack(fill=tk.X)
        hdr.pack_propagate(False)
        self._hdr = hdr

        tk.Label(hdr, text="Attach to Process",
                 font=self._theme.ui_font(13, "bold")).pack(side=tk.LEFT, padx=16, pady=12)

        btn_refresh = tk.Button(
            hdr, text="↻  Refresh",
            command=self._refresh_list,
            relief="flat", bd=0, padx=10, pady=4,
            font=self._theme.ui_font(9),
            cursor="hand2",
        )
        btn_refresh.pack(side=tk.RIGHT, padx=12, pady=8)
        self._btn_refresh = btn_refresh

        # ── Filter entry ────────────────────────────────────────────────
        filter_frame = tk.Frame(self, bd=0)
        filter_frame.pack(fill=tk.X, padx=16, pady=(0, 8))
        self._filter_frame = filter_frame

        self._filter_var = tk.StringVar()
        # trace added after _listbox is created — see end of _build()

        filter_entry = tk.Entry(
            filter_frame,
            textvariable=self._filter_var,
            font=self._theme.ui_font(10),
            bd=0, highlightthickness=1,
        )
        filter_entry.pack(fill=tk.X, ipady=5)
        filter_entry.bind("<FocusIn>",  self._clear_filter_placeholder)
        filter_entry.bind("<FocusOut>", self._restore_filter_placeholder)
        self._filter_entry = filter_entry

        # ── Process list ────────────────────────────────────────────────
        list_frame = tk.Frame(self, bd=0, highlightthickness=1)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=16)
        self._list_frame = list_frame

        scrollbar = tk.Scrollbar(list_frame, orient=tk.VERTICAL)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self._listbox = tk.Listbox(
            list_frame,
            yscrollcommand=scrollbar.set,
            selectmode=tk.SINGLE,
            font=self._theme.code_font(10),
            bd=0,
            highlightthickness=0,
            activestyle="none",
        )
        self._listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=self._listbox.yview)
        self._listbox.bind("<Double-1>",  lambda _e: self._cmd_attach())
        self._listbox.bind("<Return>",    lambda _e: self._cmd_attach())

        # ── Manual entry ────────────────────────────────────────────────
        manual_frame = tk.Frame(self, bd=0)
        manual_frame.pack(fill=tk.X, padx=16, pady=(10, 0))
        self._manual_frame = manual_frame

        tk.Label(manual_frame, text="Manual PID or name:",
                 font=self._theme.ui_font(9)).pack(side=tk.LEFT)

        self._manual_var = tk.StringVar()
        manual_entry = tk.Entry(
            manual_frame,
            textvariable=self._manual_var,
            font=self._theme.ui_font(10),
            bd=0, highlightthickness=1,
            width=20,
        )
        manual_entry.pack(side=tk.LEFT, padx=(8, 0), ipady=4)
        manual_entry.bind("<Return>", lambda _e: self._cmd_attach_manual())
        self._manual_entry = manual_entry

        btn_manual = tk.Button(
            manual_frame, text="Attach",
            command=self._cmd_attach_manual,
            relief="flat", bd=0, padx=12, pady=4,
            font=self._theme.ui_font(9, "bold"),
            cursor="hand2",
        )
        btn_manual.pack(side=tk.LEFT, padx=8)
        self._btn_manual = btn_manual

        # ── Footer ──────────────────────────────────────────────────────
        footer = tk.Frame(self, height=52, bd=0)
        footer.pack(fill=tk.X)
        footer.pack_propagate(False)
        self._footer = footer

        self._lbl_count = tk.Label(footer, text="", font=self._theme.ui_font(9))
        self._lbl_count.pack(side=tk.LEFT, padx=16)

        btn_cancel = tk.Button(
            footer, text="Cancel",
            command=self.destroy,
            relief="flat", bd=0, padx=14, pady=6,
            font=self._theme.ui_font(9),
            cursor="hand2",
        )
        btn_cancel.pack(side=tk.RIGHT, padx=8, pady=8)
        self._btn_cancel = btn_cancel

        self._btn_attach = tk.Button(
            footer, text="⚡  Attach",
            command=self._cmd_attach,
            relief="flat", bd=0, padx=14, pady=6,
            font=self._theme.ui_font(9, "bold"),
            cursor="hand2",
        )
        self._btn_attach.pack(side=tk.RIGHT, padx=4, pady=8)

        # Now that _listbox exists it is safe to add the filter trace.
        # The insert("0, ...") placeholder write below will NOT call _apply_filter
        # because the trace is not registered yet.
        self._filter_entry.insert(0, "Filter by name or PID…")
        self._filter_var.trace_add("write", lambda *_: self._apply_filter())

    # ------------------------------------------------------------------
    # Process list management
    # ------------------------------------------------------------------

    def _refresh_list(self) -> None:
        """Reload the process list on a background thread."""
        self._listbox.delete(0, tk.END)
        self._listbox.insert(tk.END, "  Loading…")
        self._lbl_count.config(text="")

        def _load() -> None:
            try:
                from scribe.memory import list_processes
                procs = list_processes()
                self.after(0, lambda: self._populate(procs))
            except Exception as exc:
                self.after(0, lambda: self._populate_error(str(exc)))

        threading.Thread(target=_load, daemon=True).start()

    def _populate(self, processes: list) -> None:
        self._processes = processes
        self._apply_filter()

    def _populate_error(self, msg: str) -> None:
        self._listbox.delete(0, tk.END)
        self._listbox.insert(tk.END, f"  Error: {msg}")

    def _apply_filter(self) -> None:
        query = self._filter_var.get().strip().lower()
        placeholder = "filter by name or pid…"
        if query == placeholder or query == "":
            self._filtered = self._processes
        else:
            self._filtered = [
                p for p in self._processes
                if query in p.name.lower() or query in str(p.pid)
            ]

        self._listbox.delete(0, tk.END)
        if not self._filtered:
            self._listbox.insert(tk.END, "  No matches")
        else:
            for proc in self._filtered:
                self._listbox.insert(tk.END, f"  {proc.pid:>7}   {proc.name}")

        n = len(self._filtered)
        total = len(self._processes)
        self._lbl_count.config(text=f"{n} of {total} processes")

    # ------------------------------------------------------------------
    # Attach commands
    # ------------------------------------------------------------------

    def _cmd_attach(self) -> None:
        """Attach to the selected process in the list."""
        sel = self._listbox.curselection()
        if not sel:
            messagebox.showwarning("SCRIBE", "Select a process first.", parent=self)
            return
        idx  = sel[0]
        if idx >= len(self._filtered):
            return
        proc = self._filtered[idx]
        self._fire(proc.pid, proc.name)

    def _cmd_attach_manual(self) -> None:
        """Attach to a process specified manually by PID or name."""
        val = self._manual_var.get().strip()
        if not val:
            return

        # Try as PID first
        if val.isdigit():
            self._fire(int(val), f"PID {val}")
            return

        # Try as process name
        try:
            from scribe.memory import find_process_by_name
            matches = find_process_by_name(val)
        except Exception as exc:
            messagebox.showerror("SCRIBE", str(exc), parent=self)
            return

        if not matches:
            messagebox.showwarning(
                "SCRIBE",
                f"No process named '{val}' found.\n"
                "Make sure the game/app is running.",
                parent=self,
            )
            return
        if len(matches) > 1:
            # Multiple instances — use the one with the lowest PID
            matches.sort(key=lambda p: p.pid)
            logger.warning(
                "Multiple instances of '%s' found, using PID %d", val, matches[0].pid
            )
        self._fire(matches[0].pid, matches[0].name)

    def _fire(self, pid: int, name: str) -> None:
        """Close the dialog and invoke the callback."""
        self.destroy()
        self._on_attach(pid, name)

    # ------------------------------------------------------------------
    # Placeholder helpers
    # ------------------------------------------------------------------

    def _clear_filter_placeholder(self, _event: tk.Event) -> None:
        if self._filter_var.get() == "Filter by name or PID…":
            self._filter_var.set("")

    def _restore_filter_placeholder(self, _event: tk.Event) -> None:
        if not self._filter_var.get().strip():
            self._filter_var.set("Filter by name or PID…")
            self._apply_filter()

    # ------------------------------------------------------------------
    # Theme
    # ------------------------------------------------------------------

    def _apply_theme(self) -> None:
        p = self._theme.palette
        self.configure(bg=p.bg)

        for frame in [self._hdr, self._filter_frame, self._manual_frame, self._footer]:
            frame.configure(bg=p.bg)

        # Labels
        for widget in self._hdr.winfo_children():
            if isinstance(widget, tk.Label):
                widget.configure(bg=p.bg, fg=p.text)
        for widget in self._manual_frame.winfo_children():
            if isinstance(widget, tk.Label):
                widget.configure(bg=p.bg, fg=p.subtext)

        self._lbl_count.configure(bg=p.bg, fg=p.subtext)
        self._list_frame.configure(highlightbackground=p.border, bg=p.card)
        self._listbox.configure(
            bg=p.card, fg=p.text,
            selectbackground=p.accent, selectforeground="#ffffff",
        )
        self._filter_entry.configure(
            bg=p.card, fg=p.subtext,
            highlightbackground=p.border, highlightcolor=p.accent,
            insertbackground=p.text,
        )
        self._manual_entry.configure(
            bg=p.card, fg=p.text,
            highlightbackground=p.border, highlightcolor=p.accent,
            insertbackground=p.text,
        )
        self._btn_refresh.configure(bg=p.nav, fg=p.subtext, activebackground=p.hover)
        self._btn_cancel.configure(bg=p.nav, fg=p.text, activebackground=p.hover)
        self._btn_manual.configure(bg=p.nav, fg=p.text, activebackground=p.hover)
        self._btn_attach.configure(bg=p.accent, fg="#ffffff", activebackground=p.accent)

    # ------------------------------------------------------------------
    def _centre_on_parent(self, parent: tk.Widget) -> None:
        self.update_idletasks()
        px = parent.winfo_rootx() + parent.winfo_width()  // 2
        py = parent.winfo_rooty() + parent.winfo_height() // 2
        w, h = 520, 480
        self.geometry(f"{w}x{h}+{px - w // 2}+{py - h // 2}")