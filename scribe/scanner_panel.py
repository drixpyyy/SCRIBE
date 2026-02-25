"""
scribe.scanner_panel
====================
CE-style value scanner UI panel.

Designed as a self-contained tk.Frame that can be embedded in any container.
All heavy work (scan loops) runs on background threads; results stream to the
UI via root.after().
"""

from __future__ import annotations

import logging
import threading
import tkinter as tk
from tkinter import messagebox, ttk
from typing import Callable

logger = logging.getLogger(__name__)

# Lazy imports so non-Windows won't crash on module load
_scanner_mod = None

def _get_scanner_mod():
    global _scanner_mod
    if _scanner_mod is None:
        from scribe import scanner as _m
        _scanner_mod = _m
    return _scanner_mod


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_MAX_DISPLAY = 2000   # cap on results shown in the list (performance)


def _flat_btn(parent, text, cmd, *, theme, primary=False, danger=False, width=None):
    p   = theme.palette
    bg  = p.accent if primary else (p.danger if danger else p.nav)
    fg  = "#ffffff" if (primary or danger) else p.text
    kw  = dict(padx=10, pady=5) if width is None else dict(width=width, pady=5)
    btn = tk.Button(
        parent, text=text, command=cmd,
        relief="flat", bd=0, font=theme.ui_font(9, "bold"),
        bg=bg, fg=fg, activebackground=p.hover, activeforeground=p.text,
        cursor="hand2", **kw,
    )
    return btn


# ---------------------------------------------------------------------------
# ScannerPanel
# ---------------------------------------------------------------------------

class ScannerPanel(tk.Frame):
    """
    Drop-in value scanner panel.

    Parameters
    ----------
    parent:
        Parent widget.
    theme:
        ThemeManager instance shared with the main app.
    get_pid:
        Callable that returns the currently attached PID (int) or None.
    get_process_name:
        Callable that returns the attached process name string.
    """

    def __init__(
        self,
        parent:           tk.Widget,
        theme:            object,
        get_pid:          Callable[[], int | None],
        get_process_name: Callable[[], str],
    ) -> None:
        super().__init__(parent, bd=0)
        self._theme            = theme
        self._get_pid          = get_pid
        self._get_process_name = get_process_name

        self._scanner     = None   # ValueScanner instance
        self._freeze_table = None  # FreezeTable instance
        self._scan_count   = 0     # number of scans performed (0 = no first scan yet)
        self._is_scanning  = False
        self._hits         = []    # list[ScanHit] currently displayed

        self._build()
        self._apply_theme()

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build(self) -> None:
        p = self._theme.palette

        # ── Process bar ─────────────────────────────────────────────────
        proc_bar = tk.Frame(self, bd=0)
        proc_bar.pack(fill=tk.X, pady=(0, 8))
        self._proc_bar = proc_bar

        tk.Label(proc_bar, text="Target:", font=self._theme.ui_font(9)).pack(side=tk.LEFT)
        self._lbl_process = tk.Label(
            proc_bar, text="No process attached",
            font=self._theme.ui_font(9, "bold"), width=32, anchor="w",
        )
        self._lbl_process.pack(side=tk.LEFT, padx=(6, 0))

        # ── Main split: controls (left) + address table (right) ─────────
        split = tk.Frame(self, bd=0)
        split.pack(fill=tk.BOTH, expand=True)
        split.columnconfigure(0, weight=3)
        split.columnconfigure(1, weight=2)
        split.rowconfigure(0, weight=1)

        left = tk.Frame(split, bd=0)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 8))

        right = tk.Frame(split, bd=0)
        right.grid(row=0, column=1, sticky="nsew")

        self._build_scan_controls(left)
        self._build_results(left)
        self._build_address_table(right)

    def _build_scan_controls(self, parent: tk.Frame) -> None:
        """Value input + type + condition + scan buttons."""
        ctrl = tk.LabelFrame(parent, text="  Scan  ", bd=1, relief="flat",
                              font=self._theme.ui_font(9))
        ctrl.pack(fill=tk.X, pady=(0, 8))
        self._ctrl_frame = ctrl

        # Row 1: value + type
        row1 = tk.Frame(ctrl, bd=0)
        row1.pack(fill=tk.X, padx=8, pady=(6, 4))

        tk.Label(row1, text="Value:", font=self._theme.ui_font(9)).pack(side=tk.LEFT)
        self._value_var = tk.StringVar()
        self._value_entry = tk.Entry(
            row1, textvariable=self._value_var,
            font=self._theme.ui_font(10), bd=0, highlightthickness=1, width=14,
        )
        self._value_entry.pack(side=tk.LEFT, padx=(6, 12), ipady=4)
        self._value_entry.bind("<Return>", lambda _e: self._cmd_scan())

        tk.Label(row1, text="Type:", font=self._theme.ui_font(9)).pack(side=tk.LEFT)
        self._dtype_var = tk.StringVar()
        dtype_labels = ["Float", "Int32 (4 bytes)", "Int64 (8 bytes)",
                         "Double", "Int16 (2 bytes)", "Int8  (1 byte)"]
        self._dtype_combo = ttk.Combobox(
            row1, textvariable=self._dtype_var,
            values=dtype_labels, state="readonly",
            font=self._theme.ui_font(9), width=14,
        )
        self._dtype_combo.set("Float")
        self._dtype_combo.pack(side=tk.LEFT, padx=(6, 0))

        # Row 2: second value (for Between) + condition
        row2 = tk.Frame(ctrl, bd=0)
        row2.pack(fill=tk.X, padx=8, pady=(0, 4))

        tk.Label(row2, text="Cond.:", font=self._theme.ui_font(9)).pack(side=tk.LEFT)
        self._cond_var = tk.StringVar()
        cond_labels = ["Exact Value", "Between", "Increased", "Decreased",
                        "Changed", "Unchanged"]
        self._cond_combo = ttk.Combobox(
            row2, textvariable=self._cond_var,
            values=cond_labels, state="readonly",
            font=self._theme.ui_font(9), width=14,
        )
        self._cond_combo.set("Exact Value")
        self._cond_combo.pack(side=tk.LEFT, padx=(6, 12))
        self._cond_var.trace_add("write", self._on_condition_changed)

        tk.Label(row2, text="Value 2:", font=self._theme.ui_font(9)).pack(side=tk.LEFT)
        self._value2_var = tk.StringVar()
        self._value2_entry = tk.Entry(
            row2, textvariable=self._value2_var,
            font=self._theme.ui_font(10), bd=0, highlightthickness=1, width=10,
            state=tk.DISABLED,
        )
        self._value2_entry.pack(side=tk.LEFT, padx=(6, 0), ipady=4)

        # Row 3: buttons
        row3 = tk.Frame(ctrl, bd=0)
        row3.pack(fill=tk.X, padx=8, pady=(2, 8))

        self._btn_new_scan  = _flat_btn(row3, "🔍  New Scan",  self._cmd_new_scan,  theme=self._theme, primary=True)
        self._btn_next_scan = _flat_btn(row3, "↩  Next Scan", self._cmd_next_scan, theme=self._theme)
        self._btn_clear     = _flat_btn(row3, "✕  Clear",     self._cmd_clear,     theme=self._theme, danger=True)

        self._btn_new_scan.pack(side=tk.LEFT, padx=(0, 4))
        self._btn_next_scan.pack(side=tk.LEFT, padx=4)
        self._btn_clear.pack(side=tk.LEFT, padx=4)

        self._btn_next_scan.configure(state=tk.DISABLED)

        # Progress / status
        self._lbl_scan_status = tk.Label(ctrl, text="", font=self._theme.ui_font(9), anchor="w")
        self._lbl_scan_status.pack(fill=tk.X, padx=8, pady=(0, 6))

    def _build_results(self, parent: tk.Frame) -> None:
        """Scrollable list of scan hits."""
        lf = tk.LabelFrame(parent, text="  Results  ", bd=1, relief="flat",
                            font=self._theme.ui_font(9))
        lf.pack(fill=tk.BOTH, expand=True)
        self._results_frame = lf

        list_container = tk.Frame(lf, bd=0, highlightthickness=1)
        list_container.pack(fill=tk.BOTH, expand=True, padx=6, pady=4)
        self._list_container = list_container

        sb = tk.Scrollbar(list_container, orient=tk.VERTICAL)
        sb.pack(side=tk.RIGHT, fill=tk.Y)

        cols = ("address", "value", "prev")
        self._results_tree = ttk.Treeview(
            list_container, columns=cols, show="headings",
            yscrollcommand=sb.set, height=10
        )
        self._results_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.config(command=self._results_tree.yview)

        self._results_tree.heading("address", text="Address")
        self._results_tree.heading("value", text="Value")
        self._results_tree.heading("prev", text="Previous")

        self._results_tree.column("address", width=140, anchor="w")
        self._results_tree.column("value", width=100, anchor="e")
        self._results_tree.column("prev", width=100, anchor="e")

        self._results_tree.bind("<Double-1>", lambda _e: self._cmd_add_selected())

        # Below-list buttons
        btn_row = tk.Frame(lf, bd=0)
        btn_row.pack(fill=tk.X, padx=6, pady=(0, 6))

        self._btn_add = _flat_btn(btn_row, "📌  Add to Table", self._cmd_add_selected, theme=self._theme)
        self._btn_add.pack(side=tk.LEFT, padx=(0, 4))
        self._btn_refresh_vals = _flat_btn(btn_row, "↻  Refresh Values", self._cmd_refresh_values, theme=self._theme)
        self._btn_refresh_vals.pack(side=tk.LEFT)

    def _build_address_table(self, parent: tk.Frame) -> None:
        """Pinned address table with freeze toggles."""
        lf = tk.LabelFrame(parent, text="  Address Table  ", bd=1, relief="flat",
                            font=self._theme.ui_font(9))
        lf.pack(fill=tk.BOTH, expand=True)
        self._addr_table_frame = lf

        # Treeview (address / type / value / frozen)
        tree_container = tk.Frame(lf, bd=0)
        tree_container.pack(fill=tk.BOTH, expand=True, padx=6, pady=(4, 0))

        sb = tk.Scrollbar(tree_container, orient=tk.VERTICAL)
        sb.pack(side=tk.RIGHT, fill=tk.Y)

        cols = ("address", "type", "value", "frozen")
        self._addr_tree = ttk.Treeview(
            tree_container,
            columns=cols,
            show="headings",
            yscrollcommand=sb.set,
            height=12,
        )
        sb.config(command=self._addr_tree.yview)
        self._addr_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self._addr_tree.heading("address", text="Address")
        self._addr_tree.heading("type",    text="Type")
        self._addr_tree.heading("value",   text="Value")
        self._addr_tree.heading("frozen",  text="🔒")
        self._addr_tree.column("address", width=110, anchor="w")
        self._addr_tree.column("type",    width=60,  anchor="center")
        self._addr_tree.column("value",   width=80,  anchor="e")
        self._addr_tree.column("frozen",  width=30,  anchor="center")

        self._addr_tree.bind("<Double-1>", self._on_table_double_click)

        # Table buttons
        btn_row = tk.Frame(lf, bd=0)
        btn_row.pack(fill=tk.X, padx=6, pady=6)

        self._btn_freeze_toggle = _flat_btn(btn_row, "🔒  Toggle Freeze", self._cmd_toggle_freeze, theme=self._theme)
        self._btn_freeze_toggle.pack(side=tk.LEFT, padx=(0, 4))
        self._btn_write_val     = _flat_btn(btn_row, "✏️  Write Value",   self._cmd_write_value,   theme=self._theme)
        self._btn_write_val.pack(side=tk.LEFT, padx=4)
        self._btn_remove_addr   = _flat_btn(btn_row, "🗑  Remove",        self._cmd_remove_address, theme=self._theme, danger=True)
        self._btn_remove_addr.pack(side=tk.LEFT, padx=4)

        # Refresh timer — update live values in the table
        self._table_data: dict[int, dict] = {}   # address → {dtype, value, frozen, iid}
        self._schedule_table_refresh()

    # ------------------------------------------------------------------
    # Commands
    # ------------------------------------------------------------------

    def _cmd_scan(self) -> None:
        if self._scan_count == 0:
            self._cmd_new_scan()
        else:
            self._cmd_next_scan()

    def _cmd_new_scan(self) -> None:
        pid = self._get_pid()
        if pid is None:
            messagebox.showwarning("SCRIBE Scanner", "Attach to a process first using ⚡ Live.")
            return
        if self._is_scanning:
            return

        cond_label = self._cond_var.get()
        if cond_label not in ("Exact Value", "Between"):
            messagebox.showwarning("SCRIBE Scanner", "First scan must use 'Exact Value' or 'Between'.")
            return

        value_str = self._value_var.get().strip()
        if not value_str:
            messagebox.showwarning("SCRIBE Scanner", "Enter a value to scan for.")
            return

        self._is_scanning = True
        self._lbl_scan_status.config(text="Scanning…")
        self._btn_new_scan.config(state=tk.DISABLED)
        self._btn_next_scan.config(state=tk.DISABLED)
        self._results_tree.delete(*self._results_tree.get_children())

        t = threading.Thread(target=self._scan_worker, args=(True,), daemon=True)
        t.start()

    def _cmd_next_scan(self) -> None:
        if self._scanner is None or self._scan_count == 0:
            return
        if self._is_scanning:
            return

        self._is_scanning = True
        self._lbl_scan_status.config(text="Filtering…")
        self._btn_new_scan.config(state=tk.DISABLED)
        self._btn_next_scan.config(state=tk.DISABLED)

        t = threading.Thread(target=self._scan_worker, args=(False,), daemon=True)
        t.start()

    def _scan_worker(self, is_new: bool) -> None:
        pid  = self._get_pid()
        mods = _get_scanner_mod()

        try:
            dtype_label = self._dtype_var.get()
            dtype       = self._resolve_dtype(dtype_label)
            cond_label  = self._cond_var.get()
            condition   = self._resolve_condition(cond_label)
            value_str   = self._value_var.get().strip() or "0"
            value2_str  = self._value2_var.get().strip() or "0"

            if is_new or self._scanner is None or self._scanner.pid != pid:
                if self._scanner:
                    self._scanner.close()
                self._scanner = mods.ValueScanner(pid)

            def on_prog(done: int, total: int) -> None:
                pct = max(1, int(done / max(total, 1) * 100))
                self.after(0, lambda: self._lbl_scan_status.config(
                    text=f"{'Scanning' if is_new else 'Filtering'}… {pct}%"
                ))

            if is_new:
                count = self._scanner.new_scan(value_str, dtype, condition, value2_str, on_progress=on_prog)
            else:
                count = self._scanner.next_scan(value_str, dtype, condition, value2_str, on_progress=on_prog)

            hits = self._scanner.hits
            self.after(0, lambda: self._on_scan_done(hits, count, dtype))

        except (PermissionError, ValueError, OSError, OverflowError) as exc:
            self.after(0, lambda: messagebox.showerror("SCRIBE Scanner", str(exc)))
            self.after(0, lambda: self._lbl_scan_status.config(text="Error"))
            self.after(0, lambda: self._reset_scan_buttons())
            self._is_scanning = False

        except Exception as exc:
            logger.exception("Scan worker failed")
            self.after(0, lambda: self._lbl_scan_status.config(text=f"Error: {exc}"))
            self.after(0, self._reset_scan_buttons)
            self._is_scanning = False

    def _on_scan_done(self, hits: list, count: int, dtype) -> None:
        self._hits         = hits
        self._scan_count  += 1
        self._is_scanning  = False
        self._reset_scan_buttons()
        self._btn_next_scan.config(state=tk.NORMAL)

        mods = _get_scanner_mod()
        label = f"{count:,} results" if count <= _MAX_DISPLAY else f"{count:,} results  (showing first {_MAX_DISPLAY:,})"
        self._lbl_scan_status.config(text=label)

        self._results_tree.delete(*self._results_tree.get_children())
        for hit in hits[:_MAX_DISPLAY]:
            val_str  = mods.fmt_value(hit.value, dtype)
            prev_str = mods.fmt_value(hit.prev_value, dtype) if hit.prev_value is not None else "—"
            self._results_tree.insert(
                "", tk.END,
                values=(f"0x{hit.address:016X}", val_str, prev_str)
            )

    def _cmd_clear(self) -> None:
        if self._scanner:
            self._scanner.clear()
        self._hits        = []
        self._scan_count  = 0
        self._is_scanning = False
        self._results_tree.delete(*self._results_tree.get_children())
        self._lbl_scan_status.config(text="")
        self._btn_next_scan.config(state=tk.DISABLED)

    def _cmd_add_selected(self) -> None:
        """Add selected result(s) to the address table."""
        sel = self._results_tree.selection()
        if not sel:
            return
        dtype = self._resolve_dtype(self._dtype_var.get())
        for iid in sel:
            idx = self._results_tree.index(iid)
            if idx >= len(self._hits):
                continue
            hit  = self._hits[idx]
            addr = hit.address
            if addr not in self._table_data:
                self._add_to_table(addr, dtype, hit.value)

    def _add_to_table(self, address: int, dtype, value) -> None:
        mods = _get_scanner_mod()
        if self._freeze_table is None:
            pid = self._get_pid()
            if pid is None:
                return
            self._freeze_table = mods.FreezeTable(pid)

        iid = self._addr_tree.insert(
            "", tk.END,
            values=(
                f"0x{address:016X}",
                dtype.value,
                mods.fmt_value(value, dtype),
                "❌",
            ),
        )
        self._table_data[address] = {
            "dtype":  dtype,
            "value":  value,
            "frozen": False,
            "iid":    iid,
        }

    def _cmd_toggle_freeze(self) -> None:
        sel = self._addr_tree.selection()
        if not sel:
            return
        for iid in sel:
            addr = self._iid_to_address(iid)
            if addr is None:
                continue
            entry = self._table_data[addr]
            entry["frozen"] = not entry["frozen"]
            if self._freeze_table:
                if entry["frozen"]:
                    self._freeze_table.add(addr, entry["dtype"], entry["value"])
                else:
                    self._freeze_table.remove(addr)
            self._addr_tree.set(iid, "frozen", "🔒" if entry["frozen"] else "❌")

    def _cmd_write_value(self) -> None:
        sel = self._addr_tree.selection()
        if not sel or self._scanner is None:
            return
        # Use the current scan value input as the new value
        new_val_str = self._value_var.get().strip()
        if not new_val_str:
            messagebox.showwarning("SCRIBE Scanner", "Enter the new value in the Value field first.")
            return
        mods = _get_scanner_mod()
        for iid in sel:
            addr = self._iid_to_address(iid)
            if addr is None:
                continue
            entry  = self._table_data[addr]
            dtype  = entry["dtype"]
            try:
                new_val = mods.parse_value(new_val_str, dtype)
            except ValueError:
                continue
            ok = self._scanner.write_address(addr, new_val, dtype)
            if ok:
                entry["value"] = new_val
                if entry["frozen"] and self._freeze_table:
                    self._freeze_table.set_value(addr, new_val)
                self._addr_tree.set(iid, "value", mods.fmt_value(new_val, dtype))

    def _cmd_remove_address(self) -> None:
        sel = self._addr_tree.selection()
        for iid in sel:
            addr = self._iid_to_address(iid)
            if addr is not None:
                if self._freeze_table:
                    self._freeze_table.remove(addr)
                del self._table_data[addr]
            self._addr_tree.delete(iid)

    def _cmd_refresh_values(self) -> None:
        """Re-read all result list values from memory."""
        if not self._scanner or not self._hits:
            return
        mods  = _get_scanner_mod()
        dtype = self._resolve_dtype(self._dtype_var.get())
        children = self._results_tree.get_children()
        for i, child_iid in enumerate(children):
            if i >= len(self._hits): break
            hit = self._hits[i]
            new_val = self._scanner.read_address(hit.address, dtype)
            if new_val is not None:
                val_str  = mods.fmt_value(new_val, dtype)
                prev_str = mods.fmt_value(hit.value, dtype)
                self._results_tree.item(child_iid, values=(f"0x{hit.address:016X}", val_str, prev_str))
                hit.prev_value = hit.value
                hit.value      = new_val

    def _on_table_double_click(self, _event: tk.Event) -> None:
        """Double-click a table row to edit its value inline via a popup."""
        sel = self._addr_tree.selection()
        if not sel:
            return
        iid  = sel[0]
        addr = self._iid_to_address(iid)
        if addr is None:
            return
        entry = self._table_data[addr]
        mods  = _get_scanner_mod()

        # Simple askstring-style popup
        popup = tk.Toplevel(self)
        popup.title("Edit Value")
        popup.geometry("260x90")
        popup.resizable(False, False)
        popup.grab_set()
        popup.configure(bg=self._theme.palette.bg)

        tk.Label(popup, text=f"New value for 0x{addr:X}:",
                 font=self._theme.ui_font(9),
                 bg=self._theme.palette.bg,
                 fg=self._theme.palette.text).pack(padx=12, pady=(10, 4))
        var = tk.StringVar(value=mods.fmt_value(entry["value"], entry["dtype"]))
        e   = tk.Entry(popup, textvariable=var,
                       font=self._theme.ui_font(10), bd=0, highlightthickness=1)
        e.pack(padx=12, fill=tk.X, ipady=4)
        e.select_range(0, tk.END)
        e.focus_set()

        def _apply() -> None:
            try:
                new_val = mods.parse_value(var.get(), entry["dtype"])
            except ValueError:
                popup.destroy()
                return
            if self._scanner:
                self._scanner.write_address(addr, new_val, entry["dtype"])
            entry["value"] = new_val
            if entry["frozen"] and self._freeze_table:
                self._freeze_table.set_value(addr, new_val)
            self._addr_tree.set(iid, "value", mods.fmt_value(new_val, entry["dtype"]))
            popup.destroy()

        e.bind("<Return>", lambda _e: _apply())
        popup.bind("<Escape>", lambda _e: popup.destroy())
        _flat_btn(popup, "Apply", _apply, theme=self._theme, primary=True).pack(pady=6)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _iid_to_address(self, iid: str) -> int | None:
        for addr, entry in self._table_data.items():
            if entry["iid"] == iid:
                return addr
        return None

    def _resolve_dtype(self, label: str):
        mods = _get_scanner_mod()
        mapping = {
            "Float":           mods.DType.FLOAT,
            "Int32 (4 bytes)": mods.DType.INT32,
            "Int64 (8 bytes)": mods.DType.INT64,
            "Double":          mods.DType.DOUBLE,
            "Int16 (2 bytes)": mods.DType.INT16,
            "Int8  (1 byte)":  mods.DType.INT8,
        }
        return mapping.get(label, mods.DType.FLOAT)

    def _resolve_condition(self, label: str):
        mods = _get_scanner_mod()
        mapping = {
            "Exact Value": mods.Condition.EXACT,
            "Between":     mods.Condition.BETWEEN,
            "Increased":   mods.Condition.INCREASED,
            "Decreased":   mods.Condition.DECREASED,
            "Changed":     mods.Condition.CHANGED,
            "Unchanged":   mods.Condition.UNCHANGED,
        }
        return mapping.get(label, mods.Condition.EXACT)

    def _on_condition_changed(self, *_) -> None:
        needs_val2 = self._cond_var.get() == "Between"
        self._value2_entry.configure(state=tk.NORMAL if needs_val2 else tk.DISABLED)

    def _reset_scan_buttons(self) -> None:
        self._btn_new_scan.config(state=tk.NORMAL)
        if self._scan_count > 0:
            self._btn_next_scan.config(state=tk.NORMAL)

    def _schedule_table_refresh(self) -> None:
        """Refresh live values in address table every 500ms."""
        self._refresh_table_values()
        self.after(500, self._schedule_table_refresh)

    def _refresh_table_values(self) -> None:
        if not self._scanner or not self._table_data:
            return
        mods = _get_scanner_mod()
        for addr, entry in list(self._table_data.items()):
            dtype  = entry["dtype"]
            new_v  = self._scanner.read_address(addr, dtype)
            if new_v is not None:
                entry["value"] = new_v
                try:
                    self._addr_tree.set(entry["iid"], "value", mods.fmt_value(new_v, dtype))
                except tk.TclError:
                    pass   # row was deleted

    def notify_process_attached(self, pid: int, name: str) -> None:
        """Called by the parent app when a new process is attached."""
        # Reset scanner state for the new process
        if self._scanner:
            self._scanner.close()
            self._scanner = None
        if self._freeze_table:
            self._freeze_table.stop()
            self._freeze_table = None
        self._cmd_clear()
        self._lbl_process.config(text=f"{name}  (PID {pid})")

    def notify_process_detached(self) -> None:
        self._lbl_process.config(text="No process attached")

    def destroy(self) -> None:
        """Clean up background threads on close."""
        if self._freeze_table:
            self._freeze_table.stop()
        super().destroy()

    # ------------------------------------------------------------------
    # Theme
    # ------------------------------------------------------------------

    def apply_theme(self) -> None:
        self._apply_theme()

    def _apply_theme(self) -> None:
        p = self._theme.palette

        def _tk_cfg(w, **kw) -> None:
            """Configure only if *w* is a plain tk widget (not ttk)."""
            if isinstance(w, (ttk.Widget,)):
                return   # ttk widgets styled via ttk.Style, not direct bg/fg
            try:
                w.configure(**kw)
            except tk.TclError:
                pass

        self.configure(bg=p.bg)
        self._proc_bar.configure(bg=p.bg)

        # Enhance Contrast: Ensure proc bar items use primary text color, not dimmed
        for w in self._proc_bar.winfo_children():
            if isinstance(w, tk.Label):
                _tk_cfg(w, bg=p.bg, fg=p.text)

        # Walk LabelFrames — skip ttk widgets entirely, enhance text contrast
        for lf in [self._ctrl_frame, self._results_frame, self._addr_table_frame]:
            _tk_cfg(lf, bg=p.bg, fg=p.text)
            for child in lf.winfo_children():
                if isinstance(child, ttk.Widget):
                    continue
                if isinstance(child, tk.Frame):
                    _tk_cfg(child, bg=p.bg)
                    for sub in child.winfo_children():
                        if isinstance(sub, ttk.Widget):
                            continue
                        if isinstance(sub, tk.Label):
                            _tk_cfg(sub, bg=p.bg, fg=p.text)
                        elif isinstance(sub, tk.Entry):
                            _tk_cfg(sub, bg=p.card, fg=p.text,
                                    insertbackground=p.text,
                                    highlightbackground=p.border,
                                    highlightcolor=p.accent)
                        elif isinstance(sub, tk.Button):
                            _tk_cfg(sub, bg=p.nav, fg=p.text,
                                    activebackground=p.hover)
                elif isinstance(child, tk.Label):
                    _tk_cfg(child, bg=p.bg, fg=p.text)
                elif isinstance(child, tk.Button):
                    _tk_cfg(child, bg=p.nav, fg=p.text, activebackground=p.hover)

        _tk_cfg(self._lbl_scan_status, bg=p.bg, fg=p.subtext)
        _tk_cfg(self._list_container,  highlightbackground=p.border)
        _tk_cfg(self._value_entry,  bg=p.card, fg=p.text, insertbackground=p.text,
                highlightbackground=p.border, highlightcolor=p.accent)
        _tk_cfg(self._value2_entry, bg=p.card, fg=p.text, insertbackground=p.text,
                highlightbackground=p.border, highlightcolor=p.accent)

        # Style all Treeview elements with mono fonts and prominent headers
        style = ttk.Style()
        style.theme_use("default")
        style.configure("Treeview",
                         background=p.card, foreground=p.text,
                         fieldbackground=p.card, rowheight=24,
                         font=self._theme.code_font(10))
        style.configure("Treeview.Heading",
                         background=p.nav, foreground=p.text, 
                         relief="flat", font=self._theme.ui_font(9, "bold"))
        style.map("Treeview", background=[("selected", p.accent)],
                  foreground=[("selected", "#ffffff")])