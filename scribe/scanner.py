"""
scribe.scanner
==============
CE-style value scanner using only ReadProcessMemory / WriteProcessMemory.

No kernel driver, no debug APIs, no injection.  All operations use the same
OpenProcess + VM read/write calls available to any normal Win32 process —
the same technique used by the live string scanner.

Public API
----------
ValueScanner          — stateful scanner object (owns the address list)
  .new_scan(...)      → int   (number of hits)
  .next_scan(...)     → int
  .read_address(addr) → value | None
  .write_address(addr, value) → bool
  .clear()

FreezeTable           — thread-based value freezer
  .add(addr, dtype, value)
  .remove(addr)
  .set_frozen(addr, frozen)
  .clear()
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import logging
import struct
import sys
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterator

if sys.platform != "win32":
    raise ImportError("scribe.scanner is Windows-only")

logger = logging.getLogger(__name__)

_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

# ---------------------------------------------------------------------------
# Win32 constants
# ---------------------------------------------------------------------------

PROCESS_VM_READ             = 0x0010
PROCESS_VM_WRITE            = 0x0020
PROCESS_VM_OPERATION        = 0x0008
PROCESS_QUERY_INFORMATION   = 0x0400

MEM_COMMIT                  = 0x00001000
PAGE_NOACCESS               = 0x001
PAGE_GUARD                  = 0x100

_READABLE_PROTECTIONS = frozenset({0x02, 0x04, 0x08, 0x20, 0x40, 0x80})

_FULL_ACCESS = (
    PROCESS_VM_READ | PROCESS_VM_WRITE |
    PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION
)

# Chunks large buffers so we don't trigger MemoryErrors on Python side during huge block scans
MAX_REGION_BYTES = 16 * 1024 * 1024  # 16 MB

_kernel32.OpenProcess.restype  = wt.HANDLE
_kernel32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
_kernel32.CloseHandle.restype  = wt.BOOL
_kernel32.CloseHandle.argtypes = [wt.HANDLE]
_kernel32.GetLastError.restype  = wt.DWORD
_kernel32.GetLastError.argtypes = []
_kernel32.ReadProcessMemory.restype  = wt.BOOL
_kernel32.ReadProcessMemory.argtypes = [
    wt.HANDLE, ctypes.c_uint64, ctypes.c_void_p,
    ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t),
]
_kernel32.WriteProcessMemory.restype  = wt.BOOL
_kernel32.WriteProcessMemory.argtypes = [
    wt.HANDLE, ctypes.c_uint64, ctypes.c_void_p,
    ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t),
]
_kernel32.VirtualQueryEx.restype  = ctypes.c_size_t
_kernel32.VirtualQueryEx.argtypes = [
    wt.HANDLE, ctypes.c_uint64,
    ctypes.c_void_p, ctypes.c_size_t,
]


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

class DType(Enum):
    INT8    = "int8"
    INT16   = "int16"
    INT32   = "int32"
    INT64   = "int64"
    FLOAT   = "float"
    DOUBLE  = "double"


_DTYPE_FORMAT: dict[DType, str] = {
    DType.INT8:   "<b",
    DType.INT16:  "<h",
    DType.INT32:  "<i",
    DType.INT64:  "<q",
    DType.FLOAT:  "<f",
    DType.DOUBLE: "<d",
}

_DTYPE_SIZE: dict[DType, int] = {
    DType.INT8:   1,
    DType.INT16:  2,
    DType.INT32:  4,
    DType.INT64:  8,
    DType.FLOAT:  4,
    DType.DOUBLE: 8,
}

_DTYPE_LABELS: dict[str, DType] = {
    "Int8  (1 byte)":  DType.INT8,
    "Int16 (2 bytes)": DType.INT16,
    "Int32 (4 bytes)": DType.INT32,
    "Int64 (8 bytes)": DType.INT64,
    "Float":           DType.FLOAT,
    "Double":          DType.DOUBLE,
}

DTYPE_LABEL_LIST = list(_DTYPE_LABELS.keys())


def label_to_dtype(label: str) -> DType:
    return _DTYPE_LABELS.get(label, DType.INT32)


def parse_value(raw: str, dtype: DType) -> Any:
    """Parse a string into the appropriate Python type for *dtype*."""
    raw = raw.strip()
    if dtype in (DType.FLOAT, DType.DOUBLE):
        return float(raw)
    return int(raw, 0)   # 0 base allows 0x hex input


def fmt_value(value: Any, dtype: DType) -> str:
    """Format a value for display in the UI."""
    if dtype == DType.FLOAT:
        return f"{value:.4g}"
    if dtype == DType.DOUBLE:
        return f"{value:.6g}"
    return str(value)


# ---------------------------------------------------------------------------
# Scan conditions
# ---------------------------------------------------------------------------

class Condition(Enum):
    EXACT       = "Exact Value"
    BETWEEN     = "Between"
    INCREASED   = "Increased"
    DECREASED   = "Decreased"
    CHANGED     = "Changed"
    UNCHANGED   = "Unchanged"


CONDITION_LABELS = [c.value for c in Condition]


# ---------------------------------------------------------------------------
# Scan hit
# ---------------------------------------------------------------------------

@dataclass
class ScanHit:
    address:    int
    value:      Any       # current value (updated by next_scan / refresh)
    prev_value: Any = None


# ---------------------------------------------------------------------------
# MBI struct (64-bit compatible)
# ---------------------------------------------------------------------------

class _MBI(ctypes.Structure):
    _fields_ = [
        ("BaseAddress",       ctypes.c_uint64),
        ("AllocationBase",    ctypes.c_uint64),
        ("AllocationProtect", wt.DWORD),
        ("__align1",          wt.DWORD),
        ("RegionSize",        ctypes.c_uint64),
        ("State",             wt.DWORD),
        ("Protect",           wt.DWORD),
        ("Type",              wt.DWORD),
        ("__align2",          wt.DWORD),
    ]


# ---------------------------------------------------------------------------
# Low-level read / write
# ---------------------------------------------------------------------------

def _read_bytes(handle: int, address: int, size: int) -> bytes | None:
    buf  = ctypes.create_string_buffer(size)
    read = ctypes.c_size_t(0)
    ok   = _kernel32.ReadProcessMemory(handle, address, buf, size, ctypes.byref(read))
    if ok and read.value == size:
        return bytes(buf.raw)
    return None


def _write_bytes(handle: int, address: int, data: bytes) -> bool:
    buf      = ctypes.create_string_buffer(data)
    written  = ctypes.c_size_t(0)
    ok       = _kernel32.WriteProcessMemory(handle, address, buf, len(data), ctypes.byref(written))
    return bool(ok) and written.value == len(data)


def _unpack(data: bytes, dtype: DType) -> Any:
    return struct.unpack(_DTYPE_FORMAT[dtype], data)[0]


def _pack(value: Any, dtype: DType) -> bytes:
    if dtype in (DType.INT8, DType.INT16, DType.INT32, DType.INT64):
        value = int(value)
    else:
        value = float(value)
    return struct.pack(_DTYPE_FORMAT[dtype], value)


def _matches(
    value: Any,
    prev:  Any,
    condition: Condition,
    target: Any,
    target2: Any,
    dtype: DType,
) -> bool:
    """Return True if *value* / *prev* satisfy the scan condition."""
    if condition == Condition.EXACT:
        if dtype in (DType.FLOAT, DType.DOUBLE):
            return abs(value - target) < 0.001
        return value == target
    if condition == Condition.BETWEEN:
        lo, hi = min(target, target2), max(target, target2)
        return lo <= value <= hi
    if condition == Condition.INCREASED:
        return prev is not None and value > prev
    if condition == Condition.DECREASED:
        return prev is not None and value < prev
    if condition == Condition.CHANGED:
        return prev is not None and value != prev
    if condition == Condition.UNCHANGED:
        return prev is None or value == prev
    return False


# ---------------------------------------------------------------------------
# Region iterator
# ---------------------------------------------------------------------------

def _iter_readable_regions(handle: int) -> Iterator[tuple[int, int]]:
    address  = 0
    mbi      = _MBI()
    mbi_size = ctypes.sizeof(_MBI)
    while True:
        ret = _kernel32.VirtualQueryEx(handle, address, ctypes.byref(mbi), mbi_size)
        if ret == 0:
            break
        next_addr = mbi.BaseAddress + mbi.RegionSize
        if (
            mbi.State == MEM_COMMIT
            and mbi.Protect & ~PAGE_GUARD in _READABLE_PROTECTIONS
            and mbi.Protect != PAGE_NOACCESS
        ):
            yield mbi.BaseAddress, mbi.RegionSize
        if next_addr <= address:
            break
        address = next_addr


# ---------------------------------------------------------------------------
# ValueScanner
# ---------------------------------------------------------------------------

class ValueScanner:
    """
    Stateful CE-style value scanner.

    Usage::

        vs = ValueScanner(pid)
        count = vs.new_scan("100", DType.FLOAT, Condition.EXACT)
        # player takes damage…
        count = vs.next_scan("75", DType.FLOAT, Condition.EXACT)
        for hit in vs.hits:
            print(hex(hit.address), hit.value)
    """

    def __init__(self, pid: int) -> None:
        self.pid:  int             = pid
        self.hits: list[ScanHit]   = []
        self._handle: int | None   = None
        self._open()

    def _open(self) -> None:
        if self._handle:
            return
        h = _kernel32.OpenProcess(_FULL_ACCESS, False, self.pid)
        if not h:
            err = _kernel32.GetLastError()
            msg = (
                f"Access denied to PID {self.pid}.  Run SCRIBE as Administrator."
                if err == 5 else
                f"OpenProcess failed: error {err}"
            )
            raise PermissionError(msg)
        self._handle = h
        logger.info("Scanner opened PID=%d", self.pid)

    def close(self) -> None:
        if self._handle:
            _kernel32.CloseHandle(self._handle)
            self._handle = None

    def __del__(self) -> None:
        self.close()

    # ------------------------------------------------------------------

    def new_scan(
        self,
        value_str:  str,
        dtype:      DType,
        condition:  Condition,
        value2_str: str = "0",
        *,
        on_progress: object = None,
    ) -> int:
        """
        Scan entire process memory.  Replaces any previous results.
        Returns the number of addresses found.
        """
        self._open()
        self.hits = []

        try:
            target  = parse_value(value_str, dtype)
            target2 = parse_value(value2_str, dtype)
        except (ValueError, OverflowError) as exc:
            raise ValueError(f"Invalid value: {exc}") from exc

        step  = _DTYPE_SIZE[dtype]
        fmt   = _DTYPE_FORMAT[dtype]
        h     = self._handle

        regions = list(_iter_readable_regions(h))
        total   = len(regions)

        for done, (base, size) in enumerate(regions, start=1):
            if callable(on_progress):
                on_progress(done, total)

            # Chunk reads to circumvent huge gigabyte allocations causing MemoryErrors
            offset = 0
            while offset < size:
                chunk_size = min(MAX_REGION_BYTES, size - offset)
                data = _read_bytes(h, base + offset, chunk_size)
                
                if not data:
                    offset += chunk_size
                    continue

                base_addr = base + offset
                val_iter = struct.iter_unpack(fmt, data)

                # High performance unpacking path - circumvents python-side memory overhead by streaming hits
                if condition == Condition.EXACT:
                    if dtype in (DType.FLOAT, DType.DOUBLE):
                        for i, (val,) in enumerate(val_iter):
                            if abs(val - target) < 0.001:
                                self.hits.append(ScanHit(address=base_addr + (i * step), value=val))
                    else:
                        for i, (val,) in enumerate(val_iter):
                            if val == target:
                                self.hits.append(ScanHit(address=base_addr + (i * step), value=val))
                elif condition == Condition.BETWEEN:
                    lo, hi = min(target, target2), max(target, target2)
                    for i, (val,) in enumerate(val_iter):
                        if lo <= val <= hi:
                            self.hits.append(ScanHit(address=base_addr + (i * step), value=val))
                else:
                    for i, (val,) in enumerate(val_iter):
                        if _matches(val, None, condition, target, target2, dtype):
                            self.hits.append(ScanHit(address=base_addr + (i * step), value=val))

                offset += chunk_size

                # Crash-prevention: cap hits if user scans for common items (e.g., searching memory for '0')
                if len(self.hits) > 5_000_000:
                    raise OverflowError(
                        "Too many results found (> 5,000,000).\nPlease refine your scan criteria (e.g. avoid scanning for 0)."
                    )

        logger.info("new_scan: %d hits for pid=%d", len(self.hits), self.pid)
        return len(self.hits)

    def next_scan(
        self,
        value_str:  str,
        dtype:      DType,
        condition:  Condition,
        value2_str: str = "0",
        *,
        on_progress: object = None,
    ) -> int:
        """
        Narrow down existing results.  Re-reads each previously found
        address and filters to those still satisfying the condition.
        """
        if not self.hits:
            return 0

        self._open()

        try:
            target  = parse_value(value_str, dtype)
            target2 = parse_value(value2_str, dtype)
        except (ValueError, OverflowError) as exc:
            raise ValueError(f"Invalid value: {exc}") from exc

        step      = _DTYPE_SIZE[dtype]
        fmt       = _DTYPE_FORMAT[dtype]
        h         = self._handle
        surviving: list[ScanHit] = []
        total     = len(self.hits)

        for idx, hit in enumerate(self.hits):
            if callable(on_progress) and idx % 5000 == 0:
                on_progress(idx, total)

            raw = _read_bytes(h, hit.address, step)
            if raw is None:
                continue   # region unmapped — drop the hit
            try:
                new_val = struct.unpack(fmt, raw)[0]
            except struct.error:
                continue
            if _matches(new_val, hit.value, condition, target, target2, dtype):
                surviving.append(ScanHit(
                    address    = hit.address,
                    value      = new_val,
                    prev_value = hit.value,
                ))

        self.hits = surviving
        logger.info("next_scan: %d hits remaining for pid=%d", len(self.hits), self.pid)
        return len(self.hits)

    def read_address(self, address: int, dtype: DType) -> Any | None:
        """Read a single value from *address*."""
        self._open()
        raw = _read_bytes(self._handle, address, _DTYPE_SIZE[dtype])
        if raw is None:
            return None
        try:
            return struct.unpack(_DTYPE_FORMAT[dtype], raw)[0]
        except struct.error:
            return None

    def write_address(self, address: int, value: Any, dtype: DType) -> bool:
        """Write a single value to *address*.  Returns True on success."""
        self._open()
        try:
            data = _pack(value, dtype)
        except (ValueError, OverflowError, struct.error):
            return False
        return _write_bytes(self._handle, address, data)

    def clear(self) -> None:
        self.hits = []


# ---------------------------------------------------------------------------
# FreezeTable
# ---------------------------------------------------------------------------

@dataclass
class FreezeEntry:
    address: int
    dtype:   DType
    value:   Any
    frozen:  bool = True


class FreezeTable:
    """
    Maintains a list of addresses whose values can be frozen (constantly
    re-written) using a background thread.
    """

    _FREEZE_INTERVAL = 0.1   # seconds between writes

    def __init__(self, pid: int) -> None:
        self.pid:      int                     = pid
        self._entries: dict[int, FreezeEntry]  = {}   # address → entry
        self._lock     = threading.Lock()
        self._running  = False
        self._thread:  threading.Thread | None = None
        self._handle:  int | None              = None

    def _ensure_handle(self) -> None:
        if self._handle:
            return
        h = _kernel32.OpenProcess(_FULL_ACCESS, False, self.pid)
        if h:
            self._handle = h

    def add(self, address: int, dtype: DType, value: Any) -> None:
        with self._lock:
            self._entries[address] = FreezeEntry(address, dtype, value, frozen=True)
        self._ensure_running()

    def remove(self, address: int) -> None:
        with self._lock:
            self._entries.pop(address, None)

    def set_frozen(self, address: int, frozen: bool) -> None:
        with self._lock:
            if address in self._entries:
                self._entries[address].frozen = frozen

    def set_value(self, address: int, value: Any) -> None:
        with self._lock:
            if address in self._entries:
                self._entries[address].value = value

    def get_entries(self) -> list[FreezeEntry]:
        with self._lock:
            return list(self._entries.values())

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=1.0)
        if self._handle:
            _kernel32.CloseHandle(self._handle)
            self._handle = None

    def _ensure_running(self) -> None:
        if self._running:
            return
        self._ensure_handle()
        self._running = True
        self._thread  = threading.Thread(target=self._freeze_loop, daemon=True)
        self._thread.start()

    def _freeze_loop(self) -> None:
        while self._running:
            with self._lock:
                entries = list(self._entries.values())
            if self._handle:
                for entry in entries:
                    if entry.frozen:
                        try:
                            data = _pack(entry.value, entry.dtype)
                            _write_bytes(self._handle, entry.address, data)
                        except Exception:
                            pass
            time.sleep(self._FREEZE_INTERVAL)