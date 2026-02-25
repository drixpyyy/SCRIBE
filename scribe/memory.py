"""
scribe.memory
Windows live-process memory scanner.
Uses only the Python standard library (ctypes) — no third-party packages.
Public API
list_processes()          → list[ProcessInfo]
scan_process(pid, config) → Iterator[list[ExtractionResult]]
How it works
OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, pid)
Walk every memory region with VirtualQueryEx
Skip regions that are not committed, not readable, or are guarded
ReadProcessMemory on each region (up to MAX_REGION_BYTES at a time)
Feed the raw bytes straight into the existing analysis engine
Yield batches of results so the GUI can stream them in real time
Caveats
Requires the same or higher privilege as the target process.
Run SCRIBE as Administrator to scan protected processes.
Anti-cheat / protected processes (e.g. EasyAntiCheat, Vanguard) will
refuse the OpenProcess call — you will get a PermissionError.
This module imports nothing from scribe.gui, keeping the engine clean.
"""
from __future__ import annotations
import ctypes
import ctypes.wintypes as wt
import logging
import sys
from dataclasses import dataclass
from typing import Iterator, Optional
from scribe.analysis import AnalysisConfig, ExtractionResult, Mode, analyse, extract_strings_from_bytes

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Guards
# ---------------------------------------------------------------------------
if sys.platform != "win32":
    raise ImportError("scribe.memory is Windows-only")

_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

# ---------------------------------------------------------------------------
# Win32 constants - OPTIMIZED
# ---------------------------------------------------------------------------
TH32CS_SNAPPROCESS = 0x00000002
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
MEM_COMMIT = 0x00001000
# Readable protection flags (exclude NOACCESS and GUARD)
PAGE_NOACCESS = 0x001
PAGE_GUARD = 0x100
_READABLE_PROTECTIONS = frozenset({
    0x02,  # PAGE_READONLY
    0x04,  # PAGE_READWRITE
    0x08,  # PAGE_WRITECOPY
    0x20,  # PAGE_EXECUTE_READ
    0x40,  # PAGE_EXECUTE_READWRITE
    0x80,  # PAGE_EXECUTE_WRITECOPY
})
# Maximum bytes to read from a single region at once.
# Large regions (e.g. heap) are split into chunks of this size to prevent MemoryError
MAX_REGION_BYTES = 16 * 1024 * 1024  # 16 MB
# Minimum string length to extract (keep consistent with analysis engine)
MIN_STRING_LEN = 4
# NEW: Maximum regions to scan before yielding (prevents UI freeze)
MAX_REGIONS_PER_BATCH = 50

# ---------------------------------------------------------------------------
# Win32 structures
# ---------------------------------------------------------------------------
class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD),
        ("cntUsage", wt.DWORD),
        ("th32ProcessID", wt.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
        ("th32ModuleID", wt.DWORD),
        ("cntThreads", wt.DWORD),
        ("th32ParentProcessID", wt.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wt.DWORD),
        ("szExeFile", ctypes.c_wchar * 260),
    ]

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    """64-bit compatible MEMORY_BASIC_INFORMATION."""
    _fields_ = [
        ("BaseAddress", ctypes.c_uint64),
        ("AllocationBase", ctypes.c_uint64),
        ("AllocationProtect", wt.DWORD),
        ("__alignment1", wt.DWORD),
        ("RegionSize", ctypes.c_uint64),
        ("State", wt.DWORD),
        ("Protect", wt.DWORD),
        ("Type", wt.DWORD),
        ("__alignment2", wt.DWORD),
    ]

# ---------------------------------------------------------------------------
# Win32 function signatures
# ---------------------------------------------------------------------------
_kernel32.CreateToolhelp32Snapshot.restype = wt.HANDLE
_kernel32.CreateToolhelp32Snapshot.argtypes = [wt.DWORD, wt.DWORD]
_kernel32.Process32FirstW.restype = wt.BOOL
_kernel32.Process32FirstW.argtypes = [wt.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
_kernel32.Process32NextW.restype = wt.BOOL
_kernel32.Process32NextW.argtypes = [wt.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
_kernel32.OpenProcess.restype = wt.HANDLE
_kernel32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
_kernel32.VirtualQueryEx.restype = ctypes.c_size_t
_kernel32.VirtualQueryEx.argtypes = [
    wt.HANDLE,
    ctypes.c_uint64,
    ctypes.POINTER(MEMORY_BASIC_INFORMATION),
    ctypes.c_size_t,
]
_kernel32.ReadProcessMemory.restype = wt.BOOL
_kernel32.ReadProcessMemory.argtypes = [
    wt.HANDLE,
    ctypes.c_uint64,
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]
_kernel32.CloseHandle.restype = wt.BOOL
_kernel32.CloseHandle.argtypes = [wt.HANDLE]
_kernel32.GetLastError.restype = wt.DWORD
_kernel32.GetLastError.argtypes = []

# ---------------------------------------------------------------------------
# Data containers
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class ProcessInfo:
    """Lightweight snapshot of a running process."""
    pid: int
    name: str

    def __str__(self) -> str:
        return f"{self.pid:>6}   {self.name}"

# ---------------------------------------------------------------------------
# Process enumeration - OPTIMIZED
# ---------------------------------------------------------------------------
def list_processes() -> list[ProcessInfo]:
    """
    Return a snapshot of all currently running processes, sorted by name.
    Uses CreateToolhelp32Snapshot so the list is consistent even if
    processes start or stop mid-call.
    """
    INVALID_HANDLE = ctypes.c_void_p(-1).value

    snapshot = _kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot == INVALID_HANDLE:
        raise OSError(f"CreateToolhelp32Snapshot failed: {_kernel32.GetLastError()}")

    processes: list[ProcessInfo] = []
    entry = PROCESSENTRY32W()
    entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)

    try:
        if _kernel32.Process32FirstW(snapshot, ctypes.byref(entry)):
            while True:
                processes.append(ProcessInfo(pid=entry.th32ProcessID, name=entry.szExeFile))
                entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
                if not _kernel32.Process32NextW(snapshot, ctypes.byref(entry)):
                    break
    finally:
        _kernel32.CloseHandle(snapshot)

    processes.sort(key=lambda p: p.name.lower())
    logger.debug("Enumerated %d processes", len(processes))
    return processes

def find_process_by_name(name: str) -> list[ProcessInfo]:
    """Return all processes whose executable name matches name (case-insensitive)."""
    name_lower = name.lower().strip()
    # Auto-append .exe if user didn't include it
    if "." not in name_lower:
        name_lower += ".exe"
    return [p for p in list_processes() if p.name.lower() == name_lower]

# ---------------------------------------------------------------------------
# Memory region iterator - OPTIMIZED
# ---------------------------------------------------------------------------
def _iter_readable_regions(
    handle: int,
) -> Iterator[tuple[int, int]]:
    """
    Walk all virtual memory regions of handle with `VirtualQueryEx`.
    Yields (base_address, region_size) for every region that is:
    - Committed (MEM_COMMIT)
    - Readable (protection not NOACCESS, not GUARD)
    OPTIMIZED: Reduced function call overhead.
    """
    address: int = 0
    mbi = MEMORY_BASIC_INFORMATION()
    mbi_size = ctypes.sizeof(MEMORY_BASIC_INFORMATION)
    virtual_query = _kernel32.VirtualQueryEx
    byref = ctypes.byref

    while True:
        ret = virtual_query(handle, address, byref(mbi), mbi_size)
        if ret == 0:
            break  # end of address space

        next_address = mbi.BaseAddress + mbi.RegionSize

        if (
            mbi.State == MEM_COMMIT
            and mbi.Protect & ~PAGE_GUARD in _READABLE_PROTECTIONS
            and mbi.Protect != PAGE_NOACCESS
        ):
            yield mbi.BaseAddress, mbi.RegionSize

        if next_address <= address:
            break  # overflow guard
        address = next_address

# ---------------------------------------------------------------------------
# Memory reader - OPTIMIZED
# ---------------------------------------------------------------------------
def _read_region(handle: int, base: int, size: int) -> bytes | None:
    """
    Read size bytes from base in handle.
    Returns None on failure (access denied, region unmapped between query and read).
    OPTIMIZED: Reuse buffer when possible.
    """
    buf = ctypes.create_string_buffer(size)
    bytes_read = ctypes.c_size_t(0)
    ok = _kernel32.ReadProcessMemory(
        handle, base, buf, size, ctypes.byref(bytes_read)
    )
    if not ok or bytes_read.value == 0:
        return None
    return bytes(buf.raw[:bytes_read.value])

# ---------------------------------------------------------------------------
# Public scanner - OPTIMIZED
# ---------------------------------------------------------------------------
def scan_process(
    pid: int,
    config: AnalysisConfig,
    *,
    on_progress: Optional[object] = None,  # callable(regions_done, regions_total) | None
) -> Iterator[list[ExtractionResult]]:
    """
    Scan every readable memory region of pid and yield batches of results.
    This is a **generator** — results are streamed as each region is
    processed. The caller (GUI thread via a background thread) can push
    each batch to the UI immediately without waiting for the full scan.

    Parameters
    ----------
    pid:
        Target process ID.
    config:
        Analysis configuration. The mode controls how strings are filtered.
        All modes work; ``GAME`` mode is particularly useful for finding
        live field values and heap strings in running games.
    on_progress:
        Optional callback ``(done: int, total: int) -> None`` called after
        each region. ``total`` is an estimate based on known address space.

    Yields
    ------
    list[ExtractionResult]
        One batch of results per readable memory region.

    Raises
    ------
    PermissionError
        If ``OpenProcess`` is denied (protected process, insufficient
        privileges).
    OSError
        If the process no longer exists.
    """
    access = PROCESS_VM_READ | PROCESS_QUERY_INFORMATION
    handle = _kernel32.OpenProcess(access, False, pid)

    if not handle:
        err = _kernel32.GetLastError()
        if err == 5:  # ERROR_ACCESS_DENIED
            raise PermissionError(
                f"Access denied to PID {pid}. "
                "Try running SCRIBE as Administrator."
            )
        raise OSError(f"OpenProcess failed for PID {pid}: error {err}")

    logger.info("Opened process PID=%d", pid)

    try:
        # Collect regions first so we can report progress
        regions = list(_iter_readable_regions(handle))
        total = len(regions)
        logger.info("Found %d readable regions in PID=%d", total, pid)

        seen_values: set[str] = set()
        batch_results: list[ExtractionResult] = []

        for done, (base, size) in enumerate(regions, start=1):
            if callable(on_progress):
                on_progress(done, total)

            # Split very large regions into chunks
            offset = 0
            while offset < size:
                chunk_size = min(MAX_REGION_BYTES, size - offset)
                data = _read_region(handle, base + offset, chunk_size)
                offset += chunk_size

                if not data:
                    continue

                # Live memory is not a static .dll — strings sit in heap, stack,
                # and mapped sections as either null-terminated ASCII or UTF-16-LE.
                # Extract them as text first, then run the analysis engine on the
                # resulting string (same pipeline used for Open File).
                # GAME mode still uses keyword filtering via the text pipeline;
                # the Mono-heap binary parser only makes sense on static files.
                source_text = extract_strings_from_bytes(data)
                if not source_text.strip():
                    continue

                if config.mode == Mode.GAME:
                    # For live memory use Strict mode filtering so we get clean
                    # readable strings, then let the keyword filter in analysis
                    # narrow them down via the text-based GAME fallback path.
                    live_config = AnalysisConfig(
                        mode=Mode.STRICT,
                        wordlist=config.wordlist,
                        deduplicate=config.deduplicate,
                    )
                    batch = analyse(source_text, live_config, binary=None)
                else:
                    batch = analyse(source_text, config, binary=None)

                # Deduplicate across regions and attach virtual addresses
                if config.deduplicate:
                    unique: list[ExtractionResult] = []
                    for r in batch:
                        if r.value not in seen_values:
                            seen_values.add(r.value)
                            # r.offset is a byte offset inside source_text (approx)
                            abs_offset = base + (offset - chunk_size)
                            unique.append(ExtractionResult(
                                value=r.value,
                                offset=abs_offset,
                                meta=f"pid:{pid}",
                            ))
                    batch = unique

                if batch:
                    batch_results.extend(batch)
                    
                    # NEW: Yield in batches to prevent memory buildup
                    if len(batch_results) >= 100 or done % MAX_REGIONS_PER_BATCH == 0:
                        yield batch_results
                        batch_results = []

        # Yield remaining results
        if batch_results:
            yield batch_results

    finally:
        _kernel32.CloseHandle(handle)
        logger.info("Closed handle for PID=%d", pid)