"""
scribe.analysis
===============
Core string extraction and analysis engine.
All analysis logic lives here, completely decoupled from the GUI.

Game Mode — how it works
------------------------
Rather than going through the slow text layer, Game mode operates directly on
raw bytes using two complementary strategies:

1.  **Mono / IL2CPP metadata string heap** — searches for the structured
    pattern documented in Unity/Mono binaries::

        [uint16_le  metadata_id] [0x00] [uint8 length] [ascii_bytes] [0x00]

    This is the ``#Strings`` heap in Mono metadata (ECMA-335 §24.2.3).
    Each entry has a stable 16-bit ID that can be used to cross-reference
    TypeDef / Field tables.

2.  **Null-terminated raw strings** — some sections store plain C-style
    strings without a length prefix.  These are found via a sliding-window
    scan for printable-ASCII runs terminated by ``0x00``.

Both passes filter by a curated set of game-engine field-name keywords so
only relevant results surface.  Results are sorted by file offset and
formatted as::

    fieldName    @0x001E9DA9  [mono id:0x0110  len:11]
"""

from __future__ import annotations

import logging
import re
import struct
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Iterator

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Analysis mode enum
# ---------------------------------------------------------------------------

class Mode(IntEnum):
    """String extraction modes, ordered by strictness / specialisation."""
    NORMAL = 0   # All printable ASCII — maximum coverage
    STRICT = 1   # Human-readable text, noise filtered
    ASM    = 2   # Aggressive: sentences only (readable through assembly noise)
    PATHS  = 3   # File system paths
    URL    = 4   # Network URLs / endpoints
    GAME   = 5   # Game engine field names + Mono metadata offsets
    UASM   = 6   # Dictionary-validated words (requires wordlist)


# ---------------------------------------------------------------------------
# Regex constants — compiled once at import time
# ---------------------------------------------------------------------------

_RE_ASCII_BYTES   = re.compile(rb"[ -~]{4,}")
_RE_WIDE_BYTES    = re.compile(rb"(?:[\x20-\x7E]\x00){4,}")
_RE_PRINTABLE     = re.compile(r"[ -~]{4,}")
_RE_STRICT        = re.compile(r"[a-zA-Z0-9 .:/\-_]{5,}")
_RE_ASM_WORDS     = re.compile(r"[a-zA-Z ]{8,}")
_RE_WIN_PATH      = re.compile(r"[a-zA-Z]:\\(?:[\w\s.\-]+\\)*[\w\s.\-]+\.\w+")
_RE_UNIX_PATH     = re.compile(r"/(?:[\w.\-]+/)+[\w.\-]+")
_RE_URL           = re.compile(
    r"(?:https?|wss?|ftp)://[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{4,}",
    re.IGNORECASE,
)
_RE_CONSONANT_RUN = re.compile(r"[^aeiouyAEIOUY\s]{5,}")
_RE_NOISE_PREFIX  = re.compile(r"^[IUPX](?=[A-Z]{7,})")
_RE_SAFE_SPLIT    = re.compile(r"[^\x20-\x7E]{2,}")

# Matches camelCase / PascalCase / underscore_names — typical field identifiers
_RE_FIELD_NAME    = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]{2,63}$")

# Register / noise prefixes seen in MSVC / LLVM compiled output
_NOISE_PREFIXES = frozenset(["WATA", "UVWA", "UATA", "VWAU", "USVW"])

# ---------------------------------------------------------------------------
# Game keyword sets
# ---------------------------------------------------------------------------

# Primary: exact substring match against the field name (case-insensitive)
_GAME_KEYWORDS_EXACT: frozenset[str] = frozenset({
    # player stats
    "health", "maxhealth", "armor", "ammo", "stamina", "mana", "energy",
    "lives", "score", "exp", "level",
    # movement
    "speed", "walkspeed", "runspeed", "sprintspeed", "maxspeed", "minspeed",
    "jumppower", "jumpforce", "jumpheight", "gravity", "friction",
    "acceleration", "deceleration", "velocity",
    # camera / aim
    "fov", "fieldofview", "sensitivity", "pitch", "yaw", "roll",
    "recoil", "spread", "bloom",
    # rendering / transforms
    "position", "rotation", "scale", "origin", "offset", "bone",
    "matrix", "vector", "hitbox", "bounds",
    # weapon
    "damage", "range", "fireRate", "firerate", "clipsize", "magazine",
    "reloadtime", "weaponid", "bulletspeed",
    # engine internals
    "localplayer", "entity", "player", "character", "pawn",
    "worldtoscreen", "viewangles", "playerbase",
    "int32", "float", "double", "bool",
    # Unity-specific
    "rigidbody", "transform", "collider", "animator",
    "networkedvar", "syncvar",
})

# Secondary: if the field name starts with one of these prefixes it's a match
_GAME_PREFIXES: tuple[str, ...] = (
    "m_", "f_", "b_", "i_", "n_",       # common member-var conventions
    "get", "set",                          # property accessors
    "max", "min", "base", "cur", "current",
)


# ---------------------------------------------------------------------------
# Data containers
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class ExtractionResult:
    """A single extracted string with optional metadata."""
    value:  str
    offset: int  = -1
    meta:   str  = ""

    def __str__(self) -> str:
        parts: list[str] = []
        if self.offset >= 0:
            parts.append(f"@0x{self.offset:08X}")
        if self.meta:
            parts.append(f"[{self.meta}]")
        parts.append(self.value)
        return "  ".join(parts)


@dataclass
class AnalysisConfig:
    """Configuration for a single analysis run."""
    mode:            Mode           = Mode.NORMAL
    min_length:      int            = 4
    deduplicate:     bool           = True
    include_offsets: bool           = False
    wordlist:        frozenset[str] = field(default_factory=frozenset)


# ---------------------------------------------------------------------------
# Wordlist loader
# ---------------------------------------------------------------------------

def load_wordlist(path: Path | str | None = None) -> frozenset[str]:
    """
    Load a line-separated word list into a frozenset for O(1) lookups.
    Falls back gracefully if the file is missing.
    """
    if path is None:
        path = Path(__file__).parent / "ASMFilter.txt"
    path = Path(path)
    if not path.exists():
        logger.warning("Wordlist not found: %s", path)
        return frozenset()
    try:
        with path.open(encoding="utf-8", errors="ignore") as fh:
            words = frozenset(
                line.strip().lower()
                for line in fh
                if len(line.strip()) > 1
            )
        logger.debug("Loaded %d words from wordlist", len(words))
        return words
    except OSError as exc:
        logger.error("Failed to load wordlist: %s", exc)
        return frozenset()


# ---------------------------------------------------------------------------
# Binary pre-processing
# ---------------------------------------------------------------------------

def extract_strings_from_bytes(data: bytes) -> str:
    """
    Extract both ASCII and UTF-16-LE strings from raw binary data and
    return them as a single newline-joined string ready for analysis.
    """
    ascii_strings = [s.decode("ascii", errors="ignore") for s in _RE_ASCII_BYTES.findall(data)]
    wide_strings  = [s.decode("utf-16-le", errors="ignore") for s in _RE_WIDE_BYTES.findall(data)]
    return "\n".join(ascii_strings + wide_strings)


def repair_wide_text(text: str) -> str:
    """
    Detect and repair UTF-16-LE text that was decoded as ASCII.
    Only operates on short single-line input — never on multi-line source
    data, to avoid collapsing newlines into a single massive string.
    """
    lines = text.splitlines(keepends=True)
    repaired: list[str] = []
    for line in lines:
        if len(line) > 6 and ("\x00" in line):
            pairs = re.findall(r"[a-zA-Z0-9]\x00", line)
            if len(pairs) > len(line) / 4:
                line = line.replace("\x00", "")
        repaired.append("".join(ch for ch in line if 31 < ord(ch) < 127 or ch in "\n\r"))
    return "".join(repaired)


# ---------------------------------------------------------------------------
# Per-mode filtering helpers
# ---------------------------------------------------------------------------

def _is_readable(text: str, mode: Mode, wordlist: frozenset[str]) -> bool:
    """Return True if *text* passes the readability heuristics for *mode*."""
    clean = text.strip()
    if len(clean) < 4:
        return False

    if len(clean) > 8 and _RE_NOISE_PREFIX.match(clean):
        clean = clean[1:]

    if mode == Mode.UASM:
        if not wordlist:
            return False
        tokens = clean.lower().split()
        if not tokens:
            return False
        hit_rate = sum(1 for w in tokens if w in wordlist) / len(tokens)
        return hit_rate >= 0.5

    if mode == Mode.ASM:
        if clean.isupper() and len(clean) > 5:
            vowel_ratio = len(re.findall(r"[AEIOUY]", clean)) / len(clean)
            if vowel_ratio < 0.25:
                return False
            if any(clean.startswith(p) for p in _NOISE_PREFIXES):
                return False
        if _RE_CONSONANT_RUN.search(clean):
            return False
        if not re.search(r"[aeiouyAEIOUY]", clean):
            return False

    return True


def _is_game_field(name: str) -> bool:
    """
    Return True if *name* looks like a game-engine field / property name.

    Accepts names that:
    - Are valid identifier-style strings (letters, digits, underscores)
    - Contain or start with a known game keyword
    """
    if not _RE_FIELD_NAME.match(name):
        return False
    low = name.lower()
    if any(kw in low for kw in _GAME_KEYWORDS_EXACT):
        return True
    if any(low.startswith(p) for p in _GAME_PREFIXES):
        return True
    return False


# ---------------------------------------------------------------------------
# Game mode — binary parsers
# ---------------------------------------------------------------------------

def _parse_mono_string_heap(data: bytes) -> list[ExtractionResult]:
    """
    Parse Mono / IL2CPP metadata ``#Strings`` heap entries.

    The on-disk layout (ECMA-335 §24.2.3, as observed in Unity builds) is::

        [uint16_le  id]  [0x00]  [uint8  length]  [ascii_bytes]  [0x00]

    This function scans the entire binary for this pattern, validates the
    decoded string against the game-keyword filter, and returns matching
    results with file offset and metadata (id + length).
    """
    results: list[ExtractionResult] = []
    i = 0
    data_len = len(data)

    while i < data_len - 6:
        # We need: byte[i+2] == 0x00 and byte[i+3] is a plausible length
        if data[i + 2] != 0x00:
            i += 1
            continue

        length = data[i + 3]
        if length < 3 or length > 128:
            i += 1
            continue

        string_start = i + 4
        string_end   = string_start + length

        if string_end >= data_len:
            i += 1
            continue

        # The byte after the string should be a null terminator
        if data[string_end] != 0x00:
            i += 1
            continue

        # All bytes in the string must be printable ASCII
        chunk = data[string_start:string_end]
        if not all(0x20 <= b <= 0x7E for b in chunk):
            i += 1
            continue

        name = chunk.decode("ascii")

        # The two bytes before the 0x00 separator form the metadata ID
        meta_id = struct.unpack_from("<H", data, i)[0]

        if _is_game_field(name):
            meta = f"mono id:0x{meta_id:04X}  len:{length}"
            results.append(ExtractionResult(value=name, offset=string_start, meta=meta))
            i = string_end + 1   # skip past this entry
        else:
            i += 1

    logger.debug("Mono heap scan: %d game fields found", len(results))
    return results


def _scan_null_terminated_strings(data: bytes) -> list[ExtractionResult]:
    """
    Scan for plain null-terminated ASCII strings (C-style, no length prefix).

    These appear in sections other than the Mono string heap — literal pools,
    debug info, resource tables.  Only strings passing the game-field filter
    are returned.
    """
    results: list[ExtractionResult] = []
    i = 0
    data_len = len(data)

    while i < data_len:
        # Skip non-printable bytes
        if not (0x20 <= data[i] <= 0x7E):
            i += 1
            continue

        # Collect printable run
        j = i
        while j < data_len and 0x20 <= data[j] <= 0x7E:
            j += 1

        if j < data_len and data[j] == 0x00:   # must be null-terminated
            name = data[i:j].decode("ascii", errors="ignore").strip()
            if _RE_FIELD_NAME.match(name) and _is_game_field(name):
                results.append(ExtractionResult(value=name, offset=i, meta="raw string"))
        i = j + 1

    logger.debug("Null-term scan: %d game fields found", len(results))
    return results


def _analyse_game_binary(binary: bytes) -> list[ExtractionResult]:
    """
    Run both binary game-field parsers and merge + deduplicate the results.
    Results are sorted by file offset.
    """
    mono    = _parse_mono_string_heap(binary)
    raw     = _scan_null_terminated_strings(binary)

    # Deduplicate by (value, offset) — prefer mono entries over raw
    seen:    set[tuple[str, int]] = set()
    merged:  list[ExtractionResult] = []

    for r in mono + raw:
        key = (r.value, r.offset)
        if key not in seen:
            seen.add(key)
            merged.append(r)

    merged.sort(key=lambda r: r.offset)
    return merged


# ---------------------------------------------------------------------------
# Main extraction engine
# ---------------------------------------------------------------------------

def analyse(
    source: str,
    config: AnalysisConfig,
    binary: bytes | None = None,
) -> list[ExtractionResult]:
    """
    Run string extraction on *source* (or *binary* for Game mode) using
    the given *config*.

    Parameters
    ----------
    source:
        Pre-processed text (output of :func:`extract_strings_from_bytes` or
        raw pasted text).  Not used in Game mode when *binary* is provided.
    config:
        Analysis configuration including mode and options.
    binary:
        Raw bytes of the original file.  **Required** for accurate Game mode
        results.  Optional for all other modes.

    Returns
    -------
    list[ExtractionResult]
        Deduplicated (when configured) list of results.
    """
    mode    = config.mode
    results: list[ExtractionResult] = []

    # Game mode skips the text layer entirely — works on raw bytes
    if mode == Mode.GAME:
        if binary:
            results = _analyse_game_binary(binary)
        else:
            # Fallback: text-layer keyword scan when no binary is available
            for line in source.splitlines():
                line = line.strip()
                if not line or not _is_game_field(line.split()[0]):
                    continue
                safe = _RE_SAFE_SPLIT.split(line)[0].strip()
                if len(safe) >= 3:
                    results.append(ExtractionResult(value=safe))
    else:
        cleaned = repair_wide_text(source)

        if mode == Mode.NORMAL:
            for match in _RE_PRINTABLE.finditer(source):
                results.append(ExtractionResult(value=match.group(), offset=match.start()))

        elif mode == Mode.STRICT:
            for match in _RE_STRICT.finditer(cleaned):
                token = match.group().strip()
                if _is_readable(token, Mode.STRICT, config.wordlist):
                    results.append(ExtractionResult(value=token))

        elif mode in (Mode.ASM, Mode.UASM):
            for match in _RE_ASM_WORDS.finditer(cleaned):
                token = match.group().strip()
                if _is_readable(token, mode, config.wordlist):
                    results.append(ExtractionResult(value=token))

        elif mode == Mode.PATHS:
            for pattern in (_RE_WIN_PATH, _RE_UNIX_PATH):
                for match in pattern.finditer(cleaned):
                    results.append(ExtractionResult(value=match.group()))

        elif mode == Mode.URL:
            for match in _RE_URL.finditer(cleaned):
                url = match.group().rstrip(".,;)'\"")
                results.append(ExtractionResult(value=url))

    if config.deduplicate and mode != Mode.GAME:
        # Game mode already deduplicates internally
        seen: set[str] = set()
        deduped: list[ExtractionResult] = []
        for r in results:
            if r.value not in seen:
                seen.add(r.value)
                deduped.append(r)
        results = deduped

    return results


def iter_results_text(results: list[ExtractionResult], show_meta: bool = True) -> Iterator[str]:
    """Yield each result as a formatted string, ready for display or export."""
    for r in results:
        yield str(r) if show_meta else r.value