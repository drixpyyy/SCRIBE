"""
scribe.export
=============
Export helpers for saving analysis results in multiple formats.
"""

from __future__ import annotations

import csv
import io
import json
import logging
from pathlib import Path

from scribe.analysis import ExtractionResult, Mode

logger = logging.getLogger(__name__)


def export_txt(results: list[ExtractionResult], path: Path) -> None:
    """Write results as plain text, one per line."""
    path.write_text("\n".join(r.value for r in results), encoding="utf-8")
    logger.info("Exported %d results → %s (txt)", len(results), path)


def export_json(
    results: list[ExtractionResult],
    path: Path,
    mode: Mode,
    source_path: str = "",
) -> None:
    """Write results as structured JSON."""
    payload = {
        "source": source_path,
        "mode": mode.name,
        "count": len(results),
        "results": [
            {"value": r.value, "offset": r.offset, "meta": r.meta}
            for r in results
        ],
    }
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    logger.info("Exported %d results → %s (json)", len(results), path)


def export_csv(
    results: list[ExtractionResult],
    path: Path,
    mode: Mode,
) -> None:
    """Write results as CSV with value / offset / meta columns."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["value", "offset", "meta", "mode"])
    for r in results:
        offset_str = f"0x{r.offset:08X}" if r.offset >= 0 else ""
        writer.writerow([r.value, offset_str, r.meta, mode.name])
    path.write_text(buf.getvalue(), encoding="utf-8")
    logger.info("Exported %d results → %s (csv)", len(results), path)
