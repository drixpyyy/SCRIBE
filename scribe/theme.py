"""
scribe.theme
============
Theme definitions and system-font resolution for the SCRIBE GUI.
"""

from __future__ import annotations

import tkinter as tk
from dataclasses import dataclass
from typing import Literal

ThemeName = Literal["dark", "light"]

_UI_FONTS   = ["Inter", "SF Pro Display", "Segoe UI", "Helvetica Neue", "Arial"]
_CODE_FONTS = ["Cascadia Code", "Consolas", "JetBrains Mono", "Menlo", "Courier New"]


def _resolve_font(candidates: list[str], size: int, weight: str = "normal") -> tuple[str, int, str]:
    """Return the first available font from *candidates*, falling back to the last."""
    try:
        import tkinter.font as tkfont
        available = set(tkfont.families())
        for name in candidates:
            if name in available:
                return (name, size, weight)
    except Exception:
        pass
    return (candidates[-1], size, weight)


@dataclass(frozen=True)
class Palette:
    bg:        str
    nav:       str
    card:      str
    text:      str
    subtext:   str
    accent:    str
    border:    str
    hover:     str
    highlight: str
    success:   str
    danger:    str


THEMES: dict[ThemeName, Palette] = {
    "dark": Palette(
        bg        = "#0d0d0f",
        nav       = "#18181b",
        card      = "#18181b",
        text      = "#f4f4f5",
        subtext   = "#71717a",
        accent    = "#6366f1",      # indigo-500
        border    = "#27272a",
        hover     = "#27272a",
        highlight = "#f59e0b",      # amber-500
        success   = "#22c55e",
        danger    = "#ef4444",
    ),
    "light": Palette(
        bg        = "#fafafa",
        nav       = "#ffffff",
        card      = "#ffffff",
        text      = "#09090b",
        subtext   = "#71717a",
        accent    = "#6366f1",
        border    = "#e4e4e7",
        hover     = "#f4f4f5",
        highlight = "#f59e0b",
        success   = "#16a34a",
        danger    = "#dc2626",
    ),
}


class ThemeManager:
    """Manages the current theme and provides helper methods for widgets."""

    def __init__(self, initial: ThemeName = "dark") -> None:
        self._name: ThemeName = initial
        self._ui_font_cache:   dict[tuple, tuple] = {}
        self._code_font_cache: dict[tuple, tuple] = {}

    # ------------------------------------------------------------------
    @property
    def name(self) -> ThemeName:
        return self._name

    @property
    def palette(self) -> Palette:
        return THEMES[self._name]

    def toggle(self) -> None:
        self._name = "light" if self._name == "dark" else "dark"

    # ------------------------------------------------------------------
    def ui_font(self, size: int = 10, weight: str = "normal") -> tuple[str, int, str]:
        key = (size, weight)
        if key not in self._ui_font_cache:
            self._ui_font_cache[key] = _resolve_font(_UI_FONTS, size, weight)
        return self._ui_font_cache[key]

    def code_font(self, size: int = 11) -> tuple[str, int, str]:
        key = (size,)
        if key not in self._code_font_cache:
            self._code_font_cache[key] = _resolve_font(_CODE_FONTS, size)
        return self._code_font_cache[key]
