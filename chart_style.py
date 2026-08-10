#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unified matplotlib chart style for inspection reports.

Import ``apply_style()`` before creating any figures; the module-level
constants provide a shared colour palette and dimension presets.
"""
from __future__ import annotations

import matplotlib
import matplotlib.pyplot as plt
import warnings

# ensure non-GUI backend before any figure creation
matplotlib.use("Agg")

# ── CJK font support ──
_CJK_FONTS = ["Microsoft YaHei", "SimHei", "WenQuanYi Micro Hei", "Noto Sans CJK SC"]
# suppress "Glyph X missing from font" noise when some glyphs aren't in every font
warnings.filterwarnings("ignore", message="Glyph.*missing from font")

# ---------------------------------------------------------------------------
# colour palette — 8 distinguishable colours for multi-line charts
# ---------------------------------------------------------------------------
C0 = "#2563EB"           # blue — primary
C1 = "#DC2626"           # red — alert / critical
C2 = "#EA580C"           # orange — secondary
C3 = "#16A34A"           # green — healthy
C4 = "#9333EA"           # purple — tertiary
C5 = "#0891B2"           # teal — quaternary
C6 = "#DB2777"           # pink — quinary
C7 = "#D97706"           # amber — senary
GREY = "#9CA3AF"         # muted, background
DARK = "#111827"         # titles, labels
LIGHT_GRID = "#E5E7EB"   # grid lines
BACKGROUND = "#FFFFFF"   # chart background

COLORS = [C0, C1, C2, C3, C4, C5, C6, C7]

# ---------------------------------------------------------------------------
# series colour aliases for semantic use
# ---------------------------------------------------------------------------
CPU_USER = C0
CPU_SYSTEM = C2
CPU_IOWAIT = C1
CPU_STEAL = C4
MEM_USED = C1
MEM_AVAILABLE = C3
MEM_CACHED = C0
MEM_SWAP = C5
DISK_READ = C0
DISK_WRITE = C2
DISK_UTIL = C1
DISK_AWAIT = C4
NET_RX = C0
NET_TX = C2

# ---------------------------------------------------------------------------
# figure presets
# ---------------------------------------------------------------------------
FIG_SIZE = (10, 4.8)
FIG_DPI = 150
LINE_WIDTH = 1.5
GRID_ALPHA = 0.2
FONT_FAMILY = "sans-serif"
FONT_SIZE_TITLE = 13
FONT_SIZE_AXIS = 10
FONT_SIZE_TICK = 8.5
DATE_ROTATION = 30

# ---------------------------------------------------------------------------
# style application
# ---------------------------------------------------------------------------

_STYLE_APPLIED = False


def apply_style() -> None:
    """Apply the unified chart style to matplotlib rcParams.

    Idempotent — safe to call multiple times.
    """
    global _STYLE_APPLIED
    if _STYLE_APPLIED:
        return
    rc = {
        # figure
        "figure.facecolor": BACKGROUND,
        "figure.dpi": FIG_DPI,
        "figure.figsize": FIG_SIZE,
        # axes
        "axes.facecolor": BACKGROUND,
        "axes.edgecolor": GREY,
        "axes.grid": True,
        "axes.grid.axis": "y",
        "axes.axisbelow": True,
        "axes.prop_cycle": plt.cycler(color=COLORS),
        "axes.spines.top": False,
        "axes.spines.right": False,
        # grid
        "grid.color": LIGHT_GRID,
        "grid.alpha": GRID_ALPHA,
        "grid.linestyle": "-",
        "grid.linewidth": 0.5,
        # lines
        "lines.linewidth": LINE_WIDTH,
        "lines.markersize": 0,
        # text
        "font.family": FONT_FAMILY,
        "font.sans-serif": _CJK_FONTS,
        "axes.unicode_minus": False,
        "axes.titlesize": FONT_SIZE_TITLE,
        "axes.titleweight": "normal",
        "axes.labelsize": FONT_SIZE_AXIS,
        "xtick.labelsize": FONT_SIZE_TICK,
        "ytick.labelsize": FONT_SIZE_TICK,
        "xtick.color": GREY,
        "ytick.color": GREY,
        "legend.fontsize": 9,
        "legend.frameon": True,
        "legend.framealpha": 0.9,
        "legend.edgecolor": LIGHT_GRID,
        # save
        "savefig.dpi": FIG_DPI,
        "savefig.facecolor": BACKGROUND,
        "savefig.bbox": "tight",
        "savefig.pad_inches": 0.05,
    }
    matplotlib.rcParams.update(rc)
    _STYLE_APPLIED = True


def chart_colors() -> dict[str, str]:
    """Return colour mapping for manual chart construction (PIL fallback etc.)."""
    return {
        "primary": C0,
        "alert": C1,
        "highlight": C2,
        "normal": C3,
        "purple": C4,
        "teal": C5,
        "muted": GREY,
        "dark": DARK,
    }
