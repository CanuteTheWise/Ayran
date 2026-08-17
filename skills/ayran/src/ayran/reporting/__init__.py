"""Report renderer and linter. Report generation never launches tools."""

from __future__ import annotations

from ayran.reporting.linter import lint
from ayran.reporting.renderer import render

__all__ = ["lint", "render"]
