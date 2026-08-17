"""Bounded Target-graph context packs for Prime ``before_agent_start``.

M5 owns the compiler. This module re-exports the M3 reconstruction contract
so existing imports keep working. Compilation never talks to the extension.
"""

from __future__ import annotations

from ayran.context.compiler import RECONSTRUCTION_TITLES, compile_context_pack

__all__ = ["RECONSTRUCTION_TITLES", "compile_context_pack"]
