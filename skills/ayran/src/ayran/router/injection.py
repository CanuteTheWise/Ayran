"""Prompt-injection defense and three-strike quarantine."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

DEFAULT_DENYLIST = (
    r"<!--\s*SYSTEM\s*-->",
    r"<<SYS>>",
    r"</?system>",
    r"ignore (all|previous|prior) instructions",
    r"you are now",
    r"override (the )?(policy|scope)",
)

_COMPILED = tuple(re.compile(item, re.IGNORECASE) for item in DEFAULT_DENYLIST)


def looks_like_injection(text: str, extra: tuple[str, ...] = ()) -> bool:
    blob = text or ""
    patterns = _COMPILED + tuple(re.compile(item, re.IGNORECASE) for item in extra)
    return any(pattern.search(blob) for pattern in patterns)


@dataclass(slots=True)
class StrikeBook:
    counts: dict[str, int] = field(default_factory=dict)
    quarantined: set[str] = field(default_factory=set)

    def note(self, source_id: str, flagged: bool) -> bool:
        """Return True if the source is now quarantined."""

        if not flagged:
            return source_id in self.quarantined
        self.counts[source_id] = self.counts.get(source_id, 0) + 1
        if self.counts[source_id] >= 3:
            self.quarantined.add(source_id)
            return True
        return source_id in self.quarantined
