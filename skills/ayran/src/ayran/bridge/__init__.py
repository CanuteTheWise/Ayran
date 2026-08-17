"""M3 Prime lifecycle bridge methods served over the M2 UDS JSON-RPC sidecar.

The TypeScript extension never writes journals or SQLite. Every context pack,
policy decision, session/child record, and shutdown checkpoint is produced here
and returned over the owner-only socket.
"""

from .handler import BridgeDispatcher, build_dispatcher

__all__ = ["BridgeDispatcher", "build_dispatcher"]
