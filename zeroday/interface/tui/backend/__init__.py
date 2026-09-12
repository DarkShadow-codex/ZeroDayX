"""Backend bridge for external TUI clients."""

from zeroday.interface.tui.backend.controller import TuiController
from zeroday.interface.tui.backend.server import TuiBackendServer


__all__ = ["TuiBackendServer", "TuiController"]
