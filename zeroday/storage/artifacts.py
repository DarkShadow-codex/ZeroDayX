"""Artifact Manager for ZeroDay v2.0."""

from __future__ import annotations

import logging
from pathlib import Path


logger = logging.getLogger(__name__)


class ArtifactManager:
    """Manages file-based reports, logs, and evidence on disk."""

    def __init__(self, base_dir: Path | str) -> None:
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def get_run_dir(self, run_name: str) -> Path:
        d = self.base_dir / run_name
        d.mkdir(parents=True, exist_ok=True)
        return d
