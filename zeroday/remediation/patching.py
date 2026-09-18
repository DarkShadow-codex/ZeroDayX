"""Patch Generation & Safe Application Engine for ZeroDay v2.0."""

from __future__ import annotations

import difflib
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any


logger = logging.getLogger(__name__)


@dataclass
class ProposedPatch:
    file_path: str
    diff_text: str
    original_code: str
    patched_code: str
    description: str
    approved: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "file_path": self.file_path,
            "diff_text": self.diff_text,
            "description": self.description,
            "approved": self.approved,
        }


class PatchGenerator:
    """Generates unified diff patches without modifying files until explicit approval."""

    @staticmethod
    def create_diff(
        file_path: str,
        original_code: str,
        patched_code: str,
        description: str = "",
    ) -> ProposedPatch:
        diff_lines = list(
            difflib.unified_diff(
                original_code.splitlines(keepends=True),
                patched_code.splitlines(keepends=True),
                fromfile=f"a/{file_path}",
                tofile=f"b/{file_path}",
            )
        )
        diff_text = "".join(diff_lines)

        return ProposedPatch(
            file_path=file_path,
            diff_text=diff_text,
            original_code=original_code,
            patched_code=patched_code,
            description=description,
            approved=False,
        )

    @staticmethod
    def apply_patch(patch: ProposedPatch) -> bool:
        """Apply patch to file only if explicitly approved."""
        if not patch.approved:
            logger.error("Refusing to apply unapproved patch to %s", patch.file_path)
            raise PermissionError("Patch must be explicitly approved by human before application")

        try:
            Path(patch.file_path).write_text(patch.patched_code, encoding="utf-8")
        except Exception:
            logger.exception("Failed to write patched file %s", patch.file_path)
            return False
        else:
            logger.info("Successfully applied approved patch to %s", patch.file_path)
            return True
