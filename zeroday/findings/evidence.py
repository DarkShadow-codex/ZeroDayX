"""Evidence Vault for ZeroDay v2.0.

Provides tamper-evident, cryptographically hashed evidence storage with automated secret redaction.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from pathlib import Path
from typing import Any

from zeroday.tools.registry import redact_sensitive


logger = logging.getLogger(__name__)


class EvidenceVault:
    """Manages secure on-disk proof artifacts per confirmed finding."""

    def __init__(self, root_dir: Path | str) -> None:
        self.root_dir = Path(root_dir)
        self.evidence_dir = self.root_dir / "evidence"
        self.evidence_dir.mkdir(parents=True, exist_ok=True)

    def store_evidence(
        self,
        finding_id: str,
        *,
        scan_id: str,
        agent_id: str,
        request_text: str = "",
        response_text: str = "",
        commands_text: str = "",
        timeline_events: list[dict[str, Any]] | None = None,
        poc_files: dict[str, str] | None = None,
        screenshot_bytes: bytes | None = None,
    ) -> dict[str, str]:
        """Store all evidence artifacts for a finding and compute SHA-256 digests."""
        vault_path = self.evidence_dir / finding_id
        vault_path.mkdir(parents=True, exist_ok=True)

        hashes: dict[str, str] = {}

        # 1. request.txt (redacted)
        clean_req = redact_sensitive(request_text)
        req_bytes = clean_req.encode("utf-8")
        req_path = vault_path / "request.txt"
        req_path.write_bytes(req_bytes)
        hashes["request.txt"] = hashlib.sha256(req_bytes).hexdigest()

        # 2. response.txt (redacted)
        clean_resp = redact_sensitive(response_text)
        resp_bytes = clean_resp.encode("utf-8")
        resp_path = vault_path / "response.txt"
        resp_path.write_bytes(resp_bytes)
        hashes["response.txt"] = hashlib.sha256(resp_bytes).hexdigest()

        # 3. commands.txt (redacted)
        clean_cmds = redact_sensitive(commands_text)
        cmds_bytes = clean_cmds.encode("utf-8")
        cmds_path = vault_path / "commands.txt"
        cmds_path.write_bytes(cmds_bytes)
        hashes["commands.txt"] = hashlib.sha256(cmds_bytes).hexdigest()

        # 4. timeline.json
        timeline_path = vault_path / "timeline.json"
        timeline_data = timeline_events or []
        timeline_bytes = json.dumps(timeline_data, indent=2).encode("utf-8")
        timeline_path.write_bytes(timeline_bytes)
        hashes["timeline.json"] = hashlib.sha256(timeline_bytes).hexdigest()

        # 5. poc/ directory
        poc_dir = vault_path / "poc"
        poc_dir.mkdir(exist_ok=True)
        if poc_files:
            for fname, fcontent in poc_files.items():
                p_file = poc_dir / fname
                clean_content = redact_sensitive(fcontent)
                poc_bytes = clean_content.encode("utf-8")
                p_file.write_bytes(poc_bytes)
                hashes[f"poc/{fname}"] = hashlib.sha256(poc_bytes).hexdigest()

        # 6. screenshot.png (optional binary)
        if screenshot_bytes:
            ss_path = vault_path / "screenshot.png"
            ss_path.write_bytes(screenshot_bytes)
            hashes["screenshot.png"] = hashlib.sha256(screenshot_bytes).hexdigest()

        # 7. metadata.json
        metadata = {
            "finding_id": finding_id,
            "scan_id": scan_id,
            "agent_id": agent_id,
            "timestamp": time.time(),
            "file_count": len(hashes) + 2,  # including metadata.json and hashes.json
        }
        meta_path = vault_path / "metadata.json"
        meta_bytes = json.dumps(metadata, indent=2).encode("utf-8")
        meta_path.write_bytes(meta_bytes)
        hashes["metadata.json"] = hashlib.sha256(meta_bytes).hexdigest()

        # 8. hashes.json
        hashes_path = vault_path / "hashes.json"
        hashes_path.write_bytes(json.dumps(hashes, indent=2).encode("utf-8"))

        logger.info("Saved evidence vault for %s with %d artifacts", finding_id, len(hashes))
        return hashes

    def verify_vault_integrity(self, finding_id: str) -> tuple[bool, list[str]]:
        """Verify the cryptographic hashes of all files in an evidence vault."""
        vault_path = self.evidence_dir / finding_id
        hashes_path = vault_path / "hashes.json"
        if not hashes_path.exists():
            return False, ["hashes.json missing from evidence vault"]

        try:
            expected_hashes: dict[str, str] = json.loads(hashes_path.read_text(encoding="utf-8"))
        except Exception as e:
            return False, [f"Failed to read hashes.json: {e}"]

        mismatches: list[str] = []
        for rel_path, expected_hash in expected_hashes.items():
            f_path = vault_path / rel_path
            if not f_path.exists():
                mismatches.append(f"Missing file: {rel_path}")
                continue
            data = f_path.read_bytes()
            actual_hash = hashlib.sha256(data).hexdigest()
            if actual_hash != expected_hash:
                mismatches.append(f"Hash mismatch for {rel_path}: expected {expected_hash}, got {actual_hash}")

        return len(mismatches) == 0, mismatches
