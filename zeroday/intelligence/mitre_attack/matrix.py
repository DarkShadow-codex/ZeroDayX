"""MITRE ATT&CK Framework Integration for ZeroDay v2.0."""

from __future__ import annotations

import enum
from dataclasses import asdict, dataclass, field
from typing import Any


class MitreTactic(enum.Enum):
    RECONNAISSANCE = "TA0043"
    RESOURCE_DEVELOPMENT = "TA0042"
    INITIAL_ACCESS = "TA0001"
    EXECUTION = "TA0002"
    PERSISTENCE = "TA0003"
    PRIVILEGE_ESCALATION = "TA0004"
    DEFENSE_EVASION = "TA0005"
    CREDENTIAL_ACCESS = "TA0006"
    DISCOVERY = "TA0007"
    LATERAL_MOVEMENT = "TA0008"
    COLLECTION = "TA0009"
    COMMAND_AND_CONTROL = "TA0011"
    EXFILTRATION = "TA0010"
    IMPACT = "TA0040"


@dataclass
class MitreTechnique:
    id: str  # e.g. T1190
    name: str  # e.g. Exploit Public-Facing Application
    tactic: MitreTactic
    sub_technique: str | None = None
    description: str = ""
    tested: bool = False
    detected: bool = False
    evidence_count: int = 0
    findings_count: int = 0


# Canonical web/cloud ATT&CK techniques
CANONICAL_TECHNIQUES: dict[str, MitreTechnique] = {
    "T1595": MitreTechnique(
        id="T1595",
        name="Active Scanning",
        tactic=MitreTactic.RECONNAISSANCE,
        description="Scanning IP blocks, ports, and web application paths",
    ),
    "T1592": MitreTechnique(
        id="T1592",
        name="Gather Victim Host Information",
        tactic=MitreTactic.RECONNAISSANCE,
        description="Identifying software versions, headers, technologies",
    ),
    "T1190": MitreTechnique(
        id="T1190",
        name="Exploit Public-Facing Application",
        tactic=MitreTactic.INITIAL_ACCESS,
        description="SQL injection, RCE, or SSRF in public endpoints",
    ),
    "T1059": MitreTechnique(
        id="T1059",
        name="Command and Scripting Interpreter",
        tactic=MitreTactic.EXECUTION,
        description="Command injection, bash, python execution",
    ),
    "T1068": MitreTechnique(
        id="T1068",
        name="Exploitation for Privilege Escalation",
        tactic=MitreTactic.PRIVILEGE_ESCALATION,
        description="Vertical privilege escalation, role tampering",
    ),
    "T1078": MitreTechnique(
        id="T1078",
        name="Valid Accounts",
        tactic=MitreTactic.DEFENSE_EVASION,
        description="Using default or stolen credentials",
    ),
    "T1110": MitreTechnique(
        id="T1110",
        name="Brute Force",
        tactic=MitreTactic.CREDENTIAL_ACCESS,
        description="Password spraying, credential stuffing",
    ),
    "T1552": MitreTechnique(
        id="T1552",
        name="Unsecured Credentials",
        tactic=MitreTactic.CREDENTIAL_ACCESS,
        description="Hardcoded secrets in source code or config",
    ),
    "T1083": MitreTechnique(
        id="T1083",
        name="File and Directory Discovery",
        tactic=MitreTactic.DISCOVERY,
        description="Directory fuzzing, sensitive file exposure",
    ),
    "T1082": MitreTechnique(
        id="T1082",
        name="System Information Discovery",
        tactic=MitreTactic.DISCOVERY,
        description="Environment variables, kernel version, cloud metadata",
    ),
    "T1041": MitreTechnique(
        id="T1041",
        name="Exfiltration Over C2 Channel",
        tactic=MitreTactic.EXFILTRATION,
        description="Data exfiltration via DNS, HTTP, or outbound tunnels",
    ),
}


class MitreCoverageMatrix:
    """Tracks ATT&CK coverage across test runs."""

    def __init__(self) -> None:
        self.techniques: dict[str, MitreTechnique] = {
            tid: MitreTechnique(
                id=t.id,
                name=t.name,
                tactic=t.tactic,
                sub_technique=t.sub_technique,
                description=t.description,
            )
            for tid, t in CANONICAL_TECHNIQUES.items()
        }

    def record_test(self, technique_id: str) -> None:
        if technique_id in self.techniques:
            self.techniques[technique_id].tested = True

    def record_detection(self, technique_id: str) -> None:
        if technique_id in self.techniques:
            self.techniques[technique_id].detected = True

    def record_finding(self, technique_id: str, evidence_count: int = 1) -> None:
        if technique_id in self.techniques:
            self.techniques[technique_id].tested = True
            self.techniques[technique_id].findings_count += 1
            self.techniques[technique_id].evidence_count += evidence_count

    def get_summary(self) -> dict[str, Any]:
        total = len(self.techniques)
        tested = sum(1 for t in self.techniques.values() if t.tested)
        detected = sum(1 for t in self.techniques.values() if t.detected)
        gaps = sum(1 for t in self.techniques.values() if t.tested and not t.detected)
        findings = sum(t.findings_count for t in self.techniques.values())

        return {
            "total_techniques": total,
            "tested_techniques": tested,
            "detected_techniques": detected,
            "detection_gaps": gaps,
            "total_findings": findings,
            "coverage_percent": round((tested / total) * 100, 1) if total else 0.0,
            "matrix": [
                {
                    "id": t.id,
                    "name": t.name,
                    "tactic": t.tactic.name,
                    "tactic_id": t.tactic.value,
                    "tested": t.tested,
                    "detected": t.detected,
                    "findings_count": t.findings_count,
                    "evidence_count": t.evidence_count,
                    "status": (
                        "DETECTED"
                        if t.detected
                        else ("GAP" if t.findings_count > 0 else ("TESTED" if t.tested else "UNTRIAGED"))
                    ),
                }
                for t in self.techniques.values()
            ],
        }
