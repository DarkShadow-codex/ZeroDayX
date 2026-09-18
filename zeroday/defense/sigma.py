"""Sigma Rule Generation Engine for ZeroDay v2.0."""

from __future__ import annotations

import uuid

from zeroday.defense.detection import DetectionRule


class SigmaRuleGenerator:
    """Generates standard Sigma YAML detection rules for validated findings and techniques."""

    @staticmethod
    def generate_web_rule(
        title: str,
        technique_id: str,
        path_pattern: str,
        method: str = "GET",
        severity: str = "high",
    ) -> DetectionRule:
        rule_id = f"SIGMA-{uuid.uuid4().hex[:8]}"
        yaml_content = f"""title: {title}
id: {rule_id}
status: test
description: Detects exploitation attempt against {path_pattern} identified by ZeroDay
author: ZeroDay Autonomous AI Red Team
date: 2026/09/13
references:
    - https://attack.mitre.org/techniques/{technique_id}
tags:
    - attack.{technique_id.lower()}
    - attack.initial_access
logsource:
    category: webserver
detection:
    selection:
        cs-method: '{method.upper()}'
        cs-uri-stem|contains: '{path_pattern}'
    condition: selection
falsepositives:
    - Authorized administrative activity
level: {severity.lower()}
"""
        return DetectionRule(
            rule_id=rule_id,
            name=title,
            format="sigma",
            content=yaml_content.strip(),
            technique_id=technique_id,
            severity=severity,
            tags=[f"attack.{technique_id.lower()}", "webserver"],
        )

    @staticmethod
    def generate_process_rule(
        title: str,
        technique_id: str,
        command_pattern: str,
        severity: str = "high",
    ) -> DetectionRule:
        rule_id = f"SIGMA-{uuid.uuid4().hex[:8]}"
        yaml_content = f"""title: {title}
id: {rule_id}
status: test
description: Detects command execution pattern identified by ZeroDay
author: ZeroDay Autonomous AI Red Team
date: 2026/09/13
tags:
    - attack.{technique_id.lower()}
    - attack.execution
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        CommandLine|contains: '{command_pattern}'
    condition: selection
level: {severity.lower()}
"""
        return DetectionRule(
            rule_id=rule_id,
            name=title,
            format="sigma",
            content=yaml_content.strip(),
            technique_id=technique_id,
            severity=severity,
            tags=[f"attack.{technique_id.lower()}", "process_creation"],
        )
