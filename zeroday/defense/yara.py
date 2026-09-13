"""YARA Rule Generation Engine for ZeroDay v2.0."""

from __future__ import annotations

import re
import uuid

from zeroday.defense.detection import DetectionRule


class YaraRuleGenerator:
    """Generates standard YARA rules for suspicious scripts or artifacts."""

    @staticmethod
    def generate_rule(
        name: str,
        strings: list[str],
        technique_id: str = "T1059",
        description: str = "",
    ) -> DetectionRule:
        rule_id = f"YARA_{uuid.uuid4().hex[:8]}"
        clean_name = re.sub(r"\W+", "_", name).strip("_")

        str_entries = []
        for i, s in enumerate(strings):
            escaped = s.replace('"', '\\"')
            str_entries.append(f'        $s{i} = "{escaped}" ascii wide nocase')

        strings_block = "\n".join(str_entries)
        condition_str = "any of ($s*)" if len(strings) > 1 else "$s0"

        rule_text = f"""rule ZeroDay_{clean_name}_{rule_id} {{
    meta:
        description = "{description or name}"
        author = "ZeroDay Defense Engine"
        technique = "{technique_id}"
        date = "2026-09-13"
    strings:
{strings_block}
    condition:
        {condition_str}
}}"""
        return DetectionRule(
            rule_id=rule_id,
            name=name,
            format="yara",
            content=rule_text,
            technique_id=technique_id,
            severity="medium",
            tags=[technique_id, "yara"],
        )
