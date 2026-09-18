"""Suricata Rule Generation Engine for ZeroDay v2.0."""

from __future__ import annotations

import secrets

from zeroday.defense.detection import DetectionRule


class SuricataRuleGenerator:
    """Generates Suricata network IDS rules for network-level signatures."""

    @staticmethod
    def generate_http_rule(
        message: str,
        uri_pattern: str,
        technique_id: str = "T1190",
        sid: int | None = None,
    ) -> DetectionRule:
        rule_sid = sid or (secrets.randbelow(1_000_000) + 9_000_000)
        escaped_uri = uri_pattern.replace('"', '\\"')

        rule_text = (
            f'alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ZERODAY {message}"; '
            f'flow:established,to_server; http.uri; content:"{escaped_uri}"; nocase; '
            f"classtype:web-application-attack; sid:{rule_sid}; rev:1;)"
        )

        return DetectionRule(
            rule_id=f"SURICATA-{rule_sid}",
            name=message,
            format="suricata",
            content=rule_text,
            technique_id=technique_id,
            severity="high",
            tags=[technique_id, "suricata", "network_ids"],
        )
