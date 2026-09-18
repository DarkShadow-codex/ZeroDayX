"""Threat Modeling Engine for ZeroDay v2.0."""

from __future__ import annotations

import logging
import uuid
from typing import TYPE_CHECKING

from zeroday.intelligence.attack_surface.models import AssetCriticality, ExposureLevel
from zeroday.intelligence.threat_model.models import (
    EntryPoint,
    SecurityControl,
    StrideCategory,
    Threat,
    ThreatActor,
    ThreatModel,
    TrustBoundary,
)


if TYPE_CHECKING:
    from zeroday.intelligence.attack_surface.models import Asset


logger = logging.getLogger(__name__)


class ThreatModelingEngine:
    """Derives threat models, entry points, and trust boundaries from discovered assets."""

    def __init__(self) -> None:
        pass

    def build_threat_model(
        self,
        target_name: str,
        assets: list[Asset],
        *,
        has_source: bool = False,
    ) -> ThreatModel:
        model = ThreatModel(
            model_id=f"TM-{uuid.uuid4().hex[:8]}",
            target_name=target_name,
        )

        # 1. Standard threat actors
        model.actors = [
            ThreatActor(
                name="External Attacker (Unauthenticated)",
                motivation="Data theft, unauthorized access, denial of service",
                capabilities="Automated scanners, custom exploit payloads, web fuzzer",
                access_level="anonymous",
            ),
            ThreatActor(
                name="Malicious Tenant / Low-Privilege User",
                motivation="Privilege escalation, cross-tenant data access (IDOR/BOLA)",
                capabilities="Authenticated API abuse, session hijacking, parameter tampering",
                access_level="authenticated_user",
            ),
        ]

        if has_source:
            model.actors.append(
                ThreatActor(
                    name="Malicious Contributor / Insider",
                    motivation="Supply chain compromise, backdoors",
                    capabilities="Source code access, pull requests",
                    access_level="insider",
                )
            )

        # 2. Trust boundaries
        tb_internet = TrustBoundary(
            boundary_id="TB-INTERNET",
            name="Internet / DMZ Boundary",
            description="Separates untrusted public internet clients from public facing endpoints",
        )
        tb_internal = TrustBoundary(
            boundary_id="TB-INTERNAL",
            name="Internal App / Data Tier Boundary",
            description="Separates web application services from internal databases and caches",
        )
        model.trust_boundaries = [tb_internet, tb_internal]

        # 3. Entry points
        for asset in assets:
            if asset.port:
                model.entry_points.append(
                    EntryPoint(
                        entry_id=f"EP-{asset.asset_id}",
                        name=f"Service on {asset.hostname or asset.ip}:{asset.port}",
                        protocol=asset.service or "tcp",
                        target=f"{asset.hostname or asset.ip}:{asset.port}",
                        auth_required=asset.criticality == AssetCriticality.CRITICAL,
                        trust_boundary_id=(
                            "TB-INTERNET"
                            if asset.exposure == ExposureLevel.INTERNET_FACING
                            else "TB-INTERNAL"
                        ),
                    )
                )

        # 4. Standard security controls
        model.controls = [
            SecurityControl(
                control_id="CTRL-WAF",
                name="Web Application Firewall (WAF)",
                type="preventative",
                protects_asset_ids=[a.asset_id for a in assets],
                effective=True,
            ),
            SecurityControl(
                control_id="CTRL-AUTH",
                name="JWT Authentication & RBAC Gatekeeper",
                type="preventative",
                protects_asset_ids=[a.asset_id for a in assets],
                effective=True,
            ),
            SecurityControl(
                control_id="CTRL-RATE-LIMIT",
                name="IP & Token Rate Limiter",
                type="preventative",
                protects_asset_ids=[a.asset_id for a in assets],
                effective=True,
            ),
        ]

        # 5. STRIDE threats per asset
        for asset in assets:
            model.threats.extend(self._generate_stride_threats(asset))

        return model

    def _generate_stride_threats(self, asset: Asset) -> list[Threat]:
        threats = []
        host_label = asset.hostname or asset.asset_id
        # Tampering
        threats.append(
            Threat(
                threat_id=f"THREAT-T-{asset.asset_id}",
                title=f"Parameter tampering or injection on {host_label}",
                stride_category=StrideCategory.TAMPERING,
                description=(
                    "Attacker modifies request parameters to manipulate state or query backend"
                ),
                affected_asset_id=asset.asset_id,
                attack_technique="T1190",
                owasp_category="A03:2021-Injection",
                severity="HIGH",
                mitigation="Input validation, parameterized statements",
            )
        )
        # Elevation of Privilege
        threats.append(
            Threat(
                threat_id=f"THREAT-E-{asset.asset_id}",
                title=f"Broken access control / Privilege escalation on {host_label}",
                stride_category=StrideCategory.ELEVATION_OF_PRIVILEGE,
                description=(
                    "Attacker accesses unauthorized resources or executes privileged functions"
                ),
                affected_asset_id=asset.asset_id,
                attack_technique="T1068",
                owasp_category="A01:2021-Broken Access Control",
                severity="HIGH",
                mitigation="Strict server-side authorization checks on all object identifiers",
            )
        )
        # Information Disclosure
        threats.append(
            Threat(
                threat_id=f"THREAT-I-{asset.asset_id}",
                title=f"Sensitive data exposure or verbose errors on {host_label}",
                stride_category=StrideCategory.INFORMATION_DISCLOSURE,
                description=(
                    "Server responds with stack traces, database metadata, or unmasked PII"
                ),
                affected_asset_id=asset.asset_id,
                attack_technique="T1592",
                owasp_category="A02:2021-Cryptographic Failures",
                severity="MEDIUM",
                mitigation="Mask sensitive data, disable debug modes in production",
            )
        )
        return threats
