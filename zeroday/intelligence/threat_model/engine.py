"""Threat Modeling Engine for ZeroDay v2.0."""

from __future__ import annotations

import logging
import uuid
from typing import Any

from zeroday.intelligence.attack_surface.models import Asset, AssetType
from zeroday.intelligence.threat_model.models import (
    EntryPoint,
    SecurityControl,
    StrideCategory,
    Threat,
    ThreatActor,
    ThreatModel,
    TrustBoundary,
)


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

        # 3. Derive entry points and threats from assets
        for asset in assets:
            if asset.type in (AssetType.ENDPOINT, AssetType.DOMAIN, AssetType.SUBDOMAIN):
                ep = EntryPoint(
                    entry_id=f"EP-{asset.asset_id}",
                    name=asset.hostname or asset.service or "HTTP Endpoint",
                    protocol="https" if asset.port == 443 else "http",
                    target=asset.hostname or asset.ip,
                    auth_required=False,
                    trust_boundary_id="TB-INTERNET",
                )
                model.entry_points.append(ep)

                # Generate representative STRIDE threats
                model.threats.extend(self._generate_stride_threats(asset))

        # 4. Standard security controls
        model.controls = [
            SecurityControl(
                control_id="CTRL-WAF",
                name="Web Application Firewall (WAF)",
                type="preventative",
                effective=True,
            ),
            SecurityControl(
                control_id="CTRL-AUTHZ",
                name="Role-Based Access Control (RBAC)",
                type="preventative",
                effective=True,
            ),
            SecurityControl(
                control_id="CTRL-RATE",
                name="API Rate Limiting",
                type="preventative",
                effective=True,
            ),
        ]

        return model

    def _generate_stride_threats(self, asset: Asset) -> list[Threat]:
        threats = []
        # Tampering
        threats.append(
            Threat(
                threat_id=f"THREAT-T-{asset.asset_id}",
                title=f"Parameter tampering or injection on {asset.hostname or asset.asset_id}",
                stride_category=StrideCategory.TAMPERING,
                description="Attacker modifies request parameters to manipulate state or query backend",
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
                title=f"Broken access control / Privilege escalation on {asset.hostname or asset.asset_id}",
                stride_category=StrideCategory.ELEVATION_OF_PRIVILEGE,
                description="Attacker accesses unauthorized resources or executes privileged functions",
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
                title=f"Sensitive data exposure or verbose errors on {asset.hostname or asset.asset_id}",
                stride_category=StrideCategory.INFORMATION_DISCLOSURE,
                description="Server responds with stack traces, database metadata, or unmasked PII",
                affected_asset_id=asset.asset_id,
                attack_technique="T1592",
                owasp_category="A02:2021-Cryptographic Failures",
                severity="MEDIUM",
                mitigation="Mask sensitive data, disable debug modes in production",
            )
        )
        return threats
