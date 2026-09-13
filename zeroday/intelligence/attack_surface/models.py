"""Attack Surface Data Models for ZeroDay v2.0."""

from __future__ import annotations

import enum
import time
from dataclasses import asdict, dataclass, field
from typing import Any


class AssetType(enum.Enum):
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP = "ip"
    PORT_SERVICE = "port_service"
    ENDPOINT = "endpoint"
    PARAMETER = "parameter"
    APPLICATION = "application"
    FRONTEND = "frontend"
    BACKEND = "backend"
    DATABASE = "database"
    CLOUD_RESOURCE = "cloud_resource"
    CONTAINER = "container"


class AssetCriticality(enum.Enum):
    CRITICAL = "critical"  # Production DB, auth service, payment gateway
    HIGH = "high"  # Core API, user account service
    MEDIUM = "medium"  # Internal admin, staging API
    LOW = "low"  # Documentation site, public assets


class ExposureLevel(enum.Enum):
    INTERNET_FACING = "internet_facing"
    DMZ = "dmz"
    INTERNAL = "internal"
    AIR_GAPPED = "air_gapped"


@dataclass
class Asset:
    """Represents a discovered attack surface entity."""

    asset_id: str
    type: AssetType
    hostname: str = ""
    ip: str = ""
    port: int | None = None
    service: str = ""
    technology: str = ""
    environment: str = "production"  # production, staging, dev
    owner: str = ""
    criticality: AssetCriticality = AssetCriticality.MEDIUM
    exposure: ExposureLevel = ExposureLevel.INTERNET_FACING
    parent_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["type"] = self.type.value
        d["criticality"] = self.criticality.value
        d["exposure"] = self.exposure.value
        return d
