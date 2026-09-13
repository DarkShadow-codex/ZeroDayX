"""OWASP Intelligence Package."""

from zeroday.intelligence.owasp.top10 import (
    OWASP_API_2023,
    OWASP_WEB_2021,
    OwaspCategory,
    lookup_owasp,
)


__all__ = [
    "OWASP_API_2023",
    "OWASP_WEB_2021",
    "OwaspCategory",
    "lookup_owasp",
]
