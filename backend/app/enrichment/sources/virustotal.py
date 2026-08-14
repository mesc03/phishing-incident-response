import base64

import httpx

from app.config import settings
from app.enrichment.base import EnrichmentSource


class VirusTotalSource(EnrichmentSource):
    name = "virustotal"
    supported_ioc_types = ["ip", "domain", "url", "hash"]
    rate_limit_per_min = 4  # free tier limit

    async def query(self, ioc_type: str, value: str) -> dict:
        if ioc_type not in self.supported_ioc_types:
            raise ValueError(f"{self.name} does not support ioc_type={ioc_type}")

        endpoint = self._build_endpoint(ioc_type, value)

        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(
                endpoint,
                headers={"x-apikey": settings.VIRUSTOTAL_API_KEY},
            )
            resp.raise_for_status()
            return resp.json()

    def _build_endpoint(self, ioc_type: str, value: str) -> str:
        base = "https://www.virustotal.com/api/v3"
        if ioc_type == "ip":
            return f"{base}/ip_addresses/{value}"
        elif ioc_type == "domain":
            return f"{base}/domains/{value}"
        elif ioc_type == "hash":
            return f"{base}/files/{value}"
        elif ioc_type == "url":
            # VT requires URLs to be base64-encoded (no padding) as the identifier
            url_id = base64.urlsafe_b64encode(value.encode()).decode().strip("=")
            return f"{base}/urls/{url_id}"
        raise ValueError(f"Unsupported ioc_type: {ioc_type}")

    def normalize(self, raw: dict) -> dict:
        stats = (
            raw.get("data", {})
            .get("attributes", {})
            .get("last_analysis_stats", {})
        )
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) or 1  # avoid divide-by-zero

        # normalize detection ratio to a 0-100 scale
        score = round(((malicious * 2 + suspicious) / (total * 2)) * 100, 2)

        if malicious >= 2:
            verdict = "malicious"
        elif malicious == 1 or suspicious >= 1:
            verdict = "suspicious"
        else:
            verdict = "clean"

        return {"score": score, "verdict": verdict}