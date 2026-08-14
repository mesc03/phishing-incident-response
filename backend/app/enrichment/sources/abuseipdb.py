import httpx

from app.config import settings
from app.enrichment.base import EnrichmentSource


class AbuseIPDBSource(EnrichmentSource):
    name = "abuseipdb"
    supported_ioc_types = ["ip"]
    rate_limit_per_min = 60

    async def query(self, ioc_type: str, value: str) -> dict:
        if ioc_type not in self.supported_ioc_types:
            raise ValueError(f"{self.name} does not support ioc_type={ioc_type}")

        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": settings.ABUSEIPDB_API_KEY, "Accept": "application/json"},
                params={"ipAddress": value, "maxAgeInDays": 90},
            )
            resp.raise_for_status()
            return resp.json()

    def normalize(self, raw: dict) -> dict:
        score = raw.get("data", {}).get("abuseConfidenceScore", 0)
        if score > 75:
            verdict = "malicious"
        elif score > 25:
            verdict = "suspicious"
        else:
            verdict = "clean"
        return {"score": score, "verdict": verdict}