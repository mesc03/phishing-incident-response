from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.models.ioc import IOC
from app.models.enrichment import EnrichmentResult
from app.schemas.ioc import IOCSubmitRequest, IOCResponse
from app.enrichment.sources.abuseipdb import AbuseIPDBSource
from app.enrichment.sources.virustotal import VirusTotalSource
from app.core.verdict import determine_verdict
from app.core.soc_summary import generate_soc_summary

router = APIRouter()

ALL_SOURCES = [AbuseIPDBSource(), VirusTotalSource()]


def utc_now_naive() -> datetime:
    """Postgres columns here are naive (no tz), so strip tzinfo after
    calculating in UTC — keeps comparisons/inserts consistent."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


async def get_or_fetch_enrichment(db: AsyncSession, ioc: IOC, source) -> dict:
    cached = await db.execute(
        select(EnrichmentResult).where(
            EnrichmentResult.ioc_id == ioc.id,
            EnrichmentResult.source == source.name,
            EnrichmentResult.expires_at > utc_now_naive(),
        )
    )
    cached_result = cached.scalar_one_or_none()

    if cached_result:
        return {
            "source": cached_result.source,
            "score": float(cached_result.score),
            "verdict": cached_result.verdict,
        }

    raw = await source.query(ioc.ioc_type, ioc.value)
    normalized = source.normalize(raw)

    new_result = EnrichmentResult(
        ioc_id=ioc.id,
        source=source.name,
        raw_response=raw,
        score=normalized["score"],
        verdict=normalized["verdict"],
        expires_at=utc_now_naive() + timedelta(hours=settings.ENRICHMENT_CACHE_TTL_HOURS),
    )
    db.add(new_result)
    await db.commit()

    return {"source": source.name, "score": normalized["score"], "verdict": normalized["verdict"]}


@router.post("/", response_model=IOCResponse)
async def submit_ioc(payload: IOCSubmitRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(IOC).where(IOC.ioc_type == payload.ioc_type.value, IOC.value == payload.value)
    )
    ioc = result.scalar_one_or_none()

    if ioc is None:
        ioc = IOC(ioc_type=payload.ioc_type.value, value=payload.value)
        db.add(ioc)
        await db.commit()
        await db.refresh(ioc)
    else:
        ioc.last_seen = utc_now_naive()
        await db.commit()

    enrichment_results = []
    for source in ALL_SOURCES:
        if payload.ioc_type.value in source.supported_ioc_types:
            try:
                result_data = await get_or_fetch_enrichment(db, ioc, source)
                enrichment_results.append(result_data)
            except Exception as e:
                enrichment_results.append({
                    "source": source.name,
                    "score": 0,
                    "verdict": f"error: {str(e)}",
                })

    # Combine everything into one verdict + SOC summary
    sources_attempted = sum(1 for s in ALL_SOURCES if payload.ioc_type.value in s.supported_ioc_types)
    verdict_data = determine_verdict(enrichment_results, sources_attempted)
    soc_summary = generate_soc_summary(payload.ioc_type.value, payload.value, verdict_data)

    return IOCResponse(
        id=ioc.id,
        ioc_type=ioc.ioc_type,
        value=ioc.value,
        first_seen=ioc.first_seen,
        last_seen=ioc.last_seen,
        enrichment_results=enrichment_results,
        verdict={
            "verdict": verdict_data["verdict"],
            "confidence": verdict_data["confidence"],
            "composite_score": verdict_data["reasoning"]["composite_score"],
            "soc_summary": soc_summary,
        },
    )