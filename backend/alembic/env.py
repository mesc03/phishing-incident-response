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

router = APIRouter()


@router.post("/", response_model=IOCResponse)
async def submit_ioc(payload: IOCSubmitRequest, db: AsyncSession = Depends(get_db)):
    # 1. Get or create the IOC record
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
        # existing IOC was looked up again — bump last_seen
        ioc.last_seen = datetime.now(timezone.utc)
        await db.commit()

    enrichment_results = []

    if payload.ioc_type.value == "ip":
        source = AbuseIPDBSource()

        # 2. Check for a cached, non-expired result from this source
        cached = await db.execute(
            select(EnrichmentResult).where(
                EnrichmentResult.ioc_id == ioc.id,
                EnrichmentResult.source == source.name,
                EnrichmentResult.expires_at > datetime.now(timezone.utc),
            )
        )
        cached_result = cached.scalar_one_or_none()

        if cached_result:
            # 3a. Cache hit — use it, skip the API call entirely
            enrichment_results.append({
                "source": cached_result.source,
                "score": float(cached_result.score),
                "verdict": cached_result.verdict,
            })
        else:
            # 3b. Cache miss — call the API and store the result
            raw = await source.query("ip", payload.value)
            normalized = source.normalize(raw)

            new_result = EnrichmentResult(
                ioc_id=ioc.id,
                source=source.name,
                raw_response=raw,
                score=normalized["score"],
                verdict=normalized["verdict"],
                expires_at=datetime.now(timezone.utc) + timedelta(hours=settings.ENRICHMENT_CACHE_TTL_HOURS),
            )
            db.add(new_result)
            await db.commit()

            enrichment_results.append({
                "source": source.name,
                "score": normalized["score"],
                "verdict": normalized["verdict"],
            })

    return IOCResponse(
        id=ioc.id,
        ioc_type=ioc.ioc_type,
        value=ioc.value,
        first_seen=ioc.first_seen,
        last_seen=ioc.last_seen,
        enrichment_results=enrichment_results,
    )