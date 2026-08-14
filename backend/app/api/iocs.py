from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.ioc import IOC
from app.schemas.ioc import IOCSubmitRequest, IOCResponse
from app.enrichment.sources.abuseipdb import AbuseIPDBSource

router = APIRouter()


@router.post("/", response_model=IOCResponse)
async def submit_ioc(payload: IOCSubmitRequest, db: AsyncSession = Depends(get_db)):
    # 1. Check if this IOC already exists, otherwise create it
    result = await db.execute(
        select(IOC).where(IOC.ioc_type == payload.ioc_type.value, IOC.value == payload.value)
    )
    ioc = result.scalar_one_or_none()

    if ioc is None:
        ioc = IOC(ioc_type=payload.ioc_type.value, value=payload.value)
        db.add(ioc)
        await db.commit()
        await db.refresh(ioc)

    # 2. Run enrichment (AbuseIPDB only supports IPs for now)
    enrichment_results = []
    if payload.ioc_type.value == "ip":
        source = AbuseIPDBSource()
        raw = await source.query("ip", payload.value)
        normalized = source.normalize(raw)
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