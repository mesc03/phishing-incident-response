from datetime import datetime

from sqlalchemy import String, DateTime, Numeric, ForeignKey, JSON
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class EnrichmentResult(Base):
    __tablename__ = "enrichment_results"

    id: Mapped[int] = mapped_column(primary_key=True)
    ioc_id: Mapped[int] = mapped_column(ForeignKey("iocs.id", ondelete="CASCADE"))
    source: Mapped[str] = mapped_column(String(50), nullable=False)
    raw_response: Mapped[dict] = mapped_column(JSON, nullable=False)
    score: Mapped[float] = mapped_column(Numeric(5, 2))
    verdict: Mapped[str] = mapped_column(String(20))
    queried_at: Mapped[datetime] = mapped_column(DateTime, server_default="now()")
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)