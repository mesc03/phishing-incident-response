from datetime import datetime

from sqlalchemy import String, DateTime, func
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class IOC(Base):
    __tablename__ = "iocs"

    id: Mapped[int] = mapped_column(primary_key=True)
    ioc_type: Mapped[str] = mapped_column(String(20), nullable=False)  # ip, hash, domain, url
    value: Mapped[str] = mapped_column(String(512), nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    last_seen: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), onupdate=func.now())