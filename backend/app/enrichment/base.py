from abc import ABC, abstractmethod
from typing import Any


class EnrichmentSource(ABC):
    name: str
    supported_ioc_types: list[str]
    rate_limit_per_min: int

    @abstractmethod
    async def query(self, ioc_type: str, value: str) -> dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        raise NotImplementedError