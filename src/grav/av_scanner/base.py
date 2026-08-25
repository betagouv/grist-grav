import enum
from abc import ABC, abstractmethod
from typing import BinaryIO


class AVScanResult(enum.Enum):
    SAFE = enum.auto()
    MALWARE = enum.auto()
    FAIL = enum.auto()


class BaseAVScanner(ABC):
    @abstractmethod
    async def process(self, files: list[BinaryIO]) -> AVScanResult:
        pass
