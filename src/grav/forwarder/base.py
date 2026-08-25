from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import BinaryIO

from starlette.requests import Request
from starlette.responses import Response


@dataclass
class FileInfo:
    filename: str
    file: BinaryIO
    content_type: str


class BaseForwarder(ABC):
    @abstractmethod
    async def forward(self, request: Request, fileinfos=None) -> Response:
        pass
