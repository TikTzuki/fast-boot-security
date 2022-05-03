import abc

from starlette.requests import Request
from starlette.responses import Response


class FilterChain(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    async def do_filter(self, request: Request, response: Response):
        ...
