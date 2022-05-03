from starlette.responses import Response

from fast_boot.schemas import Filter


class BasicAuthenticationFilter(Filter):

    async def do_filter(self, request, response, filter_chain) -> Response:
        pass
