from src.schemas import Filter


class IntegrationFilter(Filter):
    async def do_filter(self, request, response, filter_chain) -> None:
        pass
