from typing import List

from starlette.requests import Request

from app.third_party.core.matcher.request_matcher import RequestMatcher
from app.third_party.core.schemas import Filter


class SecurityFilterChain:
    request_matcher: RequestMatcher
    filters: List[Filter]

    def __init__(self, request_matcher: RequestMatcher, *filters: Filter):
        self.request_matcher = request_matcher
        self.filters = list(filters)

    def matches(self, request: Request) -> bool:
        return self.request_matcher.matches(request)
