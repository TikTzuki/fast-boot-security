from typing import List

from starlette.requests import Request

from fast_boot.matcher.request_matcher import RequestMatcher
from fast_boot.schemas import Filter


class SecurityFilterChain:
    request_matcher: RequestMatcher
    filters: List[Filter]

    def __init__(self, request_matcher: RequestMatcher, *filters: Filter):
        self.request_matcher = request_matcher
        self.filters = list(filters)

    def matches(self, request: Request) -> bool:
        return self.request_matcher.matches(request)
