import abc
from typing import Generic, List, Optional, TypeVar

from fast_boot.context.application import ApplicationContext
from fast_boot.matcher.request_matcher import (
    AntPathRequestMatcher, AnyRequestMatcher, RegexRequestMatcher,
    RequestMatcher
)

C = TypeVar("C")
B = TypeVar("B")


class AbstractRequestMatcherRegistry(Generic[B, C]):
    context: ApplicationContext
    ANY_REQUEST: 'RequestMatcher' = AnyRequestMatcher.instance()
    any_request_configured: bool = False

    def __init__(self, outer):
        self.outer = outer

    def any_request(self) -> C:
        configurer = self.request_matchers(self.ANY_REQUEST)
        self.any_request_configured = True
        return configurer

    def ant_matchers(self, method=None, *ant_patterns) -> C:
        if not ant_patterns:
            ant_patterns = ["/**"]
        return self.chain_request_matchers(self.RequestMatchers.ant_matcher(method, *ant_patterns))

    def regex_matchers(self, method=None, *regex_patterns) -> C:
        return self.chain_request_matchers(self.RequestMatchers.regex_matchers(method, *regex_patterns))

    def request_matchers(self, *request_matchers: RequestMatcher) -> C:
        return self.chain_request_matchers(list(request_matchers))

    @abc.abstractmethod
    def chain_request_matchers(self, request_matchers: List[RequestMatcher]) -> C:
        ...

    class RequestMatchers:
        @staticmethod
        def ant_matcher(http_method: Optional[str] = None, *ant_patterns: str) -> List[RequestMatcher]:
            return [AntPathRequestMatcher(pattern, http_method) for pattern in ant_patterns]

        @staticmethod
        def regex_matchers(http_method: Optional[str] = None, *regex_patterns: str) -> List[RequestMatcher]:
            return [RegexRequestMatcher(pattern, http_method) for pattern in regex_patterns]
