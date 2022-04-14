import abc
import re
from typing import Dict

from starlette.requests import Request


class RequestMatcher(abc.ABC):
    @abc.abstractmethod
    def matches(self, request: Request) -> bool:
        ...

    def matcher(self, request: Request) -> 'RequestMatcher.MatchResult':
        match = self.matches(request)
        return self.MatchResult(match, dict())

    class MatchResult:
        match: bool
        variables: Dict[str, str] = dict()

        def __init__(self, match: bool, variables: Dict[str, str]):
            self.match = match
            self.variables = variables

        @property
        def is_match(self) -> bool:
            return self.match

        @classmethod
        def match(cls, variables: Dict[str, str] = None) -> 'RequestMatcher.MatchResult':
            return cls(True, variables if variables else dict())

        @classmethod
        def not_match(cls) -> 'RequestMatcher.MatchResult':
            return cls(False, dict())


class RegexRequestMatcher(RequestMatcher):
    DEFAULT: int = 0
    pattern: re.Pattern
    http_method: str

    def __init__(self, pattern: str, http_method: str = None, case_insensitive: bool = None):
        self.pattern = re.compile(pattern, re.IGNORECASE if case_insensitive else 0)
        self.http_method = http_method

    def matches(self, request: Request) -> bool:
        if self.http_method is not None and request.method is not None and self.http_method.lower() != request.method.lower():
            return False
        else:
            return bool(self.pattern.match(str(request.url.replace(netloc='', scheme=''))))


class AntPathRequestMatcher(RequestMatcher):
    MATCH_ALL: str = "/**"
    matcher: 'Matcher'
    pattern: str
    http_method: str
    case_sensitive: bool
    url_path_helper: str

    def __init__(self, pattern: str, http_method: str = None, case_sensitive: bool = None, url_path_helper=None):
        self.case_sensitive = case_sensitive
        if not pattern == "/**" and not pattern == "**":
            if pattern.endswith("/**") and chr(63) not in pattern and chr(123) not in pattern and chr(125) not in pattern and pattern.index("*") == len(pattern) - 2:
                self.matcher = self.SubPathMatcher(pattern[0: len(pattern) - 3], case_sensitive)
            else:
                raise NotImplementedError()
                # self.matcher = self.SpringAntMatcher(pattern, case_sensitive)
        else:
            pattern = "/**"
            self.matcher = None
        self.pattern = pattern
        self.http_method = http_method
        self.url_path_helper = url_path_helper

    def matches(self, request: Request) -> bool:
        if self.http_method is not None and request.method and self.http_method.lower() != request.method.lower():
            return False
        elif self.pattern == "/**":
            return True
        else:
            return self.matcher.matches(request.url.path)

    def matcher(self, request: Request) -> 'RequestMatcher.MatchResult':
        if not self.matches(request):
            return self.MatchResult.not_match()
        elif self.matcher is None:
            return self.MatchResult.match()
        else:
            path = request.url.path
            return self.MatchResult.match(self.matcher.extract_uri_template_variables(path))

    class Matcher(abc.ABC):
        @abc.abstractmethod
        def matches(self, path: str) -> bool:
            ...

        @abc.abstractmethod
        def extract_uri_template_variables(self, path) -> Dict[str, str]:
            ...

    class SubPathMatcher(Matcher):

        sub_path: str
        length: int
        case_sensitive: bool

        def __init__(self, sub_path: str, case_sensitive: bool):
            self.sub_path = sub_path if case_sensitive else sub_path.lower()
            self.length = len(sub_path)
            self.case_sensitive = case_sensitive

        def matches(self, path: str) -> bool:
            if not self.case_sensitive:
                path = path.lower()

            return path.startswith(self.sub_path) and (len(path) == self.length or path[self.length: self.length + 1] == '/')

        def extract_uri_template_variables(self, path) -> Dict[str, str]:
            return dict()


class AnyRequestMatcher(RequestMatcher):
    _INSTANCE = None

    def __init__(self, *args, **kwargs):
        ...

    def matches(self, request: Request) -> bool:
        return True

    @classmethod
    def instance(cls, *args, **kwargs) -> 'AnyRequestMatcher':
        if not cls._INSTANCE:
            cls._INSTANCE = cls(*args, **kwargs)
        return cls._INSTANCE
