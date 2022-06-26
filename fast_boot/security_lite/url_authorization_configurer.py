from typing import Generic, TypeVar, List, Dict, Tuple

from fast_boot.matcher.request_matcher import RequestMatcher, AnyRequestMatcher, RegexRequestMatcher, AntPathRequestMatcher
from fast_boot.security_lite.access_decision_manager import AccessDecisionManager
from fast_boot.security_lite.filters.filter_security_interceptor import FilterSecurityInterceptor
from fast_boot.security_lite.shared_objects import SharedObjects

B = TypeVar("B")
Obj = TypeVar("Obj")


class ExpressionUrlAuthorizationConfigurer(Generic[Obj, B]):
    security_builder: B
    permit_all: str = "permitAll"
    deny_all: str = "denyAll"
    anonymous: str = "anonymous"
    authenticated: str = "authenticated"
    fully_authenticated = "fullyAuthenticated"
    remember_me = "rememberMe"
    role_prefix: str = ""
    registry: 'ExpressionUrlAuthorizationConfigurer.ExpressionInterceptUrlRegistry'

    def __init__(self, shared_objects: SharedObjects):
        self.shared_objects = shared_objects
        self.registry = self.ExpressionInterceptUrlRegistry(self)

    def get_registry(self) -> 'ExpressionUrlAuthorizationConfigurer.ExpressionInterceptUrlRegistry':
        return self.registry

    def _intercept_url(self, request_matchers: List[RequestMatcher], config_attributes: List[str]):
        for request_matcher in request_matchers:
            self.registry.add_mapping((request_matcher, config_attributes))

    @staticmethod
    def has_any_role(rolePrefix: str, *authorities) -> Dict:
        # anyAuthorities = f"','{rolePrefix}".join(authorities)
        return {"hasAnyRole": list(authorities)}
        # return "{hasAnyRole('" + rolePrefix + anyAuthorities + "')"

    @staticmethod
    def has_role(rolePrefix: str, role: str) -> Dict:
        return {"hasRole": role}
        # return "hasRole('" + rolePrefix + role + "')"

    @staticmethod
    def has_authority(authority: str) -> Dict:
        return {"hasAuthority": authority}
        # return "hasAuthority('" + authority + "')"

    @staticmethod
    def has_any_authority(*authorities) -> Dict:
        return {"hasAnyAuthority": list(authorities)}
        # any_authorities = "','".join(authorities)
        # return "hasAnyAuthority('" + any_authorities + "')"

    def and_(self) -> B:
        return self.security_builder

    def init(self, builder: B) -> None:
        ...

    def configure(self, http: B):
        metadata_source = self.create_metadata_source(http)
        if metadata_source:
            security_interceptor = self.create_filter_security_interceptor(http, metadata_source)
            http.add_filter(security_interceptor)

    def create_filter_security_interceptor(self, http: B, metadata_source) -> FilterSecurityInterceptor:
        interceptor = FilterSecurityInterceptor()
        interceptor.security_metadata_source = metadata_source
        interceptor.authentication_manager = self.shared_objects.authenticator
        interceptor.access_decision_manager = AccessDecisionManager()
        return interceptor

    def create_metadata_source(self, http: B) -> Dict[RequestMatcher, List[str]]:
        request_map = self.registry.create_request_map()
        return request_map

    class AuthorizeUrl:
        request_matchers: List[RequestMatcher]
        _not: bool = False

        def __init__(self, request_matchers: List[RequestMatcher], outer: 'ExpressionUrlAuthorizationConfigurer'):
            self.request_matchers = request_matchers
            self.outer = outer

        def not_(self) -> 'ExpressionUrlAuthorizationConfigurer[B].AuthorizeUrl':
            self._not = True
            return self

        def has_role(self, role: str) -> 'ExpressionUrlAuthorizationConfigurer.ExpressionInterceptUrlRegistry':
            return self.access(ExpressionUrlAuthorizationConfigurer.has_role(self.outer.role_prefix, role))

        def has_any_role(self, *roles: str) -> 'ExpressionUrlAuthorizationConfigurer.ExpressionInterceptUrlRegistry':
            return self.access(ExpressionUrlAuthorizationConfigurer.has_any_role(self.outer.role_prefix, *roles))

        def has_authority(self, authority: str) -> 'ExpressionUrlAuthorizationConfigurer.ExpressionInterceptUrlRegistry':
            return self.access(ExpressionUrlAuthorizationConfigurer.has_authority(authority))

        def has_any_authority(self, *authorities) -> 'ExpressionUrlAuthorizationConfigurer.ExpressionInterceptUrlRegistry':
            return self.access(ExpressionUrlAuthorizationConfigurer.has_any_authority(*authorities))

        def permit_all(self) -> 'ExpressionUrlAuthorizationConfigurer.ExpressionInterceptUrlRegistry':
            return self.access({"permitAll": None})

        def anonymous(self) -> 'ExpressionUrlAuthorizationConfigurer.ExpressionInterceptUrlRegistry':
            return self.access({"anonymous": None})

        def deny_all(self) -> 'ExpressionUrlAuthorizationConfigurer.ExpressionInterceptUrlRegistry':
            return self.access({"denyAll": None})

        def authenticated(self) -> 'ExpressionUrlAuthorizationConfigurer.ExpressionInterceptUrlRegistry':
            return self.access({"authenticated": None})

        def access(self, attribute) -> 'ExpressionUrlAuthorizationConfigurer.ExpressionInterceptUrlRegistry':
            if self._not:
                attribute = "!" + attribute
            self.outer._intercept_url(self.request_matchers, [attribute])
            return self.outer.registry

    class ExpressionInterceptUrlRegistry:
        url_mappings: List[Tuple[RequestMatcher, List[str]]] = []

        def __init__(self, outer: 'ExpressionUrlAuthorizationConfigurer'):
            self.outer = outer

        def any_request(self) -> 'ExpressionUrlAuthorizationConfigurer.AuthorizeUrl':
            return self.request_matchers(AnyRequestMatcher.instance())

        def ant_matchers(self, *ant_patterns, method=None) -> 'ExpressionUrlAuthorizationConfigurer.AuthorizeUrl':
            if not ant_patterns:
                ant_patterns = ["/**"]
            return self.chain_request_matchers([AntPathRequestMatcher(pattern, method) for pattern in ant_patterns])

        def regex_matchers(self, *regex_patterns, method=None) -> 'ExpressionUrlAuthorizationConfigurer.AuthorizeUrl':
            return self.chain_request_matchers([RegexRequestMatcher(pattern, method) for pattern in regex_patterns])

        def request_matchers(self, *request_matchers: RequestMatcher) -> 'ExpressionUrlAuthorizationConfigurer.AuthorizeUrl':
            return self.chain_request_matchers(list(request_matchers))

        def chain_request_matchers(self, request_matchers: List[RequestMatcher]) -> 'ExpressionUrlAuthorizationConfigurer.AuthorizeUrl':
            return self.outer.AuthorizeUrl(request_matchers, self.outer)

        def add_mapping(self, url_mapping: Tuple[RequestMatcher, List[str]]):
            self.url_mappings.append(url_mapping)

        def and_(self) -> B:
            return self.outer.and_()

        def create_request_map(self) -> Dict[RequestMatcher, List[str]]:
            return {matcher: config_attrs for matcher, config_attrs in self.url_mappings}
