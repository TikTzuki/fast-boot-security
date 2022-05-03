from typing import Generic, TypeVar, Any, List, Dict, Tuple

from fast_boot import logging
from fast_boot.security.access.security_metadata_source import SecurityMetadataSource

from fast_boot.matcher.request_matcher import RequestMatcher, AnyRequestMatcher, RegexRequestMatcher, AntPathRequestMatcher

from fast_boot.context.application import ApplicationContext
from fast_boot.security_lite.access_decision_manager import AccessDecisionManager
from fast_boot.security_lite.authenticator import Authenticator
from fast_boot.security_lite.filters.filter_security_interceptor import FilterSecurityInterceptor

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

    def __init__(self, context: ApplicationContext):
        self.context = context
        self.registry = self.ExpressionInterceptUrlRegistry(context, self)

    def get_registry(self) -> 'ExpressionUrlAuthorizationConfigurer.ExpressionInterceptUrlRegistry':
        return self.registry

    def _intercept_url(self, request_matchers: List[RequestMatcher], config_attributes: List[str]):
        for request_matcher in request_matchers:
            self.registry.add_mapping((request_matcher, config_attributes))

    @staticmethod
    def has_any_role(rolePrefix: str, *authorities) -> str:
        anyAuthorities = f"','{rolePrefix}".join(authorities)
        return "hasAnyRole('" + rolePrefix + anyAuthorities + "')"

    @staticmethod
    def has_role(rolePrefix: str, role: str) -> str:
        return "hasRole('" + rolePrefix + role + "')"

    @staticmethod
    def has_authority(authority: str) -> str:
        return "hasAuthority('" + authority + "')"

    @staticmethod
    def has_any_authority(*authorities) -> str:
        any_authorities = "','".join(authorities)
        return "hasAnyAuthority('" + any_authorities + "')"

    def and_(self) -> B:
        return self.security_builder

    def init(self, builder: B) -> None:
        ...

    def configure(self, http: B):
        metadata_source = self.create_metadata_source(http)
        if metadata_source:
            security_interceptor = self.create_filter_security_interceptor(http, metadata_source, self.context.get_bean(Authenticator))
            http.add_filter(security_interceptor)

    def create_filter_security_interceptor(self, http: B, metadata_source, authenticator: Authenticator) -> FilterSecurityInterceptor:
        interceptor = FilterSecurityInterceptor()
        interceptor.security_metadata_source = metadata_source
        if self.context.debug:
            logging.debug(metadata_source)
        interceptor.authentication_manager = authenticator
        interceptor.access_decision_manager = self.context.get_bean(AccessDecisionManager)
        return interceptor

    def create_metadata_source(self, http: B) -> Dict[RequestMatcher, list[str]]:
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
            return self.access("permitAll")

        def anonymous(self) -> 'ExpressionUrlAuthorizationConfigurer.ExpressionInterceptUrlRegistry':
            return self.access("anonymous")

        def deny_all(self) -> 'ExpressionUrlAuthorizationConfigurer.ExpressionInterceptUrlRegistry':
            return self.access("denyAll")

        def authenticated(self) -> 'ExpressionUrlAuthorizationConfigurer.ExpressionInterceptUrlRegistry[B]':
            return self.access("authenticated")

        def access(self, attribute) -> 'ExpressionUrlAuthorizationConfigurer.ExpressionInterceptUrlRegistry':
            if self._not:
                attribute = "!" + attribute
            self.outer._intercept_url(self.request_matchers, [attribute])
            return self.outer.registry

    class ExpressionInterceptUrlRegistry:
        url_mappings: List[Tuple[RequestMatcher, List[str]]] = []

        def __init__(self, context: ApplicationContext, outer: 'ExpressionUrlAuthorizationConfigurer'):
            self.context = context
            self.outer = outer

        def any_request(self) -> 'ExpressionUrlAuthorizationConfigurer.AuthorizeUrl':
            return self.request_matchers(AnyRequestMatcher.instance())

        def ant_matchers(self, method=None, *ant_patterns) -> 'ExpressionUrlAuthorizationConfigurer.AuthorizeUrl':
            if not ant_patterns:
                ant_patterns = ["/**"]
            return self.chain_request_matchers([AntPathRequestMatcher(pattern, method) for pattern in ant_patterns])

        def regex_matchers(self, method=None, *regex_patterns) -> 'ExpressionUrlAuthorizationConfigurer.AuthorizeUrl':
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
