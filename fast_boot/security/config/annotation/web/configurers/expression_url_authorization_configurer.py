from typing import Any, Dict, Generic, List, TypeVar

from fast_boot.configurers.abstract_request_matcher_registry import (
    AbstractRequestMatcherRegistry
)
from fast_boot.context.application import ApplicationContext
from fast_boot.matcher.request_matcher import RequestMatcher
from fast_boot.security.abstract_configured_security_builder import (
    AbstractConfiguredSecurityBuilder
)
from fast_boot.security.access.expression import (
    SecurityExpressionHandler, WebExpressionVoter
)
from fast_boot.security.access.hierarchical_roles import (
    RoleHierarchy
)
from fast_boot.security.access.intercept.filter_security_interceptor import (
    FilterSecurityInterceptor
)
from fast_boot.security.access.permission_evaluator import (
    PermissionEvaluator
)
from fast_boot.security.access.security_metadata_source import (
    SecurityMetadataSource
)
from fast_boot.security.access.vote import AccessDecisionManager
from fast_boot.security.authentication import (
    AuthenticationTrustResolver, Authenticator
)
from fast_boot.security.config.annotation.security_builder import (
    Obj
)
from fast_boot.security.config.annotation.security_configurer_adapter import (
    SecurityConfigurerAdapter
)
from fast_boot.security.core import GrantedAuthorityDefaults
from fast_boot.security.security_core_prototype.config_attribute import (
    ConfigAttribute
)
from fast_boot.security.security_core_prototype.filter_invocation import (
    FilterInvocation
)
from fast_boot.security.security_core_prototype.security_config import (
    SecurityConfig
)

B = TypeVar("B", bound=AbstractConfiguredSecurityBuilder)


class ExpressionUrlAuthorizationConfigurer(SecurityConfigurerAdapter[Any, B], Generic[B]):
    filter_security_interceptor_one_per_request: bool = None
    access_decision_manager: 'AccessDecisionManager' = None
    # --- super
    security_builder: Any
    permit_all: str = "permitAll"
    deny_all: str = "denyAll"
    anonymous: str = "anonymous"
    authenticated: str = "authenticated"
    fully_authenticated = "fullyAuthenticated"
    remember_me = "rememberMe"
    role_prefix: str = "ROLE_"
    registry: 'ExpressionUrlAuthorizationConfigurer.ExpressionInterceptUrlRegistry'
    expression_handler: SecurityExpressionHandler[FilterInvocation] = None

    def __init__(self, context: ApplicationContext):
        super().__init__(context)
        self.registry = self.ExpressionInterceptUrlRegistry(context, self)

    def get_registry(self) -> 'ExpressionUrlAuthorizationConfigurer.ExpressionInterceptUrlRegistry':
        return self.registry

    def _intercept_url(self, request_matchers: List[RequestMatcher], config_attributes: List[ConfigAttribute]):
        for request_matcher in request_matchers:
            self.registry.add_mapping(self.ExpressionInterceptUrlRegistry.UrlMapping(request_matcher, config_attributes))

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

    def and_(self) -> Any:
        return self.security_builder

    def configure(self, http: B) -> None:
        metadata_source = self.create_metadata_source(http)
        if metadata_source:
            security_interceptor = self.create_filter_security_interceptor(http, metadata_source, http.get_shared_object(Authenticator))
            security_interceptor.observe_one_per_request = self.filter_security_interceptor_one_per_request

            # security_interceptor = self.post_process(security_interceptor)
            http.add_filter(security_interceptor)
            http.set_shared_object(FilterSecurityInterceptor, security_interceptor)

    def build(self) -> Obj:
        ...

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
            self.outer._intercept_url(self.request_matchers, SecurityConfig.create_list(attribute))
            return self.outer.registry

    class ExpressionInterceptUrlRegistry(AbstractRequestMatcherRegistry[B, AuthorizeUrl], Generic[B]):
        url_mappings: List['ExpressionUrlAuthorizationConfigurer.ExpressionInterceptUrlRegistry.UrlMapping'] = []
        unmapped_matchers: List[RequestMatcher]

        def __init__(self, context: ApplicationContext, outer: 'ExpressionUrlAuthorizationConfigurer'):
            super().__init__(outer)
            self.outer = outer
            self.context = context

        def chain_request_matchers(self, request_matchers: List[RequestMatcher]) -> 'ExpressionUrlAuthorizationConfigurer.AuthorizeUrl':
            self.unmapped_matchers = request_matchers
            return self.outer.AuthorizeUrl(request_matchers, self.outer)

        def add_mapping(self, url_mapping: 'UrlMapping'):
            self.unmapped_matchers = None
            self.url_mappings.append(url_mapping)

        def and_(self) -> B:
            return self.outer.and_()

        def create_request_map(self) -> Dict[RequestMatcher, List[ConfigAttribute]]:
            request_map = dict()
            u: ExpressionUrlAuthorizationConfigurer.ExpressionInterceptUrlRegistry.UrlMapping
            for mapping in self.url_mappings:
                matcher = mapping.request_matcher
                config_attrs: List[ConfigAttribute] = mapping.config_attrs
                request_map.update({matcher: config_attrs})
            return request_map

        class UrlMapping:
            def __init__(self, request_matcher: RequestMatcher, config_attrs: List[ConfigAttribute]):
                self.request_matcher = request_matcher
                self.config_attrs = config_attrs

    def get_decision_voters(self, http: B) -> List[WebExpressionVoter]:
        decision_voters = []
        # TODO change this
        expression_voter = WebExpressionVoter()
        expression_voter.expression_handler = self._get_expression_handler(http)
        decision_voters.append(expression_voter)
        return decision_voters

    def create_metadata_source(self, http: B) -> SecurityMetadataSource:
        request_map = self.registry.create_request_map()
        return SecurityMetadataSource(request_map, self._get_expression_handler(http))

    def _get_expression_handler(self, http: B) -> SecurityExpressionHandler:
        if self.expression_handler:
            return self.expression_handler
        else:
            handler = SecurityExpressionHandler()
            trust_resolver = http.get_shared_object(AuthenticationTrustResolver)
            handler.trust_resolver = trust_resolver

            context = http.get_shared_object(ApplicationContext)

            handler.role_hierarchy = context.get_bean(RoleHierarchy)

            granted_authority_default = context.get_bean(GrantedAuthorityDefaults)
            handler.default_role_prefix = granted_authority_default.get_role_prefix()

            handler.permission_evaluator = context.get_bean(PermissionEvaluator)
            # TODO: self.expression_handler = self.post_process(handler)
            self.expression_handler = handler
            return self.expression_handler

    def create_filter_security_interceptor(self, http: B, metadata_source: SecurityMetadataSource, authenticator: Authenticator) -> FilterSecurityInterceptor:
        interceptor = FilterSecurityInterceptor()
        interceptor.security_metadata_source = metadata_source
        interceptor.accession_decision_manager = self.get_access_decision_manager(http)
        interceptor.authentication_manager = authenticator
        interceptor.after_properties_set()
        return interceptor

    def create_default_access_decision_manager(self, http: B) -> 'AccessDecisionManager':
        return AccessDecisionManager(self.get_decision_voters(http))

    def get_access_decision_manager(self, http: B) -> 'AccessDecisionManager':
        if self.access_decision_manager is None:
            self.access_decision_manager = self.create_default_access_decision_manager(http)
        return self.access_decision_manager
