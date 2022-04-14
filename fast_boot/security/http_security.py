from typing import Any, Dict, List, Type, TypeVar

from starlette.requests import Request

from fast_boot.context.application import ApplicationContext
from fast_boot.matcher.request_matcher import (
    AnyRequestMatcher, RequestMatcher
)
from fast_boot.schemas import Filter
from fast_boot.security.authentication import Authenticator
from fast_boot.security.config.annotation.security_configurer_adapter import (
    SecurityConfigurerAdapter
)
from fast_boot.security.security_core_prototype.builders.filter_order_registration import (
    FilterOrderRegistration
)

from .abstract_configured_security_builder import (
    AbstractConfiguredSecurityBuilder
)
from .config.annotation.abstract_security_builder import (
    AbstractSecurityBuilder
)
from .config.annotation.web.configurers.expression_url_authorization_configurer import (
    ExpressionUrlAuthorizationConfigurer
)
from .config.annotation.web.security_filter_chain import SecurityFilterChain

T = TypeVar("T")


class HttpSecurity(AbstractSecurityBuilder[SecurityFilterChain, AbstractConfiguredSecurityBuilder]):
    authentication_manager: Authenticator
    request_matcher_configurer: 'RequestMatcherConfigurer'
    filter_orders: FilterOrderRegistration
    filters: List['OrderedFilter'] = []
    request_matcher: RequestMatcher

    def __init__(self, object_post_processor, authentication_builder, shared_objects: Dict[Type, Any]):
        super().__init__(object_post_processor)
        self.request_matcher = AnyRequestMatcher.instance()
        self.filter_orders = FilterOrderRegistration()
        self.shared_objects.update({Authenticator: authentication_builder})
        self.shared_objects.update(shared_objects)
        context = self.shared_objects.get(ApplicationContext)
        self.request_matcher_configurer = self.RequestMatcherConfigurer(context, self)

    def get_context(self):
        return self.shared_objects.get(ApplicationContext)

    def authorize_requests(self) -> "ExpressionUrlAuthorizationConfigurer.ExpressionInterceptUrlRegistry":
        context = self.get_context()
        return self._get_or_apply(ExpressionUrlAuthorizationConfigurer(context)).get_registry()

    def _get_or_apply(
            self, configurer: SecurityConfigurerAdapter[SecurityFilterChain, AbstractConfiguredSecurityBuilder]
    ) -> SecurityConfigurerAdapter[SecurityFilterChain, AbstractConfiguredSecurityBuilder]:
        existing_config = self.get_configurer(type(configurer))
        return existing_config if existing_config is not None else self.apply(configurer)

    def set_shared_object(self, shared_type: Type, obj: SecurityConfigurerAdapter[SecurityFilterChain, AbstractConfiguredSecurityBuilder]) -> None:
        self.shared_objects.update({shared_type: obj})

    def get_shared_object(self, shared_type: Type) -> Any:
        return self.shared_objects.get(shared_type)

    def perform_build(self) -> SecurityFilterChain:
        self.filters.sort(key=lambda f: f.order)
        sorted_filters: List[HttpSecurity.OrderedFilter] = []
        for flt in self.filters:
            sorted_filters.append(flt)
        return SecurityFilterChain(self.request_matcher, *sorted_filters)

    def add_filter_at_offset_of(self, flt: Filter, offset: int, registed_filter: Any):
        order = self.filter_orders.get_order(registed_filter) + offset
        self.filters.append(self.OrderedFilter(flt, order))
        self.filter_orders.put(type(flt), order)

    def add_filter(self, flt: Filter) -> 'HttpSecurity':
        order = self.filter_orders.get_order(type(flt))
        if order is None:
            raise Exception("The Filter class " + type(flt).__name__ + " does not have a registered order and cannot be added without a specified order.")
        self.filters.append(self.OrderedFilter(flt, order))
        return self

    class OrderedFilter(Filter):
        filter: Any = None

        def __init__(self, filter: Filter, order: int):
            self.filter = filter
            self.order = order

        async def do_filter(self, request: Request, response, filter_chain):
            await self.filter.do_filter(request, response, filter_chain)

    class RequestMatcherConfigurer:
        matchers: List[RequestMatcher] = []

        def __init__(self, context, outer: 'HttpSecurity'):
            self.context = context
            self.outer = outer

        def and_(self) -> 'HttpSecurity':
            return self.outer
