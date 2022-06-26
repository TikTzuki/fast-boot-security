from typing import Generic, TypeVar, Type, Optional, Dict, List, Any

from starlette.requests import Request
from starlette.responses import Response

from fast_boot.matcher.request_matcher import AnyRequestMatcher
from fast_boot.schemas import Filter
from fast_boot.security_lite.filter_order_registration import FilterOrderRegistration
from fast_boot.security_lite.security_filter_chain import SecurityFilterChain
from fast_boot.security_lite.shared_objects import SharedObjects
from fast_boot.security_lite.url_authorization_configurer import ExpressionUrlAuthorizationConfigurer

Obj = TypeVar("Obj")
B = TypeVar("B")


class AbstractSecurityBuilder(Generic[Obj, B]):
    ...


class HttpSecurity(AbstractSecurityBuilder[SecurityFilterChain, 'HttpSecurity']):
    configurers: Dict[Type[ExpressionUrlAuthorizationConfigurer[SecurityFilterChain, 'HttpSecurity']], List[ExpressionUrlAuthorizationConfigurer[SecurityFilterChain, 'HttpSecurity']]]
    filters: List['OrderedFilter'] = []
    filter_orders: FilterOrderRegistration

    def __init__(self, shared_objects: SharedObjects):
        self.configurers = dict()
        self.request_matcher = AnyRequestMatcher.instance()
        self.filter_orders = FilterOrderRegistration()
        self.shared_objects = shared_objects

    def authorize_requests(self) -> 'ExpressionUrlAuthorizationConfigurer.ExpressionInterceptUrlRegistry':
        return self._get_or_apply(ExpressionUrlAuthorizationConfigurer(self.shared_objects)).get_registry()

    def _get_or_apply(self, configurer: ExpressionUrlAuthorizationConfigurer) -> ExpressionUrlAuthorizationConfigurer:
        existing_config = self.get_configurer(type(configurer))
        return existing_config if existing_config is not None else self.apply(configurer)

    def apply(self, configurer) -> ExpressionUrlAuthorizationConfigurer[SecurityFilterChain, 'HttpSecurity']:
        self.configurers.update({type(configurer): [configurer]})
        return configurer

    def get_configurer(
            self,
            clazz: Type[ExpressionUrlAuthorizationConfigurer[SecurityFilterChain, 'HttpSecurity']]
    ) -> Optional[ExpressionUrlAuthorizationConfigurer[SecurityFilterChain, 'HttpSecurity']]:
        configs = self.configurers.get(clazz)
        return configs[0] if configs else None

    def get_configurers(self) -> List[ExpressionUrlAuthorizationConfigurer[SecurityFilterChain, 'HttpSecurity']]:
        result = []
        for configs in self.configurers.values():
            result += configs
        return result

    def perform_build(self) -> SecurityFilterChain:
        self.filters.sort(key=lambda f: f.order)
        sorted_filters = [flt for flt in self.filters]
        return SecurityFilterChain(self.request_matcher, *sorted_filters)

    def add_filter_at_offset_of(self, flt: Filter, offset: int, registered_filter: Any):
        order = self.filter_orders.get_order(registered_filter) + offset
        self.filters.append(self.OrderedFilter(flt, order))
        self.filter_orders.put(type(flt), order)

    def add_filter(self, flt: Filter) -> 'HttpSecurity':
        order = self.filter_orders.get_order(type(flt))
        if order is None:
            raise Exception("The Filter class " + type(flt).__name__ + " does not have a registered order and cannot be added without a specified order.")
        self.filters.append(self.OrderedFilter(flt, order))
        return self

    def build(self) -> SecurityFilterChain:
        self.init()
        self.configure()
        return self.perform_build()

    def init(self) -> None:
        for conf in self.get_configurers():
            conf.init(self)

    def configure(self) -> None:
        for conf in self.get_configurers():
            conf.configure(self)

    class OrderedFilter(Filter):
        filter: Filter = None

        def __init__(self, filter: Filter, order: int):
            self.filter = filter
            self.order = order

        async def do_filter(self, request: Request, response, filter_chain) -> Response:
            return await self.filter.do_filter(request, response, filter_chain)
