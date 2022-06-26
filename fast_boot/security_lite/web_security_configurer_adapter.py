from starlette.middleware.base import RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from fast_boot.context.application import ApplicationContext
from fast_boot.security_lite.authenticator import Authenticator
from fast_boot.security_lite.filter_chain import FilterChain
from fast_boot.security_lite.http_security import HttpSecurity
from fast_boot.security_lite.security_filter_chain import SecurityFilterChain
from fast_boot.security_lite.shared_objects import SharedObjects


class WebSecurityConfigurerAdapter:
    def __init__(self, shared_objects:SharedObjects, http: HttpSecurity):
        self.shared_objects = shared_objects
        self.http: HttpSecurity = http

    def get_http(self) -> HttpSecurity:
        if not self.http:
            self.http = HttpSecurity(self.shared_objects)
            self.apply_default_configuration(self.http)
            self.configure(self.http)
        return self.http

    def apply_default_configuration(self, http: HttpSecurity) -> None:
        ...

    def configure(self, http: HttpSecurity) -> None:
        ...

    def build(self) -> 'HyperFilterChain':
        return self.HyperFilterChain(self.get_http().build())

    def authenticator(self) -> Authenticator:
        ...

    def user_detail_service(self):
        ...

    def init(self, web):
        http = self.get_http()
        web.add_security_filter_chain_builder(http)

    class HyperFilterChain(FilterChain):
        def __init__(self, security_filter_chain: SecurityFilterChain):
            self.request_matcher = security_filter_chain.request_matcher
            self.ordered_filters = security_filter_chain.filters

        async def do_filter(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
            filter_chain_index = request.scope.get("filter_chain_index")
            if filter_chain_index is None:
                filter_chain_index = 0

            if filter_chain_index == len(self.ordered_filters):
                return await call_next(request)
            else:
                next_filter = self.ordered_filters[filter_chain_index]
                request.scope.update({"filter_chain_index": filter_chain_index + 1})
                return await next_filter.do_filter(request, call_next, self)
