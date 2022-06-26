from logging import Filter
from typing import Dict, List

from starlette.requests import Request
from starlette.responses import Response

from fast_boot import logging
from fast_boot.matcher.request_matcher import RequestMatcher
from fast_boot.security_lite.access_decision_manager import AccessDecisionManager
from fast_boot.security_lite.authenticator import Authenticator
from fast_boot.security_lite.filter_chain import FilterChain


class FilterSecurityInterceptor(Filter):
    security_metadata_source: Dict[RequestMatcher, List[Dict]]
    authentication_manager: Authenticator
    access_decision_manager: AccessDecisionManager
    observe_one_per_request: bool = True

    async def do_filter(self, request: Request, response: Response, filter_chain: FilterChain) -> None:
        auth, user = await self.authentication_manager.authenticate(request)
        request.scope["auth"] = auth
        request.scope["user"] = user

        for matcher, attrs in self.security_metadata_source.items():
            if not matcher.matches(request):
                continue
            if request.app.debug:
                logging.debug(f"chain index: {request.scope.get('filter_chain_index') - 1}, {attrs}")
            self.access_decision_manager.decide(user, attrs)

        response = await filter_chain.do_filter(request, response)
        return response
