import re

from loguru import logger
from starlette import status
from starlette.requests import Request

from fast_boot import error_code
from fast_boot.exception import LOSException
from fast_boot.matcher.request_matcher import (
    AnyRequestMatcher, RegexRequestMatcher
)
from fast_boot.schemas import Filter
from fast_boot.security.access.security_metadata_source import (
    SecurityMetadataSource
)
from fast_boot.security.access.vote import AccessDecisionManager
from fast_boot.security.authentication import Authenticator


class FilterSecurityInterceptor(Filter):
    security_metadata_source: SecurityMetadataSource
    accession_decision_manager: AccessDecisionManager
    authentication_manager: Authenticator
    observe_one_per_request: bool = True

    async def do_filter(self, request: Request, response, filter_chain) -> None:

        auth, user = await self.authentication_manager.authenticate(request)
        request.scope["auth"] = auth
        request.scope["user"] = user

        for matcher, attrs in self.security_metadata_source.request_map.items():
            if matcher.matches(request) and type(matcher) == RegexRequestMatcher:
                logger.debug("matcher" + type(matcher).__name__)
                user_role_string = self.security_metadata_source.handler.expression_parser.parse(user.role_hierarchy, self.security_metadata_source.handler.default_role_prefix)
                for a in attrs:
                    expression = self.security_metadata_source.handler.expression_parser.parse_expression(a.get_attribute())
                    logger.debug(expression)
                    logger.debug(user_role_string)
                    if not bool(re.search(expression, user_role_string)):
                        raise LOSException.with_error(code=error_code.ACCESS_DENIED, status_code=status.HTTP_403_FORBIDDEN)
            elif type(matcher) == AnyRequestMatcher:
                ...

    def after_properties_set(self) -> None:
        ...
