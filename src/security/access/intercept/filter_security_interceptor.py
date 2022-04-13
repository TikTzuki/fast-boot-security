import re

from loguru import logger
from starlette import status
from starlette.requests import Request

from app.third_party.core import error_code
from app.third_party.core.exception import LOSException
from app.third_party.core.matcher.request_matcher import (
    AnyRequestMatcher, RegexRequestMatcher
)
from app.third_party.core.schemas import Filter
from app.third_party.core.security.access.security_metadata_source import (
    SecurityMetadataSource
)
from app.third_party.core.security.access.vote import AccessDecisionManager
from app.third_party.core.security.authentication import Authenticator


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
