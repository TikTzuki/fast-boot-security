import itertools
from typing import Dict, List

from starlette.requests import Request

from fast_boot.expression.expression_parser import ExpressionParser
from fast_boot.matcher.request_matcher import RequestMatcher
from fast_boot.security.access.expression import (
    SecurityExpressionHandler, WebExpressionAttribute
)
from fast_boot.security.security_core_prototype.config_attribute import (
    ConfigAttribute
)


class SecurityMetadataSource:
    request_map: Dict[RequestMatcher, List[ConfigAttribute]]

    def __init__(self, request_map: Dict[RequestMatcher, List[ConfigAttribute]], expression_handler: SecurityExpressionHandler):
        # TODO: self.request_map = self.process_map(request_map, expression_handler.get_expression_parser())
        self.request_map = request_map
        self.handler = expression_handler

    def get_attributes(self, request: Request) -> List[ConfigAttribute]:
        # request: Request = object.request
        for key, value in self.request_map.items():
            if key.matches(request):
                return value

    def get_all_config_attributes(self) -> List[ConfigAttribute]:
        return list(itertools.chain(*self.request_map.values()))

    def supports(self) -> bool:
        ...

    @staticmethod
    def process_map(request_map: Dict[RequestMatcher, List[ConfigAttribute]], parser: ExpressionParser) -> Dict[RequestMatcher, List[ConfigAttribute]]:
        processed: Dict[RequestMatcher, List[ConfigAttribute]] = dict()
        for request, value in request_map.items():
            processed.update(SecurityMetadataSource.process(parser, request, value))
        return processed

    @staticmethod
    def process(paser: ExpressionParser, request: RequestMatcher, value: List[ConfigAttribute]) -> Dict[RequestMatcher, List[ConfigAttribute]]:
        expression = SecurityMetadataSource._get_expression(request, value)
        processed: List[ConfigAttribute] = list()
        processed.append(WebExpressionAttribute(paser.parse_expression(expression)))
        return {request: processed}

    @staticmethod
    def _get_expression(request: RequestMatcher, value: List[ConfigAttribute]) -> str:
        return value[0].get_attribute()
