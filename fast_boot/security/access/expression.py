from typing import Any, Generic, List, Optional, TypeVar

from fastapi.security import HTTPBasicCredentials

from fast_boot.expression.expression_parser import (
    Expression, ExpressionParser
)
from fast_boot.security.access.hierarchical_roles import (
    RoleHierarchy
)
from fast_boot.security.access.permission_evaluator import (
    PermissionEvaluator
)
from fast_boot.security.security_core_prototype.config_attribute import (
    ConfigAttribute
)

T = TypeVar("T")


class SecurityExpressionHandler(Generic[T]):
    expression_parser: ExpressionParser = ExpressionParser()
    role_hierarchy: RoleHierarchy
    permission_evaluator: PermissionEvaluator
    trust_resolver: Any  # 'AuthenticationTrustResolver'
    default_role_prefix: str = "ROLE_"

    def get_expression_parser(self) -> ExpressionParser:
        return self.expression_parser

    def create_evaluation_context(self, authentication: HTTPBasicCredentials, invocation: Any) -> Any:  # 'EvaluationContext'
        ...


class WebExpressionAttribute(ConfigAttribute):

    def __init__(self, authorize_expression: Expression):
        self.authorize_expression = authorize_expression

    def get_attribute(self) -> Optional[str]:
        return None


class WebExpressionVoter:
    expression_handler: SecurityExpressionHandler = SecurityExpressionHandler()

    def vote(self, authentication: HTTPBasicCredentials, filter_invocation, attrs: List[ConfigAttribute]):
        expression_config_attr = self.find_config_attribute(attrs)
        if expression_config_attr is None:
            return 0
        else:
            ctx = self.expression_handler.create_evaluation_context(authentication, filter_invocation)
            granted: bool = expression_config_attr.authorize_expression.get_value(context=ctx, type=bool)
            if granted:
                return 1
            else:
                return -1

    def find_config_attribute(self, attrs: List[ConfigAttribute]) -> Optional[WebExpressionAttribute]:
        for attr in attrs:
            if isinstance(attr, WebExpressionAttribute):
                return attr
        return None
