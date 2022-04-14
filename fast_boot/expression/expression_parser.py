import re
from typing import Any, Type

from fast_boot.security.access.hierarchical_roles import (
    RoleHierarchy
)


class Expression:
    def get_expression_string(self):
        ...

    def get_value(self, context: Any = None, root_object: Any = None, type: Type = None) -> Any:
        return True
        # TODO: write this


class ExpressionParser:
    configuration = None
    permit_all: str = "permitAll"
    deny_all: str = "denyAll"
    anonymous: str = "anonymous"
    fully_authenticated = "fullyAuthenticated"
    remember_me = "rememberMe"
    has_any_role = "hasAnyRole"
    has_role = "hasRole"
    has_authority = "hasAuthority"
    has_any_authority = "hasAnyAuthority"

    def parse_expression(self, expression_string: str) -> re.Pattern[str]:
        if not expression_string:
            raise Exception("expression string is required")
        if expression_string.startswith(self.anonymous):
            return "."
        elif expression_string.startswith(self.has_role):
            return expression_string.replace(self.has_role + "(", "")[:-1]
        elif expression_string.startswith(self.has_any_role):
            return expression_string.replace(self.has_any_role + "(", "").replace(",", "|")[:-1]
        elif expression_string.startswith(self.has_authority):
            return expression_string.replace(self.has_authority + "(", "")[:-1]
        elif expression_string.startswith(self.has_any_authority):
            return expression_string.replace(self.has_any_authority + "(", "").replace(",", "|")[:-1]

    def parse_raw(self, expression_string: str) -> 'ExpressionParser':
        return self.do_parse_expression(expression_string, None)

    def do_parse_expression(self, expression_string: str, parser_context) -> 'ExpressionParser':
        return Expression(expression_string, None, self.configuration)

    def parse(self, role_hierarchy: RoleHierarchy, role_prefix: str) -> str:
        string_builder = ""
        roles = [role.role for role in role_hierarchy.roles]
        # permission = itertools.chain(role.permissions for role in role_hierarchy.roles)
        string_builder += "'" + role_prefix + f"','{role_prefix}".join(roles) + "'"
        # string_builder +=
        return string_builder
