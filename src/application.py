from typing import Any, Dict, Type

from fastapi import FastAPI

from src.context.application import ApplicationContext, T
from src.security.access.hierarchical_roles import (
    RoleHierarchy
)
from src.security.access.permission_evaluator import (
    PermissionEvaluator
)
from src.security.authentication import (
    AuthenticationTrustResolver
)
from src.security.core import GrantedAuthorityDefaults


class FastApplication(FastAPI, ApplicationContext):
    bean_factory: Dict[Type, Any]
    INSTANCE: ApplicationContext

    def setup(self) -> None:
        super().setup()
        beans = {
            RoleHierarchy,
            GrantedAuthorityDefaults,
            PermissionEvaluator,
            AuthenticationTrustResolver
        }
        self.bean_factory = {bean: bean() for bean in beans}
        self.INSTANCE = self

    def get_id(self):
        return id(self)

    def get_application_name(self) -> str:
        return self.title

    def get_display_name(self) -> str:
        return self.title

    def set_bean(self, bean: Any) -> None:
        self.bean_factory.update({type(bean): bean})

    def get_bean(self, type: Type[T]) -> T:
        return self.bean_factory.get(type)
