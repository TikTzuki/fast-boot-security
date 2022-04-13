from typing import Any, Dict, Type

from fastapi import FastAPI

from app.third_party.core.context.application import ApplicationContext, T
from app.third_party.core.security.access.hierarchical_roles import (
    RoleHierarchy
)
from app.third_party.core.security.access.permission_evaluator import (
    PermissionEvaluator
)
from app.third_party.core.security.authentication import (
    AuthenticationTrustResolver
)
from app.third_party.core.security.core import GrantedAuthorityDefaults


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
