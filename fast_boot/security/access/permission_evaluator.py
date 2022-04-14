import abc
from typing import Any

from fastapi.security import HTTPBasicCredentials


class PermissionEvaluator:
    @abc.abstractmethod
    def has_permission(self, authentication: HTTPBasicCredentials, permission: Any, target_domain_object, target_id, target_type: str):
        ...
