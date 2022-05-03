from typing import List, Any

from pydantic import BaseModel

from fast_boot.security.core import GrantedAuthority


class Permission(BaseModel):
    permission_code: str


class Role(BaseModel):
    role_code: str
    permissions: List[Permission] = []

    # def __init__(self, role_code: str, permissions: List[Permission], **data: Any):
    #     super().__init__(**data)
    #     self.role_code = role_code
    #     self.permissions = permissions


class RoleHierarchy(BaseModel):
    roles: List[Role] = []

    def get_reachable_granted_authorities(self, authorities: List[GrantedAuthority]) -> List[GrantedAuthority]:
        ...

    class Config:
        validation = False
