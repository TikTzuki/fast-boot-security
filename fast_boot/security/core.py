import abc


class GrantedAuthority:

    @abc.abstractmethod
    def get_authority(self) -> str:
        ...


class GrantedAuthorityDefaults:
    role_prefix: str

    def __init__(self, role_prefix="ROLE_"):
        self.role_prefix = role_prefix

    @abc.abstractmethod
    def get_role_prefix(self) -> str:
        return self.role_prefix
