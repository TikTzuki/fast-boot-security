import abc
from typing import Type, TypeVar

from fast_boot.schemas import Filter

C = TypeVar("C")


class AbstractConfiguredSecurityBuilder(abc.ABC):
    @abc.abstractmethod
    def add_filter(self, flt: Filter) -> 'AbstractConfiguredSecurityBuilder':
        ...

    @abc.abstractmethod
    def set_shared_object(self, shared_type: Type, obj) -> None:
        ...

    @abc.abstractmethod
    def get_shared_object(self, shared_type: Type[C]) -> C:
        ...
