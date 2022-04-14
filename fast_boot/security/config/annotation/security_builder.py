import abc
from typing import Generic, TypeVar

Obj = TypeVar("Obj")


class SecurityBuilder(Generic[Obj], abc.ABC):
    @abc.abstractmethod
    def build(self) -> Obj:
        ...
