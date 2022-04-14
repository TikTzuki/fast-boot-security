import abc
from typing import Any, Type, TypeVar

T = TypeVar("T")


class ApplicationContext(abc.ABC):
    @abc.abstractmethod
    def get_id(self):
        ...

    @abc.abstractmethod
    def get_application_name(self) -> str:
        ...

    @abc.abstractmethod
    def get_display_name(self) -> str:
        ...

    @abc.abstractmethod
    def get_bean(self, type: Type[T]) -> T:
        ...

    @abc.abstractmethod
    def set_bean(self, bean: Any) -> None:
        ...
