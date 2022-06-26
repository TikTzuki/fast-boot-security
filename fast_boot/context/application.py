import abc
from typing import TypeVar

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

    @property
    @abc.abstractmethod
    def debug(self) -> bool:
        ...
