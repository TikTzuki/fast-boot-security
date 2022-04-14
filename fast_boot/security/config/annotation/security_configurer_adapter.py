import abc
from typing import Any, Generic, List, TypeVar

from fast_boot.context.application import ApplicationContext
from fast_boot.security.config.annotation.security_builder import (
    SecurityBuilder
)

B = TypeVar("B")
F = TypeVar("F")
T = TypeVar("T")


class ObjectPostProcessor:
    def post_process(self, obj: T) -> T:
        ...


class SecurityConfigurerAdapter(SecurityBuilder[F], Generic[F, B], abc.ABC):
    security_builder: B
    registry: Any
    object_post_processor: 'CompositeObjectPostProcessor'

    def __init__(self, context: ApplicationContext):
        self.context = context
        self.object_post_processor = self.CompositeObjectPostProcessor()

    def init(self, builder: B) -> None:
        ...

    @abc.abstractmethod
    def configure(self, builder: B) -> None:
        ...

    @abc.abstractmethod
    def get_registry(self) -> Any:
        ...

    def and_(self) -> B:
        return self.get_builder()

    def get_builder(self) -> B:
        return self.security_builder

    class CompositeObjectPostProcessor(ObjectPostProcessor):
        post_processors: List[ObjectPostProcessor] = []

        def post_process(self, obj: T) -> T:
            for opp in self.post_processors:
                obj = opp.post_process(obj)
            return obj

        def add_object_post_process(self, object_post_processor) -> None:
            self.post_processors.append(object_post_processor)
            # TODO: self.post_processors.sort()
