import abc
from enum import Enum, auto
from typing import Any, Dict, Generic, List, Optional, Type, TypeVar

from fast_boot.security.config.annotation.security_builder import (
    SecurityBuilder
)
from fast_boot.security.config.annotation.security_configurer_adapter import (
    SecurityConfigurerAdapter
)

Obj = TypeVar("Obj")
B = TypeVar("B")


class AbstractSecurityBuilder(SecurityBuilder[Obj], Generic[Obj, B]):
    # ----
    object: Obj
    building: bool = False
    # ---
    configurers: Dict[Type[SecurityConfigurerAdapter[Obj, B]], List[SecurityConfigurerAdapter[Obj, B]]]
    object_post_processor: Any
    build_state: 'BuildState'
    allow_configurers_of_same_type: bool
    configurers_added_in_initializing: List[SecurityConfigurerAdapter[Obj, B]]
    shared_objects: Dict[Type, Any]

    def __init__(self, object_post_processor, allow_configurers_of_same_type=False):
        self.configurers = dict()
        self.configurers_added_in_initializing = list()
        self.shared_objects = dict()
        self.build_state = self.BuildState.UN_BUILT
        self.object_post_processor = object_post_processor
        self.allow_configurers_of_same_type = allow_configurers_of_same_type

    # super 1
    def build(self) -> Obj:
        if not self.building:
            self.building = True
            self.object = self.do_build()
            return self.object
        else:
            raise RuntimeError("This object has already been built")

    def do_build(self) -> Obj:
        self.build_state = self.BuildState.INITIALIZING
        self.before_init()
        self.init()
        self.build_state = self.BuildState.CONFIGURING
        self.before_configure()
        self.configure()
        self.build_state = self.BuildState.BUILDING
        result: Obj = self.perform_build()
        self.build_state = self.BuildState.BUILT
        return result

    def before_init(self) -> None:
        ...

    def init(self) -> None:
        configurers: List[SecurityConfigurerAdapter] = self.get_configurers()
        configurer: SecurityConfigurerAdapter
        for conf in configurers:
            configurer = conf
            configurer.init(self)

        for conf in self.configurers_added_in_initializing:
            configurer = conf
            configurer.init(self)

    def before_configure(self) -> None:
        ...

    def configure(self) -> None:
        configurers = self.get_configurers()
        for conf in configurers:
            conf.configure(self)

    @abc.abstractmethod
    def perform_build(self) -> Obj:
        ...

    # current
    def get_configurer(self, clazz: Type[SecurityConfigurerAdapter[Obj, B]]) -> Optional[SecurityConfigurerAdapter[Obj, B]]:
        configs = self.configurers.get(clazz)
        return configs[0] if configs else None

    def get_configurers(self) -> List[SecurityConfigurerAdapter[Obj, B]]:
        result = []
        for configs in self.configurers.values():
            result.append(*configs)
        return result

    def add(self, configurer: SecurityConfigurerAdapter[Obj, B]) -> None:
        clazz = type(configurer)
        configs: List[SecurityConfigurerAdapter[Obj, B]] = []
        if self.allow_configurers_of_same_type:
            configs = self.configurers.get(clazz)
        configs.append(configurer)
        self.configurers.update({clazz: configs})
        if self.build_state.is_initializing():
            self.configurers_added_in_initializing.append(configurer)

    def apply(self, configurer: Any) -> SecurityConfigurerAdapter:
        self.add(configurer)
        return configurer

    class BuildState(Enum):
        UN_BUILT = auto()
        INITIALIZING = auto()
        CONFIGURING = auto()
        BUILDING = auto()
        BUILT = auto()

        def is_initializing(self):
            return self.INITIALIZING == self
