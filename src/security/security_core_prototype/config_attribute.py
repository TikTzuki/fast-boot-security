import abc


class ConfigAttribute(abc.ABC):

    @abc.abstractmethod
    def get_attribute(self) -> str:
        ...
