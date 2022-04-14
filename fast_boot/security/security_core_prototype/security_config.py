from typing import List

from fast_boot.security.security_core_prototype.config_attribute import (
    ConfigAttribute
)


class SecurityConfig(ConfigAttribute):
    attrib: str

    def __init__(self, config: str):
        self.attrib = config

    def get_attribute(self) -> str:
        return self.attrib

    @classmethod
    def create_list(cls, *attribute_names: str) -> List[ConfigAttribute]:
        attributes: List[ConfigAttribute] = []
        for attribute in attribute_names:
            attributes.append(cls(attribute.strip()))
        return attributes
