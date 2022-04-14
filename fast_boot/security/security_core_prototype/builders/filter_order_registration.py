from typing import Dict, Type

from fast_boot.security.access.intercept.filter_security_interceptor import (
    FilterSecurityInterceptor
)
from fast_boot.security.access.intercept.integration_filter import (
    IntegrationFilter
)
from fast_boot.security.authentication import (
    UsernamePasswordAuthenticationFilter
)


class FilterOrderRegistration(object):
    INITIAL_ORDER: int = 100
    ORDER_STEP: int = 100
    filter_to_order: Dict[Type, int] = dict()

    def __init__(self):
        order = self.Step(100, 100)
        self.put(IntegrationFilter, order.next())
        self.put(UsernamePasswordAuthenticationFilter, order.next())
        self.put(FilterSecurityInterceptor, order.next())

    def put(self, clazz: Type, order: int):
        self.filter_to_order.update({clazz: order})

    def get_order(self, clazz: Type) -> int:
        return self.filter_to_order.get(clazz, None)

    class Step:
        value: int
        step_size: int

        def __init__(self, initial_value: int, step_size: int):
            self.value = initial_value
            self.step_size = step_size

        def next(self) -> int:
            value = self.value
            self.value += self.step_size
            return value
