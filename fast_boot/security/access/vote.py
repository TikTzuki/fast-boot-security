from typing import Any, List

from fastapi.security import HTTPBasicCredentials
from starlette import status

from fast_boot import error_code
from fast_boot.exception import LOSException
from fast_boot.security.security_core_prototype.config_attribute import (
    ConfigAttribute
)


class AccessDecisionManager:
    allow_if_all_abstain_decisions: bool = False

    def __init__(self, voters: List):
        self.decision_voters = voters

    def decide(self, authentication: HTTPBasicCredentials, object: Any, config_attrs: List[ConfigAttribute]) -> None:
        deny = 0
        for voter in self.decision_voters:
            result = voter.vote(authentication, object, config_attrs)
            if result == -1:
                deny += 1
                break
            elif result == 1:
                return
        if deny > 0:
            raise LOSException.with_error(code=error_code.ACCESS_DENIED, status_code=status.HTTP_403_FORBIDDEN)
        elif self.allow_if_all_abstain_decisions:
            raise LOSException.with_error(code=error_code.ACCESS_DENIED, status_code=status.HTTP_403_FORBIDDEN)
