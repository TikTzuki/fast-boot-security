from abc import ABC
from typing import Any, Dict, List, Optional, Union

from pydantic.error_wrappers import ErrorList, ErrorWrapper, flatten_errors
from pydantic.errors import PydanticErrorMixin

from fast_boot import error_code
from fast_boot.exception import LOSError
from fast_boot.schemas import Schema


class Base(ABC):
    def __init__(self, model=Schema):
        self.raw_errors: List[ErrorList] = []
        self.model = model
        self._error_cache: Optional[List[Dict[str, Any]]] = None

    def errors(self) -> List[Dict[str, Any]]:
        if self._error_cache is None:
            try:
                config = self.model.__config__  # type: ignore
            except AttributeError:
                config = self.model.__pydantic_model__.__config__  # type: ignore
            self._error_cache = list(flatten_errors(self.raw_errors, config))
        return self._error_cache

    def append_error(self, loc: List[Union[str, float]], code=None, msg_template=None, error: PydanticErrorMixin = None, **kwargs) -> None:
        """
        mặc định sử dụng LOSError phải có code vs msg_template tương ứng
        :param loc: vị trí của field lỗi
        :param code: error_code
        :param msg_template:
        :param error: sử dụng error có sẵn trong package errors của pydantic
        :return:
        """
        # assert hasattr(message, error.), "Không tìm thấy msg error"
        assert (code or error), "Required code or error"
        if code:
            if msg_template is None:
                msg_template = error_code.msg_templates.get(code)
            assert msg_template, f"Required msg_template for code: {code}"
            self.raw_errors.append(ErrorWrapper(exc=LOSError(code=code, msg_template=msg_template, **kwargs), loc=tuple(loc)))
        elif error:
            self.raw_errors.append(ErrorWrapper(exc=error, loc=tuple(loc)))

    def has_error(self) -> bool:
        return bool(self.raw_errors)

    def count_errors(self) -> int:
        return len(self.raw_errors)

