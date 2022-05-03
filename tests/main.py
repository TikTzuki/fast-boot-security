import http
import typing
from typing import Dict, Type, Any
from typing import Optional

import uvicorn
from fastapi import Path, Query
from fastapi.security.utils import get_authorization_scheme_param
from starlette.authentication import AuthCredentials
from starlette.requests import HTTPConnection, Request

from fast_boot.application import FastApplication
from fast_boot.middleware import HttpSecurityMiddleWare
from fast_boot.schemas import AbstractUser, UnAuthenticatedUser
from fast_boot.security.authentication import Authenticator
from fast_boot.security.http_security import HttpSecurity

app = FastApplication(
    docs_url="/"
)


@app.get("/text")
def get_text():
    return "Hello World"


@app.get("/path/{item_id}")
def get_id(item_id):
    return item_id


@app.get("/path/str/{item_id}")
def get_str_id(item_id: str):
    return item_id


@app.get("/path/int/{item_id}")
def get_int_id(item_id: int):
    return item_id


@app.get("/path/float/{item_id}")
def get_float_id(item_id: float):
    return item_id


@app.get("/path/bool/{item_id}")
def get_bool_id(item_id: bool):
    return item_id


@app.get("/path/param/{item_id}")
def get_path_param_id(item_id: Optional[str] = Path(None)):
    return item_id


@app.get("/path/param-required/{item_id}")
def get_path_param_required_id(item_id: str = Path(...)):
    return item_id


@app.get("/path/param-minlength/{item_id}")
def get_path_param_min_length(item_id: str = Path(..., min_length=3)):
    return item_id


@app.get("/path/param-maxlength/{item_id}")
def get_path_param_max_length(item_id: str = Path(..., max_length=3)):
    return item_id


@app.get("/path/param-min_maxlength/{item_id}")
def get_path_param_min_max_length(item_id: str = Path(..., max_length=3, min_length=2)):
    return item_id


@app.get("/path/param-gt/{item_id}")
def get_path_param_gt(item_id: float = Path(..., gt=3)):
    return item_id


@app.get("/path/param-gt0/{item_id}")
def get_path_param_gt0(item_id: float = Path(..., gt=0)):
    return item_id


@app.get("/path/param-ge/{item_id}")
def get_path_param_ge(item_id: float = Path(..., ge=3)):
    return item_id


@app.get("/path/param-lt/{item_id}")
def get_path_param_lt(item_id: float = Path(..., lt=3)):
    return item_id


@app.get("/path/param-lt0/{item_id}")
def get_path_param_lt0(item_id: float = Path(..., lt=0)):
    return item_id


@app.get("/path/param-le/{item_id}")
def get_path_param_le(item_id: float = Path(..., le=3)):
    return item_id


@app.get("/path/param-lt-gt/{item_id}")
def get_path_param_lt_gt(item_id: float = Path(..., lt=3, gt=1)):
    return item_id


@app.get("/path/param-le-ge/{item_id}")
def get_path_param_le_ge(item_id: float = Path(..., le=3, ge=1)):
    return item_id


@app.get("/path/param-lt-int/{item_id}")
def get_path_param_lt_int(item_id: int = Path(..., lt=3)):
    return item_id


@app.get("/path/param-gt-int/{item_id}")
def get_path_param_gt_int(item_id: int = Path(..., gt=3)):
    return item_id


@app.get("/path/param-le-int/{item_id}")
def get_path_param_le_int(item_id: int = Path(..., le=3)):
    return item_id


@app.get("/path/param-ge-int/{item_id}")
def get_path_param_ge_int(item_id: int = Path(..., ge=3)):
    return item_id


@app.get("/path/param-lt-gt-int/{item_id}")
def get_path_param_lt_gt_int(item_id: int = Path(..., lt=3, gt=1)):
    return item_id


@app.get("/path/param-le-ge-int/{item_id}")
def get_path_param_le_ge_int(item_id: int = Path(..., le=3, ge=1)):
    return item_id


@app.get("/query")
def get_query(query):
    return f"foo bar {query}"


@app.get("/query/optional")
def get_query_optional(query=None):
    if query is None:
        return "foo bar"
    return f"foo bar {query}"


@app.get("/query/int")
def get_query_type(query: int):
    return f"foo bar {query}"


@app.get("/query/int/optional")
def get_query_type_optional(query: Optional[int] = None):
    if query is None:
        return "foo bar"
    return f"foo bar {query}"


@app.get("/query/int/default")
def get_query_type_int_default(query: int = 10):
    return f"foo bar {query}"


@app.get("/query/param")
def get_query_param(query=Query(None)):
    if query is None:
        return "foo bar"
    return f"foo bar {query}"


@app.get("/query/param-required")
def get_query_param_required(query=Query(...)):
    return f"foo bar {query}"


@app.get("/query/param-required/int")
def get_query_param_required_type(query: int = Query(...)):
    return f"foo bar {query}"


@app.get("/enum-status-code", status_code=http.HTTPStatus.CREATED)
def get_enum_status_code():
    return "foo bar"


class AuthenticationManager(Authenticator):
    async def authenticate(self, conn: HTTPConnection) -> typing.Tuple[AuthCredentials, typing.Optional[AbstractUser]]:
        unauthenticated = AuthCredentials(), UnAuthenticatedUser()
        authorization: str = conn.headers.get("Authorization")
        if not authorization:
            return unauthenticated
        scheme, credentials = get_authorization_scheme_param(authorization)
        if not (authorization and scheme and credentials):
            return unauthenticated
        if scheme == "Bearer":
            ...
        # authenticated_user = AbstractUser(
        #     access_token=credentials,
        #     user_info=data_decode["user_info"],
        # )
        # return AuthCredentials(scopes=[]), authenticated_user


class FastHttpSecurityMiddleWare(HttpSecurityMiddleWare):
    def configure(self, http: HttpSecurity):
        super().configure(http)
        http.authorize_requests() \
            .regex_matchers(None, "/role-login/*").anonymous() \
            .regex_matchers("get", "/role$").has_role("role-1") \
            .regex_matchers("get", "/any-role").has_any_role("role-2", "role-3", "ACCESS") \
            .regex_matchers("get", "/permission").has_authority("permission-1") \
            .regex_matchers("get", "/any-permission").has_any_authority("permission-2", "permission-3") \
            .any_request().authenticated()

    def create_shared_object(self) -> Dict[Type, Any]:
        shared_objects = super().create_shared_object()
        shared_objects.update({Authenticator: AuthenticationManager()})
        return shared_objects


app.add_middleware(HttpSecurityMiddleWare, context=app)


@app.middleware("http")
async def test(request: Request, call_next):
    return await call_next(request)


if __name__ == "__main__":
    uvicorn.run('tests.main:app', host="127.0.0.1", port=8000, reload=True)
