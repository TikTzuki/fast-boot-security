import http
from typing import Optional
from typing import Tuple

import jwt
import uvicorn
from fastapi import Path, Query, Security, HTTPException
from fastapi.security import HTTPBearer, HTTPBasic
from fastapi.security.utils import get_authorization_scheme_param
from starlette import status
from starlette.authentication import AuthCredentials
from starlette.requests import HTTPConnection, Request

from fast_boot import error_code
from fast_boot.application import FastApplication
from fast_boot.exception import LOSException
from fast_boot.schemas import AbstractUser, UnAuthenticatedUser, User
from fast_boot.security_lite.authenticator import Authenticator
from fast_boot.security_lite.http_security import HttpSecurity
from fast_boot.security_lite.http_security_middleware import HttpSecurityMiddleware
from fast_boot.security_lite.web_security_configurer_adapter import WebSecurityConfigurerAdapter
from tests.data import users

app = FastApplication(
    docs_url="/",
    debug=True
)


class WebConfig(WebSecurityConfigurerAdapter):
    def configure(self, http: HttpSecurity) -> None:
        http.authorize_requests() \
            .regex_matchers(None, "/login*").permit_all() \
            .regex_matchers(None, "/enum-status-code/").has_any_authority("APPROVER", "CONTROLLER") \
            .regex_matchers(None, "/text*").has_any_authority("INITIALIZER", "CONTROLLER") \
            .regex_matchers(None, "/text*").has_role("NGOCHB3") \
            .regex_matchers(None, "/path/*").has_any_authority("APPROVER") \
            # .any_request().authenticated()


# class User(AbstractUser):
#     class Branch(CustomBaseModel):
#         branch_code: str = None
#         branch_name: str = None
#         branch_parent_code: str = None
#
#     user_id: str = None
#     user_name: str = None
#     full_Name: str = None
#     branch: Branch
#     group_roles: typing.List[Dict]
#
#     def __init__(self, **data: Any):
#         super().__init__(**data)
#
#     def get_branch_code(self) -> str:
#         return self.branch.branch_code
#
#     def get_branch_parent_code(self) -> str:
#         return self.branch.branch_parent_code
#
#     @property
#     def role_hierarchy(self) -> RoleHierarchy:
#         return RoleHierarchy(roles=self.group_roles)
#
#     @property
#     def is_authenticated(self) -> bool:
#         return True
#
#     @property
#     def display_name(self) -> str:
#         return self.user_name
#
#     @property
#     def identity(self) -> str:
#         return self.user_name


class AuthenticationManager(Authenticator):

    async def authenticate(self, conn: HTTPConnection) -> Tuple[AuthCredentials, AbstractUser]:
        unauthenticated = AuthCredentials(), UnAuthenticatedUser()
        authorization: str = conn.headers.get("Authorization")
        if not authorization:
            return unauthenticated
        scheme, credentials = get_authorization_scheme_param(authorization)
        if not (scheme and credentials):
            return unauthenticated
        if scheme == "Bearer":
            secret_key = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
            algorithms = "HS256"
            try:
                rs = jwt.decode(credentials, secret_key, algorithms=algorithms)
            except jwt.ExpiredSignatureError:
                raise LOSException.with_error(code=error_code.TOKEN_EXPIRED, status_code=status.HTTP_401_UNAUTHORIZED)
            except jwt.exceptions.InvalidSignatureError:
                raise LOSException.with_error(code=error_code.ERROR_INVALID_TOKEN, status_code=status.HTTP_401_UNAUTHORIZED)
            except jwt.DecodeError as e:
                raise LOSException.with_error(code=error_code.ERROR_INVALID_TOKEN, status_code=status.HTTP_401_UNAUTHORIZED)
            user = User(**rs.get("user_info"))
            return AuthCredentials(), user

        if scheme == "Basic":
            basic_credentials = await HTTPBasic()(conn)
            user_opt = list(filter(lambda u: u["user_info"]["user_name"] == basic_credentials.username, users))
            if not user_opt:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid authentication credentials",
                    headers={"WWW-Authenticate": "Basic"},
                )
            user = user_opt[0]["user_info"]
            user = User(username=user["user_name"], fullname=user["full_name"])
            return AuthCredentials(), user
        return unauthenticated


app.update_bean({
    WebSecurityConfigurerAdapter: WebConfig(app),
    Authenticator: AuthenticationManager()
})

app.add_middleware(HttpSecurityMiddleware, context=app)


@app.get(
    "/text",
    dependencies=[Security(HTTPBearer())]
)
def get_text():
    return "Hello World"


@app.get("/path/{item_id}")
def get_id(item_id):
    return item_id


@app.post(
    "/login",
    dependencies=[Security(HTTPBasic())]
)
def get_id(request: Request):
    return request.user


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


if __name__ == "__main__":
    uvicorn.run("tests.security_lite:app", host="127.0.0.1", port=8000, reload=True)
