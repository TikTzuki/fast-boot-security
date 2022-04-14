import time
from typing import Any, Callable, Dict, Optional, Tuple, Type

from fastapi import HTTPException
from fastapi.responses import ORJSONResponse
from loguru import logger
from starlette import status
from starlette.authentication import AuthCredentials, AuthenticationError
from starlette.requests import HTTPConnection, Request
from starlette.responses import PlainTextResponse, Response
from starlette.types import ASGIApp, Receive, Scope, Send

from fast_boot import error_code
from fast_boot.application import FastApplication
from fast_boot.context.application import ApplicationContext
from fast_boot.exception import LOSException
from fast_boot.schemas import AbstractUser
from fast_boot.security.access.intercept.integration_filter import (
    IntegrationFilter
)
from fast_boot.security.http_security import HttpSecurity


async def add_process_time_header(response, start_time):
    process_time = time.time() - start_time
    response.headers["Server-Execute-Time"] = str(process_time)
    return response


async def middleware_setting(request: Request, call_next):
    start_time = time.time()
    # check auth
    response = await call_next(request)
    # add header time
    response = await add_process_time_header(response=response, start_time=start_time)
    return response


class AbstractAuthorizationFilter:
    async def authorize(
            self, conn: HTTPConnection
    ) -> Optional[Tuple["AuthCredentials", AbstractUser]]:
        raise NotImplementedError()  # pragma: no cover


class AuthorizationMiddleware:
    def __init__(
            self,
            app: ASGIApp,
            filter: AbstractAuthorizationFilter,
            on_error: Callable[
                [HTTPConnection, AuthenticationError], Response
            ] = None,
    ) -> None:
        self.app = app
        self.filter = filter
        self.on_error = (
            on_error if on_error is not None else self.default_on_error
        )  # type: Callable[[HTTPConnection, Exception], Response]

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ["http", "websocket"]:
            await self.app(scope, receive, send)
            return

        conn = HTTPConnection(scope)
        try:
            await self.filter.authorize(conn)
        except AuthenticationError as exc:
            response = self.on_error(conn, exc)
            if scope["type"] == "websocket":
                await send({"type": "websocket.close", "code": 1000})
            else:
                await response(scope, receive, send)
            return
        except Exception as e:
            response = self.on_error(conn, e)
            await response(scope, receive, send)
        await self.app(scope, receive, send)

    @staticmethod
    def default_on_error(conn: HTTPConnection, exc: Exception) -> Response:
        if isinstance(exc, LOSException):
            return Response(content={"errors": LOSException.arrow_error_pipeline(exc.get_detail()), }, status_code=status.HTTP_403_FORBIDDEN)
        return PlainTextResponse(str(exc), status_code=400)


class HttpSecurityMiddleWare:
    def __init__(
            self,
            app: ASGIApp,
            context: FastApplication,
            on_error: Callable[
                [HTTPConnection, AuthenticationError], Response
            ] = None,
    ) -> None:
        self.app = app
        self.context = context
        self.on_error = (on_error if on_error is not None else self.default_on_error)  # type: Callable[[HTTPConnection, Exception], Response]
        self.authentication_builder = None
        self.http = None
        self.http = self.get_http()
        self.filter_chain = self.http.build()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        request = Request(scope, receive, send)  # noqa
        try:
            if self.filter_chain.matches(request):
                for filter in self.filter_chain.filters:
                    await filter.do_filter(request, None, self.filter_chain)
        except HTTPException as e:
            response = self.on_error(request, e)
            await response(scope, receive, send)
            return

        await self.app(scope, receive, send)

    def get_http(self) -> HttpSecurity:
        if self.http:
            return self.http
        else:
            shared_objects: Dict = self.create_shared_object()
            self.http = HttpSecurity(None, self.authentication_builder, shared_objects)
            self.apply_default_configuration(self.http)
            self.configure(self.http)
            return self.http

    def configure(self, http: HttpSecurity):
        http.authorize_requests() \
            .any_request().authenticated()

    def apply_default_configuration(self, http: HttpSecurity):
        http.add_filter(IntegrationFilter())

    def create_shared_object(self) -> Dict[Type, Any]:
        shared_objects = dict()
        # shared_objects.update({self.local_configure_authentication_bldr.get_shared_objects()})
        # TODO shared_objects.update({UserDetailService: })
        shared_objects.update({ApplicationContext: self.context})
        # shared_objects.update({AuthenticationTrustResolver: self.trust_resolver})
        return shared_objects

    @staticmethod
    def default_on_error(conn: HTTPConnection, exc: Exception) -> Response:
        logger.exception(exc)
        if isinstance(exc, LOSException):
            return ORJSONResponse(content={"errors": LOSException.arrow_error_pipeline(exc.get_detail()), }, status_code=status.HTTP_403_FORBIDDEN)
        if isinstance(exc, HTTPException):
            return ORJSONResponse(content={"errors": [{"detail": exc.detail, "msg": error_code.ACCESS_DENIED}]}, status_code=status.HTTP_403_FORBIDDEN)
        return PlainTextResponse(str(exc), status_code=400)
