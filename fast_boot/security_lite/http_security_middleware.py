import asyncio
from asyncio import Queue
from typing import Callable, AsyncGenerator, Optional

from fastapi import HTTPException
from fastapi.responses import ORJSONResponse
from starlette.authentication import AuthenticationError
from starlette.middleware.base import RequestResponseEndpoint, DispatchFunction
from starlette.requests import HTTPConnection, Request
from starlette.responses import PlainTextResponse, Response, StreamingResponse
from starlette.types import ASGIApp, Receive, Scope, Send, Message

from fast_boot import error_code
from fast_boot.exception import LOSException
from fast_boot.security_lite.authenticator import Authenticator
from fast_boot.security_lite.http_security import HttpSecurity
from fast_boot.security_lite.shared_objects import SharedObjects
from fast_boot.security_lite.web_security_configurer_adapter import WebSecurityConfigurerAdapter


class HttpSecurityMiddleware:

    def __init__(
            self,
            app: ASGIApp,
            authenticator: Authenticator,
            dispatch: DispatchFunction = None,
            on_error: Callable[[HTTPConnection, AuthenticationError], Response] = None
    ) -> None:
        self.app = app
        self.on_error = (on_error if on_error is not None else self.default_on_error)  # type: Callable[[HTTPConnection, Exception], Response]
        self.dispatch_func = self.dispatch if dispatch is None else dispatch
        shared_objects = SharedObjects(app, authenticator)
        http = HttpSecurity(shared_objects)
        self.configure(http)
        configurer = WebSecurityConfigurerAdapter(shared_objects, http)
        chain = configurer.build()
        self.filter_chain = chain

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive=receive)
        response = await self.dispatch_func(request, self.call_next)
        await response(scope, receive, send)

    def configure(self, http: HttpSecurity) -> None:
        ...

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        try:
            return await self.filter_chain.do_filter(request, call_next)
        except HTTPException as e:
            return self.on_error(request, e)

    @staticmethod
    def default_on_error(conn: HTTPConnection, exc: Exception) -> Response:
        if isinstance(exc, LOSException):
            return ORJSONResponse(content={"errors": LOSException.arrow_error_pipeline(exc.get_detail()), }, status_code=exc.status_code)
        if isinstance(exc, HTTPException):
            return ORJSONResponse(content={"errors": [{"detail": exc.detail, "msg": error_code.ACCESS_DENIED}]}, status_code=exc.status_code)
        return PlainTextResponse(str(exc), status_code=400)

    async def call_next(self, request: Request) -> Response:
        loop = asyncio.get_event_loop()
        queue: Queue[Optional[Message]] = asyncio.Queue()

        scope = request.scope
        receive = request.receive
        send = queue.put

        async def coro() -> None:
            try:
                await self.app(scope, receive, send)
            finally:
                await queue.put(None)

        task = loop.create_task(coro())
        message = await queue.get()
        if message is None:
            task.result()
            raise RuntimeError("No response returned.")
        assert message["type"] == "http.response.start"

        async def body_stream() -> AsyncGenerator[bytes, None]:
            while True:
                message = await queue.get()
                if message is None:
                    break
                assert message["type"] == "http.response.body"
                yield message.get("body", b"")
            task.result()

        response = StreamingResponse(
            status_code=message["status"], content=body_stream()
        )
        response.raw_headers = message["headers"]
        return response
