from fastapi import FastAPI

from fast_boot.context.application import ApplicationContext


class FastApplication(FastAPI, ApplicationContext):

    # def __init__(
    #         self,
    #         middleware: Optional[Sequence[Middleware]] = None,
    #         **extra: Any
    # ):
    # middleware = [*([] if middleware is None else list(middleware)), Middleware(HttpSecurityMiddleware, context=self)]
    # super().__init__(middleware=middleware, **extra)

    def get_id(self):
        return id(self)

    def get_application_name(self) -> str:
        return self.title

    def get_display_name(self) -> str:
        return self.title
