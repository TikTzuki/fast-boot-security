import uvicorn

from fast_boot.middleware import HttpSecurityMiddleWare
from fast_boot.security.http_security import HttpSecurity


class SecurityMiddleWare(HttpSecurityMiddleWare):
    def configure(self, http: HttpSecurity):
        http.authorize_requests() \
            .regex_matchers().has_role("READ_TEXT") \
            .any_request().authenticated()


if __name__ == "__main__":
    uvicorn.run('tests.los:app', host="127.0.0.1", port=8000, reload=True)
