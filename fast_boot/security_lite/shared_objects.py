from fast_boot.context.application import ApplicationContext
from fast_boot.security_lite.authenticator import Authenticator


class SharedObjects:
    authenticator: Authenticator
    context: ApplicationContext

    def __init__(self, context, authenticator):
        self.context = context
        self.authenticator = authenticator
