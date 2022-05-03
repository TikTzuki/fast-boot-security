from typing import Dict, Type

from fast_boot.security_lite.filters.filter_security_interceptor import FilterSecurityInterceptor


class FilterOrderRegistration(object):
    """
    1. ChannelProcessingFilter, because it might need to redirect to a different protocol

    2. SecurityContextPersistenceFilter, so a SecurityContext can be set up in the SecurityContextHolder at the beginning of a web request, and any changes to the SecurityContext can be copied to the HttpSession when the web request ends (ready for use with the next web request)

    3. ConcurrentSessionFilter, because it uses the SecurityContextHolder functionality but needs to update the SessionRegistry to reflect ongoing requests from the principal

    4. Authentication processing mechanisms - UsernamePasswordAuthenticationFilter, CasAuthenticationFilter, BasicAuthenticationFilter etc - so that the SecurityContextHolder can be modified to contain a valid Authentication request token

    5. The SecurityContextHolderAwareRequestFilter, if you are using it to install a Spring Security aware HttpServletRequestWrapper into your servlet container

    6. RememberMeAuthenticationFilter, so that if no earlier authentication processing mechanism updated the SecurityContextHolder, and the request presents a cookie that enables remember-me services to take place, a suitable remembered Authentication object will be put there

    7. AnonymousAuthenticationFilter, so that if no earlier authentication processing mechanism updated the SecurityContextHolder, an anonymous Authentication object will be put there

    8. ExceptionTranslationFilter, to catch any Spring Security exceptions so that either an HTTP error response can be returned or an appropriate AuthenticationEntryPoint can be launched

    9. FilterSecurityInterceptor, to protect web URIs and raise exceptions when access is denied
    """
    INITIAL_ORDER: int = 100
    ORDER_STEP: int = 100
    filter_to_order: Dict[Type, int] = dict()

    def __init__(self):
        order = self.Step(100, 100)
        'ChannelProcessingFilter'
        'WebAsyncManagerIntegrationFilter'
        'SecurityContextPersistenceFilter'
        'HeaderWriterFilter'
        'CorsFilter'
        'CsrfFilter'
        'LogoutFilter'
        'OAuth2AuthorizationRequestRedirectFilter'
        'Saml2WebSsoAuthenticationRequestFilter'
        'X509AuthenticationFilter'
        'AbstractPreAuthenticatedProcessingFilter'
        'UsernamePasswordAuthenticationFilter'
        'ConcurrentSessionFilter'
        'BearerTokenAuthenticationFilter'
        'BasicAuthenticationFilter'
        'SecurityContextHolderAwareRequestFilter'
        'RememberMeAuthenticationFilter'
        'AnonymousAuthenticationFilter'
        'ExceptionTranslationFilter'
        self.put(FilterSecurityInterceptor, order.next())
        'AuthorizationFilter'

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
