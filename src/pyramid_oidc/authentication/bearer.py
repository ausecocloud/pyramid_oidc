from jose.exceptions import ExpiredSignatureError, JWTClaimsError
from pyramid.authentication import CallbackAuthenticationPolicy
from pyramid.interfaces import IAuthenticationPolicy
from zope.interface import implementer

from ..interfaces import IOIDCUtility


@implementer(IAuthenticationPolicy)
class OIDCBearerAuthenticationPolicy(CallbackAuthenticationPolicy):

    def __init__(self, callback=None, debug=False, **kwargs):
        self.callback = callback
        self.debug = debug

    def get_token(self, request):
        # TODO: this should be an access token, and for now we assume it is
        #       a jwt with all information we need ... in the future we can
        #       unitilze the token_info / user_info endpoint or whatever to
        #       get user details.
        try:
            auth_type, params = request.authorization
            if auth_type.lower() == 'bearer':
                return params
        except (ValueError, TypeError):
            # ValueError: too many values to unpack
            #             not enough values to unpack
            # TypeError:  NoneType not iterable (header was none)
            # could not parse auth header => no token
            # TODO: different things here?
            #   .. ValueError ... fail here?
            #   .. TypeError ... probably no auth header so no error?
            pass
        return None

    def _get_utility(self, request):
        return request.registry.getUtility(IOIDCUtility)

    def _validate_access_token(self, request):
        # verify access token and return claims
        # TODO: assumes access token is a jwt with useful attributes
        claims = request.environ.get('oidc.claims')
        if claims:
            # we already decoded the access token
            return claims
        token = self.get_token(request)
        try:
            claims = self._get_utility(request).validate_token(token)
        except (ExpiredSignatureError, JWTClaimsError):
            # access token expired or claims don't check out
            # ... can't do anything here
            # TODO: log it?
            pass
        if claims:
            request.environ['oidc.claims'] = claims
        else:
            request.environ.pop('oidc.claims', None)
        return claims

    # @IAuthenticationPolicy
    def unauthenticated_userid(self, request):
        """Get identity from request Auth header without validation"""
        # we verify and extract the token here, so that we can
        # inspect the claims in the callback
        # if verify fails, we return None
        # any claims in the request.env
        claims = self._validate_access_token(request)
        if not claims:
            return None
        oidc = self._get_utility(request)
        return claims.get(oidc.userid_claim)

    # @IAuthenticationPolicy
    def remember(self, request, userid, **kw):
        """ Return a set of headers suitable for 'remembering' the
        :term:`userid` named ``userid`` when set in a response.  An
        individual authentication policy and its consumers can
        decide on the composition and meaning of ``**kw``.
        """
        # Anything to do here? ....
        return []

    # @IAuthenticationPolicy
    def forget(self, request):
        """ Return a set of headers suitable for 'forgetting' the
        current user on subsequent requests.
        """
        # Returns challenge headers. This should be attached to a response
        # to indicate that credentials are required.
        return [('WWW-Authenticate', 'Bearer')]
        # TODO: any header parameters like realm=???
