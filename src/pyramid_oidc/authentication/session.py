import logging

from jose.exceptions import ExpiredSignatureError
from oauthlib.oauth2.rfc6749.errors import InvalidGrantError
from pyramid.authentication import CallbackAuthenticationPolicy
from pyramid.interfaces import IAuthenticationPolicy
from zope.interface import implementer

from ..interfaces import IOIDCUtility


@implementer(IAuthenticationPolicy)
class OIDCSessionAuthenticationPolicy(CallbackAuthenticationPolicy):
    # This auth policy requires a session factory to be set up.
    # In general cookie base session store won't work, as the cookie payload
    # usually exceeds 4kb

    def __init__(self, callback=None, debug=False, **kwargs):
        self.callback = callback
        self.debug = debug
        self.log = logging.getLogger(__name__)

    def get_token(self, request):
        # get tokens from session
        tokens = request.session.get('oidc.token')
        if tokens:
            return tokens.get('access_token')
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
        oidc = self._get_utility(request)
        try:
            token = self.get_token(request)
            if token:
                claims = oidc.validate_access_token(token)
        except ExpiredSignatureError:
            # token is expired ... if we have a refresh token, we can try to
            # update the token
            self.log.info('Access Token expired')
            oidc_tokens = request.session.get('oidc.token')
            if not (oidc_tokens and oidc_tokens.get('refresh_token')):
                # no refresh token
                del request.session['oidc.token']
                return None
            # try refresh
            oauth = oidc.get_oauth2_session(request, token=oidc_tokens)
            try:
                self.log.info('Refreshing Access Token...')
                response = oauth.refresh_token(
                    oidc.token_endpoint,
                    auth=(oidc.client_id, oidc.client_secret)
                )
                self.log.info('Access Token refreshed')
            except InvalidGrantError:
                # most likely because refresh token has expired
                del request.session['oidc.token']
                self.log.info('Access Token refresh failed')
                return None
            # validate id_token
            id_token = oidc.validate_id_token(response['id_token'])
            access_token = response['access_token']
            claims = oidc.validate_access_token(access_token)
            # store new tokens in session (store full token response)
            oidc_tokens = dict(response)
            # and the decoded id_token
            oidc_tokens['id_token'] = id_token
            request.session['oidc.token'] = oidc_tokens
        if claims:
            # store claims in familiar place as well
            request.environ['oidc.claims'] = claims
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
        # We already store the tokens in the session ... nothing to do here
        return []

    # @IAuthenticationPolicy
    def forget(self, request):
        """ Return a set of headers suitable for 'forgetting' the
        current user on subsequent requests.
        """
        # Clear session
        request.session.invalidate()
        return []
