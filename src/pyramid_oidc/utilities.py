import os
import warnings

# TODO: oauthlib uses pyjwt?
from jose import jwt
import requests
from requests_oauthlib import OAuth2Session
from zope.interface import implementer

from .interfaces import IOIDCUtility


@implementer(IOIDCUtility)
class OIDCUtility(object):

    def __init__(self, issuer, client_id, client_secret,
                 userid_claim='sub',
                 audience=None, verify_aud=None,
                 redirect_route='pyramid_oidc.redirect_uri',
                 redirect_route_params=None,
                 **kwargs):
        self.issuer = issuer
        self.client_id = client_id
        self.client_secret = client_secret
        self.scope = 'openid'
        if 'scope' in kwargs:
            self.scope = kwargs['scope']
        self.audience = client_id
        if audience:
            self.audience = audience
        # our settings parser my put None in in case the value has not been configured.
        if verify_aud is None:
            verify_aud = True
        self.verify_aud = verify_aud
        self.redirect_route = redirect_route
        if redirect_route_params is None:
            redirect_route_params = {}
        self.redirect_route_params = redirect_route_params

        self.userid_claim = userid_claim or 'sub'

        # Disbale SSL verify
        self.verify = os.environ.get('PYTHONHTTPSVERIFY', None) != '0'

        # load openid-configuration
        self._load_configuration()

    def _load_configuration(self):
        config_url = '{}/.well-known/openid-configuration'.format(self.issuer)
        config = requests.get(config_url, verify=self.verify).json()
        # TODO: assert issuer config['issuer']
        self.config = config
        self.authorization_endpoint = config['authorization_endpoint']
        self.token_endpoint = config['token_endpoint']
        self.token_introspection_endpoint = config['token_introspection_endpoint']
        self.userinfo_endpoint = config['userinfo_endpoint']
        self.jwks_uri = config['jwks_uri']
        # TODO: refresh jwks every now and then
        self.jwk = requests.get(self.jwks_uri, verify=self.verify).json()

    def get_oauth2_session(self, request, state=None, scope=None, token=None):
        session = OAuth2Session(
            client_id=self.client_id,
            auto_refresh_url=self.token_endpoint,
            # auto_refresh_kwargs,
            scope=scope or self.scope,
            redirect_uri=request.route_url(self.redirect_route, **self.redirect_route_params),
            state=state,
            token=token,
            # **kwargs:
            #   code=None,
        )
        return session

    def fetch_user_info(self, request, token):
        """Call user info endpoint with given token to retrieve detailed
        information about current user.
        """
        oauth = self.get_oauth2_session(request, token=token)
        # from urllib.parse import urlencode
        return oauth.get(
            self.userinfo_endpoint,
            token={
                'access_token': token,
                'token_type': 'Bearer'
            },
            verify=self.verify
        ).json()

    def get_auth_url(self, request, scope=None):
        """Return URL to redirect user to authenticate."""
        oauth = self.get_oauth2_session(request, scope=scope)
        return oauth.authorization_url(
            url=self.authorization_endpoint,
            # **kwargs
        )

    def fetch_auth_token(self, request, state=None, scope=None):
        """Trade code from auth server for access, id, refresh tokens."""
        oauth = self.get_oauth2_session(request, state=state, scope=scope)
        token = oauth.fetch_token(
            token_url=self.token_endpoint,
            authorization_response=request.url,
            auth=(self.client_id, self.client_secret),
            # **kwargs
        )
        return token

    def validate_token(self, token, verify_exp=True):
        """Decode and validate given id token.

           Assumes token is a JWT.

           TODO: use token introspection endpoint for non JWT tokens.
                 in case of id_tokens it may be more appropriate to call user info endpoint?
        """
        # typical validation:
        # - check signature
        # - check issuer, audience, timestamps (iat, exp), nonce
        if not token:
            return None
        return jwt.decode(
            token=token,
            key=self.jwk,
            audience=self.audience,
            issuer=self.issuer,
            options={
                'verify_aud': self.verify_aud,
                'verify_exp': verify_exp,
            }
        )

    def validate_id_token(self, id_token):
        warnings.warn('use OIDCUtility.validate_token', category=DeprecationWarning, stacklevel=2)
        return self.validate_token(id_token)

    def validate_access_token(self, token):
        warnings.warn('use OIDCUtility.validate_token', category=DeprecationWarning, stacklevel=2)
        return self.validate_token(token)

    def get_unverified_claims(self, token):
        return jwt.get_unverified_claims(token)
