import os

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
                 **kwargs):
        self.issuer = issuer
        self.client_id = client_id
        self.client_secret = client_secret
        self.scope = 'openid'
        if 'scope' in kwargs:
            self.scope = kwargs['scope']
        if not audience:
            self.audience = client_id
        # our settings parser my put None in in case the value has not been configured.
        if verify_aud is None:
            verify_aud = True
        self.verify_aud = verify_aud

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
            redirect_uri=request.route_url('oidc.redirect_uri'),
            # state=,
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
            # state=None,
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

    def validate_id_token(self, id_token):
        """Decode and validate given id token."""
        # typical validation:
        # - check signature
        # - check issuer, audience, timestamps (iat, exp), nonce
        return jwt.decode(
            token=id_token,
            key=self.jwk,
            audience=self.audience,
            issuer=self.issuer,
        )

    def validate_access_token(self, token):
        # verify access token and return claims
        # TODO: assumes access token is a jwt with useful attributes
        if not token:
            return None
        return jwt.decode(
            token=token,
            key=self.jwk,
            audience=self.audience,
            issuer=self.issuer,
            options={
                'verify_aud': self.verify_aud,
            },
        )

    def get_unverified_claims(self, token):
        return jwt.get_unverified_claims(token)
