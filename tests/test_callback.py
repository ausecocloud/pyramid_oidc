from datetime import datetime
import unittest

from pyramid import testing
import requests_mock

from .common import DummyRequest, gen_jwt, JWKS, WELL_KNOWN_OIDC_CONFIG


class TestBearerAuthenticationPolicy(unittest.TestCase):

    def setUp(self):
        self.config = testing.setUp()

        self.config.registry.settings.update({
            'oidc.issuer': 'https://example.com',
            'oidc.client_id': 'example_client_id',
            # 'oidc.client_secret': 'example_client_secret',
            # 'oidc.userid_claim': 'sub',
            # 'oidc.audience': 'example_audience',
            # 'oidc.verify_aud': 'True',
            # 'oidc.enable_views': 'True'
        })
        with requests_mock.mock() as m:
            m.get('https://example.com/.well-known/openid-configuration',
                  json=WELL_KNOWN_OIDC_CONFIG)
            m.get('https://example.com/jwks', json=JWKS)
            self.config.include('pyramid_oidc')
        self.messages = []

    def tearDown(self):
        del self.config
        testing.tearDown()

    def _makeOne(self, userid=None):
        from pyramid_oidc.authentication import OIDCBearerAuthenticationPolicy
        from pyramid_oidc.authentication.keycloak import keycloak_callback
        policy = OIDCBearerAuthenticationPolicy(keycloak_callback)
        return policy

    def _gen_token(self, exp=500, aud='example_client_id'):
        return gen_jwt({
            'iss': 'https://example.com',
            'exp': int(datetime.utcnow().timestamp()) + exp,
            'aud': aud,
            'sub': 'example_user_id',
            'realm_access': {
                'roles': ['realm_role'],
            },
            'resource_access': {
                'resource': {
                    'roles': ['resource_role']
                }
            }
        })

    def test_unauthenticated_no_roles(self):
        request = DummyRequest()
        policy = self._makeOne()
        self.assertEqual(policy.authenticated_userid(request), None)
        self.assertEqual(policy.effective_principals(request),
                         ['system.Everyone'])

    def test_authenticated_roles(self):
        request = DummyRequest()
        token = self._gen_token()
        request.headers['Authorization'] = 'Bearer {}'.format(token)
        policy = self._makeOne()
        self.assertEqual(policy.get_token(request), token)
        self.assertEqual(policy.unauthenticated_userid(request),
                         'example_user_id')
        self.assertEqual(policy.authenticated_userid(request),
                         'example_user_id')
        self.assertEqual(request.environ['oidc.claims']['sub'],
                         'example_user_id')
        self.assertEqual(
            policy.effective_principals(request),
            [
                'system.Everyone', 'system.Authenticated', 'example_user_id',
                'realm_role', 'resource/resource_role'
            ]
        )
