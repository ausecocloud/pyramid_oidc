from datetime import datetime
import unittest

from pyramid import testing
import requests_mock

from .common import DummyRequest, gen_jwt, ISSUER, JWKS, WELL_KNOWN_OIDC_CONFIG


class TestBearerAuthenticationPolicy(unittest.TestCase):

    def setUp(self):
        self.config = testing.setUp()

        self.config.registry.settings.update({
            'oidc.issuer': ISSUER,
            'oidc.client_id': 'example_client_id',
            # 'oidc.client_secret': 'example_client_secret',
            # 'oidc.userid_claim': 'sub',
            # 'oidc.audience': 'example_audience',
            # 'oidc.verify_aud': 'True',
            # 'oidc.enable_views': 'True'
        })
        with requests_mock.mock() as m:
            m.get('{}/.well-known/openid-configuration'.format(ISSUER),
                  json=WELL_KNOWN_OIDC_CONFIG)
            m.get('{}/jwks'.format(ISSUER), json=JWKS)
            self.config.include('pyramid_oidc')
        self.messages = []

    def tearDown(self):
        del self.config
        testing.tearDown()

    def _makeOne(self, userid=None):
        from pyramid_oidc.authentication import OIDCBearerAuthenticationPolicy

        policy = OIDCBearerAuthenticationPolicy()
        return policy

    def _gen_token(self, exp=500, aud='example_client_id'):
        return gen_jwt({
            'iss': 'https://example.com',
            'exp': int(datetime.utcnow().timestamp()) + exp,
            'aud': aud,
            'sub': 'example_user_id',
            'realm_access': {
                'roles': [],
            },
            'resource_access': {
                'resource': {
                    'roles': []
                }
            }
        })

    def test_unauthenticated_userid_is_None(self):
        request = DummyRequest()
        policy = self._makeOne()
        self.assertEqual(policy.unauthenticated_userid(request), None)
        self.assertEqual(policy.authenticated_userid(request), None)
        self.assertNotIn('oidc.claims', request.environ)

    def test_authenticated_userid(self):
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

    def test_expired_userid(self):
        request = DummyRequest()
        token = self._gen_token(exp=-500)
        request.headers['Authorization'] = 'Bearer {}'.format(token)
        policy = self._makeOne()
        self.assertEqual(policy.get_token(request), token)
        self.assertEqual(policy.unauthenticated_userid(request), None)
        self.assertEqual(policy.authenticated_userid(request), None)
        self.assertNotIn('oidc.claims', request.environ)

    def test_fail_aud(self):
        request = DummyRequest()
        token = self._gen_token(aud='other_client_id')
        request.headers['Authorization'] = 'Bearer {}'.format(token)
        policy = self._makeOne()
        self.assertEqual(policy.get_token(request), token)
        self.assertEqual(policy.unauthenticated_userid(request), None)
        self.assertEqual(policy.authenticated_userid(request), None)
        self.assertNotIn('oidc.claims', request.environ)

    def test_ignore_aud(self):
        request = DummyRequest()
        token = self._gen_token(aud='other_client_id')
        request.headers['Authorization'] = 'Bearer {}'.format(token)
        policy = self._makeOne()
        policy._get_utility(request).verify_aud = False
        self.assertEqual(policy.get_token(request), token)
        self.assertEqual(policy.unauthenticated_userid(request),
                         'example_user_id')
        self.assertEqual(policy.authenticated_userid(request),
                         'example_user_id')
        self.assertEqual(request.environ['oidc.claims']['sub'],
                         'example_user_id')

    def test_other_aud(self):
        request = DummyRequest()
        token = self._gen_token(aud='other_client_id')
        request.headers['Authorization'] = 'Bearer {}'.format(token)
        policy = self._makeOne()
        policy._get_utility(request).audience = 'other_client_id'
        self.assertEqual(policy.get_token(request), token)
        self.assertEqual(policy.unauthenticated_userid(request),
                         'example_user_id')
        self.assertEqual(policy.authenticated_userid(request),
                         'example_user_id')
        self.assertEqual(request.environ['oidc.claims']['sub'],
                         'example_user_id')

    def test_fail_other_aud(self):
        request = DummyRequest()
        token = self._gen_token()
        request.headers['Authorization'] = 'Bearer {}'.format(token)
        policy = self._makeOne()
        policy._get_utility(request).audience = 'other_client_id'
        self.assertEqual(policy.get_token(request), token)
        self.assertEqual(policy.unauthenticated_userid(request), None)
        self.assertEqual(policy.authenticated_userid(request), None)
        self.assertNotIn('oidc.claims', request.environ)

    def test_remember(self):
        request = DummyRequest()
        policy = self._makeOne()
        self.assertEqual(policy.remember(request, 'userid'), [])

    def test_forget(self):
        request = DummyRequest()
        policy = self._makeOne()
        self.assertEqual(policy.forget(request),
                         [('WWW-Authenticate', 'Bearer')])
