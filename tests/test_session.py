from datetime import datetime
import unittest

from pyramid import testing
import requests_mock

from .common import DummyRequest, gen_jwt, ISSUER, JWKS, WELL_KNOWN_OIDC_CONFIG


class TestSessionAuthenticationPolicy(unittest.TestCase):

    def setUp(self):
        self.config = testing.setUp()

        self.config.registry.settings.update({
            'oidc.issuer': ISSUER,
            'oidc.client_id': 'example_client_id',
            'oidc.client_secret': 'example_client_secret',
            # 'oidc.userid_claim': 'sub',
            # 'oidc.audience': 'example_audience',
            # 'oidc.verify_aud': 'True',
            'oidc.enable_views': 'True',
            'session.factory': 'pyramid_oidc.session.SessionFactory',
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
        from pyramid_oidc.authentication import OIDCSessionAuthenticationPolicy

        policy = OIDCSessionAuthenticationPolicy()
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

        # config.add_route('oidc.redirect_uri', '/redirect_uri',
        #                  request_param='code')
        # config.add_route('oidc.login', '/login')
        # config.add_route('oidc.logout', '/logout')
        # config.add_route('oidc.token', '/token')

    def test_unauthenticated_userid_is_None(self):
        request = DummyRequest()
        policy = self._makeOne()
        self.assertEqual(policy.unauthenticated_userid(request), None)
        self.assertEqual(policy.authenticated_userid(request), None)
        self.assertNotIn('oidc.claims', request.environ)

    def test_authenticated_userid(self):
        token = self._gen_token()
        oidc_token = {'access_token': token}
        request = DummyRequest(session={'oidc.token': oidc_token})
        policy = self._makeOne()
        self.assertEqual(policy.get_token(request), token)
        self.assertEqual(policy.unauthenticated_userid(request),
                         'example_user_id')
        self.assertEqual(policy.authenticated_userid(request),
                         'example_user_id')
        self.assertEqual(request.environ['oidc.claims']['sub'],
                         'example_user_id')
        # session should have tokens and environ claims
        self.assertEqual(request.session['oidc.token'], oidc_token)
        self.assertIn('oidc.claims', request.environ)

    # TODO: test refresh
    def test_expired_userid(self):
        token = self._gen_token(exp=-500)
        oidc_token = {'access_token': token}
        request = DummyRequest(session={'oidc.token': oidc_token})
        policy = self._makeOne()
        self.assertEqual(policy.get_token(request), token)
        self.assertEqual(policy.unauthenticated_userid(request), None)
        self.assertEqual(policy.authenticated_userid(request), None)
        self.assertNotIn('oidc.token', request.session)
        self.assertNotIn('oidc.claims', request.environ)

    @requests_mock.mock()
    def test_expired_refresh(self, m):
        new_token = self._gen_token()
        new_oidc_token = {'id_token': new_token, 'access_token': new_token,
                          'refresh_token': new_token}
        m.post('{}/token'.format(ISSUER),
               json=new_oidc_token)
        token = self._gen_token(exp=-500)
        oidc_token = {'access_token': token,
                      'refresh_token': token}
        request = DummyRequest(session={'oidc.token': oidc_token})
        policy = self._makeOne()
        self.assertEqual(policy.get_token(request), token)
        self.assertEqual(policy.unauthenticated_userid(request),
                         'example_user_id')
        self.assertEqual(policy.authenticated_userid(request),
                         'example_user_id')
        self.assertEqual(request.session['oidc.token']['access_token'],
                         new_token)
        self.assertEqual(request.session['oidc.token']['refresh_token'],
                         new_token)
        self.assertIn('oidc.claims', request.environ)

    @requests_mock.mock()
    def test_expired_refresh_fail(self, m):
        m.post('{}/token'.format(ISSUER),
               json={"error": "invalid_grant"})
               # error_description, error_uri, state
        token = self._gen_token(exp=-500)
        oidc_token = {'access_token': token,
                      'refresh_token': token}
        request = DummyRequest(session={'oidc.token': oidc_token})
        policy = self._makeOne()
        self.assertEqual(policy.get_token(request), token)
        self.assertEqual(policy.unauthenticated_userid(request), None)
        self.assertEqual(policy.authenticated_userid(request), None)
        self.assertNotIn('oidc.token', request.session)
        self.assertNotIn('oidc.claims', request.environ)

    # def test_fail_aud(self):
    #     token = self._gen_token(aud='other_client_id')
    #     request = DummyRequest(session={'oidc.token': {'access_token': token}})
    #     policy = self._makeOne()
    #     self.assertEqual(policy.get_token(request), token)
    #     self.assertEqual(policy.unauthenticated_userid(request), None)
    #     self.assertEqual(policy.authenticated_userid(request), None)
    #     self.assertNotIn('oidc.claims', request.environ)

    # def test_ignore_aud(self):
    #     request = DummyRequest()
    #     token = self._gen_token(aud='other_client_id')
    #     request.headers['Authorization'] = 'Bearer {}'.format(token)
    #     policy = self._makeOne()
    #     policy._get_utility(request).verify_aud = False
    #     self.assertEqual(policy.get_token(request), token)
    #     self.assertEqual(policy.unauthenticated_userid(request),
    #                      'example_user_id')
    #     self.assertEqual(policy.authenticated_userid(request),
    #                      'example_user_id')
    #     self.assertEqual(request.environ['oidc.claims']['sub'],
    #                      'example_user_id')

    # def test_other_aud(self):
    #     request = DummyRequest()
    #     token = self._gen_token(aud='other_client_id')
    #     request.headers['Authorization'] = 'Bearer {}'.format(token)
    #     policy = self._makeOne()
    #     policy._get_utility(request).audience = 'other_client_id'
    #     self.assertEqual(policy.get_token(request), token)
    #     self.assertEqual(policy.unauthenticated_userid(request),
    #                      'example_user_id')
    #     self.assertEqual(policy.authenticated_userid(request),
    #                      'example_user_id')
    #     self.assertEqual(request.environ['oidc.claims']['sub'],
    #                      'example_user_id')

    # def test_fail_other_aud(self):
    #     request = DummyRequest()
    #     token = self._gen_token()
    #     request.headers['Authorization'] = 'Bearer {}'.format(token)
    #     policy = self._makeOne()
    #     policy._get_utility(request).audience = 'other_client_id'
    #     self.assertEqual(policy.get_token(request), token)
    #     self.assertEqual(policy.unauthenticated_userid(request), None)
    #     self.assertEqual(policy.authenticated_userid(request), None)
    #     self.assertNotIn('oidc.claims', request.environ)

    def test_remember(self):
        request = DummyRequest()
        policy = self._makeOne()
        self.assertEqual(policy.remember(request, 'userid'), [])

    def test_forget(self):
        request = DummyRequest()
        policy = self._makeOne()
        self.assertEqual(policy.forget(request), [])
