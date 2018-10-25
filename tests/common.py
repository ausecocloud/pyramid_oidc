# define some constants to be used in unittests
import json

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from jose import jwt
from jose.constants import ALGORITHMS
from jose.backends import RSAKey
from pyramid import testing


# A testing request enhanced with some WebOb properties
class DummyRequest(testing.DummyRequest):

    @property
    def authorization(self):
        authorization = self.headers.get('Authorization')
        try:
            from webob.descriptors import parse_auth
            return parse_auth(authorization)
        except Exception:
            pass
        return None


# create an encoded jwt with keys from this module
def gen_jwt(claims):
    return jwt.encode(claims, PRIVKEY, ALGORITHMS.RS256)


# help to generate random keys
def gen_new_keys():
    key = rsa.generate_private_key(65537, 2048, default_backend())
    pem = key.private_bytes(encoding=serialization.Encoding.PEM,
                            format=serialization.PrivateFormat.PKCS8,
                            encryption_algorithm=serialization.NoEncryption())
    privkey = RSAKey(pem, ALGORITHMS.RS256).to_dict()
    privkey['id'] = 'keyid'
    for k in privkey:
        if isinstance(privkey[k], bytes):
            privkey[k] = privkey[k].decode('utf-8')
    pkey = key.public_key()
    pem = pkey.public_bytes(encoding=serialization.Encoding.PEM,
                            format=serialization.PublicFormat.PKCS1)
    pubkey = RSAKey(pem, ALGORITHMS.RS256).to_dict()
    pubkey['id'] = 'keyid'
    for k in pubkey:
        if isinstance(pubkey[k], bytes):
            pubkey[k] = pubkey[k].decode('utf-8')
    return privkey, pubkey


PRIVKEY, PUBKEY = gen_new_keys()

JWKS = {
    "keys": [PUBKEY]
}


ISSUER = 'https://example.com'
WELL_KNOWN_OIDC_CONFIG = {
    'issuer': ISSUER,
    'authorization_endpoint': '{}/auth'.format(ISSUER),
    'token_endpoint': '{}/token'.format(ISSUER),
    'token_introspection_endpoint': '{}/introspect'.format(ISSUER),
    'userinfo_endpoint': '{}/userinfo'.format(ISSUER),
    'jwks_uri': '{}/jwks'.format(ISSUER),
}
