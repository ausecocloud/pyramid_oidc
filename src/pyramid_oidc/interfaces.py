import os

from zope.interface import Interface, Attribute


class IOIDCUtility(Interface):

    issuer = Attribute('Issuer URI')
    scope = Attribute('OIDC Scope')

    client_id = Attribute('Client ID')
    client_secret = Attribute('Client Secret')

    userid_claim = Attribute('Userid claim')

    verify = Attribute('Verify SSL')

    # Auto populated attributes
    # self.config = config
    # self.authorization_endpoint = config['authorization_endpoint']
    # self.token_endpoint = config['token_endpoint']
    # self.token_introspection_endpoint = config['token_introspection_endpoint']
    # self.userinfo_endpoint = config['userinfo_endpoint']
    # self.jwks_uri = config['jwks_uri']
    # TODO: refresh jwks every now and then
    # self.jwk = requests.get(self.jwks_uri, verify=self.verify).json()

    def __init__(self, issuer, client_id, client_secret,
                 userid_claim='sub',
                 callback=None, debug=False, route_prefix='',
                 **kwargs):
        self.callback = callback
        self.debug = debug

        self.issuer = issuer
        self.client_id = client_id
        self.client_secret = client_secret
        self.scope = 'openid'
        if 'scope' in kwargs:
            self.scope = kwargs['scope']

        self.userid_claim = userid_claim

        # Disbale SSL verify
        self.verify = os.environ.get('PYTHONHTTPSVERIFY', None) != '0'

        # load openid-configuration
        self._load_configuration()

