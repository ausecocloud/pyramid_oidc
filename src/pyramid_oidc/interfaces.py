from zope.interface import Interface, Attribute


class IOIDCUtility(Interface):

    issuer = Attribute('Issuer URI')
    scope = Attribute('OIDC Scope')

    client_id = Attribute('Client ID')
    client_secret = Attribute('Client Secret')

    userid_claim = Attribute('Userid claim')

    verify = Attribute('Verify SSL')
