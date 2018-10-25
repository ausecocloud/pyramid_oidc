
pyramid_oidc
============


Provides authenticators to handle OIDC bearer tokens and manage OIDC login
via sessions.

It also provides a pyramid session factory which uses dogpile.cache as session
store.

The session factory can be configured via ini file. To configure the
authenticators via ini settings, you need to use a library like
pyramid_multiauth.

There is also a little helper authenticator callback (groupfinder) method
to extract realm and client roles (scopes) for Keycloak tokens.

For the session based authenticator, this package also provides a set of OIDC
flow helper views.


.. code:: python

    config.include('pyramid_oidc', route_prefix='/oidc')



Configuration:
==============

.. code:: ini

    # example which uses multiauth to configure authentication
    multiauth.policies = bearer session
    multiauth.policy.bearer.use = pyramid_oidc.authentication.OIDCBearerAuthenticationPolicy
    #multiauth.policy.bearer.callback =
    multiauth.policy.session.use = pyramid_oidc.authentication.OIDCSessionAuthenticationPolicy
    #multiauth.policy.session.callback =
    multiauth.authorization_policy = pyramid.authorization.ACLAuthorizationPolicy
    multiauth.groupfinder = pyramid_oidc.authentication.keycloak.keycloak_callback

    # These settings can also be passed via environment variables
    # env vars have greater precedence than settings in ini file
    oidc.issuer =
    oidc.client_id =
    oidc.client_secret =
    # settings to deal with audience claims
    #oidc.audience =
    #oidc.verify_aud = True
    # set to something falsy if oidc views should be disabled
    #oidc.enable_views = True

    # Configure session
    # if session.factory is not configured, no session factory will be set up
    # by this module
    session.factory = pyramid_oidc.session.SessionFactory
    # Configure a session.secret if required. This secret is used to sign
    # the session cookie. A session secret will be created on startup if
    # this is not set. Session secret can also be set via SESSION_SECRET
    # environment variable.
    #session.secret =
    # Session cookie timeout
    #session.timeout = 1200
    # Session cookie refresh interval
    #session.refresh = <session.timeout // 2>
    # Set session cookie even on exception
    #session.on_exception = True

    # Session cookie settings:
    # Cookie name
    #session.cookie_opts.name = oidc.session
    # cookie max_age
    #session.cookie_opts.max_age = <session.timeout>
    # cookie path
    #session.cookie_opts.path = /
    # cookie domain
    #session.cookie_opts.domain = <None>
    # send cookie only over ssl
    # session.cookie_opts.secure = True
    # cookie accessible to javascript
    # session.cookie_opts.httponly = True

    # Dogpile settings for session cache
    # Configuration options are passed directly to dogpile.
    # dogpile cache backend
    # session.dogpile_opts.backend = dogpile.cache.memory
    # default cache expiration time
    # session.dogpile_opts.expiration_timeout = <session.timeout>

    # Example to use redis as backend
    # session.dogpile_opts.backend = dogpile.cache.redis
    # session.dogpile_opts.arguments.host = 172.17.0.4
    # session.dogpile_opts.arguments.port = 6379
    # session.dogpile_opts.arguments.redis_expiration_time = 2400
    # session.dogpile_opts.debug = True
