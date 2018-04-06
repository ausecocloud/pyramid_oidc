import os

from pyramid.settings import asbool

from .interfaces import IOIDCUtility
from .utilities import OIDCUtility

# TODO: support multiple IOIDC clients? ... lookup utilities by name
# TODO: maybe use IOIDCProvider instead of IOIDCUtility?


def parse_setting(settings, prefix, key, conv=None, envvar=None):
    val = None
    if envvar:
        val = os.environ.get(envvar, None)
    if val is None:
        val = settings.get('{}{}'.format(prefix, key), None)
    if val is not None and conv is not None:
        val = conv(val)
    return val


def get_session_opts(settings):
    # session opts
    prefix = 'session.'
    opts = {}
    for key, envvar in (('factory', None), ('secret', 'SESSION_SECRET')):
        val = parse_setting(settings, prefix, key, envvar=envvar)
        if val:
            opts[key] = val
    # get int settings
    for key in ('timeout', 'refresh'):
        val = parse_setting(settings, prefix, key, conv=int)
        if val is not None:
            opts[key] = val
    # bool vars
    for key in ('on_exception',):
        val = parse_setting(settings, prefix, key, conv=asbool)
        if val is not None:
            opts[key] = val

    # cookie opts
    prefix = 'session.cookie_opts.'
    cookie_opts = {}
    for key in ('name', 'path', 'domain'):
        val = parse_setting(settings, prefix, key)
        if val:
            cookie_opts[key] = val
    # int opts
    for key in ('max_age',):
        val = parse_setting(settings, prefix, key, conv=int)
        if val is not None:
            opts[key] = val
    # bool opts
    for key in ('secure', 'httponly'):
        val = parse_setting(settings, prefix, key, conv=asbool)
        if val is not None:
            cookie_opts[key] = val
    if cookie_opts:
        opts['cookie_opts'] = cookie_opts

    # dogpile opts
    prefix = 'session.dogpile_opts.'
    dogpile_opts = {}
    for key in settings:
        if not key.startswith(prefix):
            continue
        dogpile_opts[key[len(prefix):]] = settings[key]
    if dogpile_opts:
        opts['dogpile_opts'] = dogpile_opts

    return opts


def includeme(config):
    settings = config.get_settings()

    utility = OIDCUtility(
        issuer=parse_setting(settings, 'oidc.', 'issuer',
                             envvar='OIDC_ISSUER'),
        client_id=parse_setting(settings, 'oidc.', 'client_id',
                                envvar='OIDC_CLIENT_ID'),
        client_secret=parse_setting(settings, 'oidc.', 'client_secret',
                                    envvar='OIDC_CLIENT_SECRET'),
        userid_claim=parse_setting(settings, 'oidc.', 'userid_claim',
                                   envvar='OIDC_USERID_CLAIM')
    )
    config.registry.registerUtility(utility, IOIDCUtility)

    if asbool(settings.get('oidc.enable_views', True)):
        # TODO: could make urls configurable ...
        #       have to add more speificity to redirect_uri in case it hase the
        #       same route pattern as login... (e.g. require code parameter)
        config.add_route('oidc.redirect_uri', '/redirect_uri',
                         request_param='code')
        config.add_route('oidc.login', '/login')
        config.add_route('oidc.logout', '/logout')
        config.add_route('oidc.token', '/token')
        config.scan()

    # setup session factory if requested
    session_opts = get_session_opts(settings)
    session_factory = session_opts.pop('factory', None)
    if session_factory:
        factory = config.maybe_dotted(session_factory)
        config.set_session_factory(factory(**session_opts))

