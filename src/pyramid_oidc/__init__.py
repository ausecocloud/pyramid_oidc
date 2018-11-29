import os

from pyramid.settings import asbool

from .interfaces import IOIDCUtility
from .utilities import OIDCUtility


def parse_setting(settings, prefix, key, conv=None, envvar=True):
    val = None
    name = ''.join([prefix, key])
    if envvar:
        envvar = name.replace('.', '_').upper()
        val = os.environ.get(envvar, None)
    if val is None:
        val = settings.get(name, None)
    if val is not None and conv is not None:
        val = conv(val)
    return val


def get_session_opts(settings):
    # session opts
    prefix = 'session.'
    opts = {}
    for key, envvar in (('factory', False), ('secret', True)):
        val = parse_setting(settings, prefix, key, envvar=envvar)
        if val:
            opts[key] = val
    # get int settings
    for key in ('timeout', 'refresh'):
        val = parse_setting(settings, prefix, key, conv=int, envvar=False)
        if val is not None:
            opts[key] = val
    # bool vars
    for key in ('on_exception',):
        val = parse_setting(settings, prefix, key, conv=asbool, envvar=False)
        if val is not None:
            opts[key] = val

    # cookie opts
    prefix = 'session.cookie_opts.'
    cookie_opts = {}
    for key in ('name', 'path', 'domain'):
        val = parse_setting(settings, prefix, key, envvar=False)
        if val:
            cookie_opts[key] = val
    # int opts
    for key in ('max_age',):
        val = parse_setting(settings, prefix, key, conv=int, envvar=False)
        if val is not None:
            opts[key] = val
    # bool opts
    for key in ('secure', 'httponly'):
        val = parse_setting(settings, prefix, key, conv=asbool, envvar=False)
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


def build_oidc_utility(settings, prefix):
    return OIDCUtility(
        issuer=parse_setting(settings, prefix, 'issuer'),
        client_id=parse_setting(settings, prefix, 'client_id'),
        client_secret=parse_setting(settings, prefix, 'client_secret'),
        userid_claim=parse_setting(settings, prefix, 'userid_claim'),
        audience=parse_setting(settings, prefix, 'audience'),
        verify_aud=parse_setting(settings, prefix, 'verify_aud', conv=asbool),
    )


def includeme(config):
    settings = config.get_settings()

    utility = build_oidc_utility(settings, 'oidc.')
    config.registry.registerUtility(utility, IOIDCUtility)

    if asbool(settings.get('oidc.enable_views', True)):
        # TODO: could make urls configurable ...
        #       have to add more specificity to redirect_uri in case it hase the
        #       same route pattern as login... (e.g. require code parameter)
        config.add_route('pyramid_oidc.redirect_uri', '/redirect_uri',
                         request_param='code')
        config.add_route('pyramid_oidc.login', '/login')
        config.add_route('pyramid_oidc.logout', '/logout')
        config.scan()

    # setup session factory if requested
    session_opts = get_session_opts(settings)
    session_factory = session_opts.pop('factory', None)
    if session_factory:
        factory = config.maybe_dotted(session_factory)
        config.set_session_factory(factory(**session_opts))
