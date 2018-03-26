from pyramid.httpexceptions import HTTPFound
from pyramid.view import view_config

from .interfaces import IOIDCUtility


@view_config(route_name='oidc.login')
def login(request):
    # Trigger login flow. We start a new session, and redirect to
    # authentication endpoint.
    # all login related state is stored in the session 'oidc.login'

    # if we already have a valid user, just redirect back to previous url
    if request.authenticated_userid:
        return HTTPFound(
            request.headers.get('Referer', None) or
            # TODO: logged in view would work here as well
            request.application_url
        )

    # redirect user to auth endpoint
    oidc = request.registry.getUtility(IOIDCUtility)
    auth_url, state = oidc.get_auth_url(request)
    # store state in session
    session = request.session
    session['oidc.login'] = {
        'state': state,
        'came_from': request.headers.get('Referer')
    }
    # can do raise or return, but return seems to be more fitting
    # as it is not really an error condition here
    return HTTPFound(auth_url)


@view_config(route_name='oidc.redirect_uri')
def redirect_uri(request):
    # TODO: we just assume things here and let it fail terribly if our
    #       assumption is wrong. e.g.: code param, session state is there

    oidc = request.registry.getUtility(IOIDCUtility)
    session = request.session
    # there is only one chance to get this right
    state = session.pop('oidc.login', {})
    response = oidc.fetch_auth_token(
        request,
        state=state.get('state')
    )
    # response should now be a dict with keys:
    #   access_token, expires_at, expires_in
    #   refresh_token, refresh_expires_in
    #   id_token
    #   not-before-policy, session_state, token_type='bearer'

    # validate id_token
    id_token = oidc.validate_id_token(response['id_token'])

    # store tokens in sesssion
    # TODO: configure which bits of the toeken response we want to keep?
    #       should authpol to this? (or utility) it relies on this as well
    oidc_tokens = dict(response)
    oidc_tokens['id_token'] = id_token
    session['oidc.token'] = oidc_tokens
    # clear old stuff
    return HTTPFound(
        state.get('came_from') or
        # TODO: logged in view would work here as well
        request.application_url
    )


@view_config(route_name='oidc.logout')
def logout(request):
    # TODO: we probabl want to call / redirect to the oidc lougout endpoint
    #       if possible
    # logout from oidc, with redirect to where?
    session = request.session
    session.invalidate()
    return HTTPFound(
        request.headers.get('Referer', None) or
        # TODO: some logged_out view would work as well
        request.application_url
    )
