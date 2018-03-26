

def keycloak_callback(userid, request):
    # extract role claims from decoded access_token
    claims = request.environ.get('oidc.claims', {})
    if not claims:
        # no claims, so not authenticated
        return None
    # realm_access ... roles per realm
    roles = []
    roles.extend(claims.get('realm_access', {}).get('roles', []))
    # resource_access ... roles per application
    for resource, resource_roles in claims.get('resource_access', {}).items():
        roles.extend('{}/{}'.format(resource, role)
                     for role in resource_roles.get('roles', []))
    # roles way be empty here, but we have a doceded access token so we should
    # not return None
    return roles
