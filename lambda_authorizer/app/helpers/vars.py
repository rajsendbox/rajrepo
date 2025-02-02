import os

AUTHENTICATION_EXCLUDED_PATHS = [
    '/auth/login/', '/auth/login', 
    '/auth/token/', '/auth/token', 
    '/auth/verify/', '/auth/verify', 
    '/auth/refresh/', '/auth/refresh'
]

AUTHORIZATION_EXCLUDED_PATHS = AUTHENTICATION_EXCLUDED_PATHS + ['/notifications/types/', '/auth/logout', '/auth/logout/']

AUTHORIZATION_EXCLUDED_PATHS_WILDCARD = ['/notifications/', ]

USER = 'user'

ALLOW = 'Allow'

DENY = 'Deny'

AUTH_API_INTERNAL_ENDPOINT = os.environ.get('AUTH_API_INTERNAL_ENDPOINT')
KEYCLOAK_API_INTERNAL_ENDPOINT = os.environ.get('KEYCLOAK_API_INTERNAL_ENDPOINT', "https://dev-01.auth.merumesh.com")
SECRET_NAME = os.getenv("KEYCLOAK_CREDS","keyclock/admin/creds")
