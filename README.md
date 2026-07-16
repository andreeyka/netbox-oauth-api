# netbox-keycloak-jwt-auth

Keycloak JWT (Bearer) authentication for the NetBox REST API.

NetBox supports OIDC only for UI login (via python-social-auth); the REST API
accepts only native `Token <key>` credentials or a session. This plugin adds a
DRF authentication backend that validates Keycloak-issued access tokens
(`Authorization: Bearer <JWT>`) directly against the realm's JWKS and maps the
token onto a NetBox user — no token-exchange service, no admin token to store,
no secrets at all (only the realm's public keys are ever fetched).

## Features

- **Signature validation via JWKS** — keys are fetched from
  `{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/certs`, cached in the
  Django cache and force-refreshed once when an unknown `kid` appears
  (key rotation works without a NetBox restart, with a cooldown against
  refresh storms).
- **Strict claim checks** — `iss`, `aud`, `exp`/`nbf`/`iat` with configurable
  clock skew; `alg: none` and symmetric (HMAC) algorithms are rejected
  unconditionally.
- **User mapping by stable identity** — users are matched by the immutable
  `sub` claim first (stored in a `KeycloakIdentity` record), so renames in
  Keycloak never create duplicate NetBox accounts. Missing users can be
  auto-created with profile fields from the token.
- **Group and flag sync** — Keycloak roles (from a configurable, possibly
  nested claim path) map to NetBox groups. Only managed groups are touched:
  locally assigned groups survive. Optional `is_superuser` / `is_staff`
  control (off by default).
- **Fast hot path** — the sub+roles→user mapping is cached (default 60 s);
  a cache hit performs no writes and no network calls. The roles hash in the
  cache key makes role changes take effect immediately.
- **Chain-friendly** — any non-`Bearer` Authorization scheme is passed to the
  next authentication class, so native NetBox tokens and sessions keep
  working unchanged.
- **Audit-friendly** — validated claims are exposed as
  `request.keycloak_claims`; NetBox change logging attributes changes to the
  mapped user. Failures return an opaque 401 while details go to the
  `netbox_keycloak_jwt_auth` logger. Tokens are never logged.

## Compatibility

| Component | Version           |
|-----------|-------------------|
| NetBox    | 4.0 – 4.2         |
| Python    | 3.10+             |
| Keycloak  | 22+ (OIDC realm)  |

## Installation

```bash
pip install netbox-keycloak-jwt-auth
```

Then restart both `netbox` and `netbox-rq`.

## Configuration

```python
PLUGINS = ['netbox_keycloak_jwt_auth']

PLUGINS_CONFIG = {
    'netbox_keycloak_jwt_auth': {
        # required
        'KEYCLOAK_URL': 'https://keycloak.example.com',
        'REALM': 'infra',
        'AUDIENCE': 'netbox',
        # validation
        'ALLOWED_ALGORITHMS': ['RS256'],
        'CLOCK_SKEW_SECONDS': 30,
        'VERIFY_SSL': True,          # or a path to a CA bundle
        'JWKS_CACHE_TTL': 300,
        'JWKS_REFRESH_COOLDOWN': 30,
        'HTTP_TIMEOUT': 5.0,
        # user mapping
        'USERNAME_CLAIM': 'preferred_username',
        'AUTO_CREATE_USER': True,
        # permissions
        'GROUP_SYNC_ENABLED': True,
        'ROLES_CLAIM_PATH': 'realm_access.roles',
        'AUTO_CREATE_GROUPS': True,
        'ROLE_GROUP_MAPPING': {
            'netbox-admin': 'NetBox Administrators',
            'netbox-write': 'NetBox Writers',
            'netbox-read': 'NetBox Readers',
        },
        'SUPERUSER_ROLES': [],
        'STAFF_ROLES': [],
        # caching
        'USER_CACHE_TTL': 60,
    }
}

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'netbox_keycloak_jwt_auth.authentication.KeycloakJWTAuthentication',
        'netbox.api.authentication.TokenAuthentication',
        'rest_framework.authentication.SessionAuthentication',
    ],
}
```

`KEYCLOAK_URL`, `REALM` and `AUDIENCE` are mandatory: NetBox refuses to start
without them (a missing `AUDIENCE` would otherwise let any client of the
realm access the API). The configuration is validated at startup, not at the
first request.

### Settings reference

| Setting | Default | Description |
|---|---|---|
| `KEYCLOAK_URL` | — | Base URL of the Keycloak server |
| `REALM` | — | Realm name; issuer is `{KEYCLOAK_URL}/realms/{REALM}` |
| `AUDIENCE` | — | Required `aud` value (your NetBox client) |
| `ALLOWED_ALGORITHMS` | `['RS256']` | Signature algorithms; `none`/HS* are always refused |
| `CLOCK_SKEW_SECONDS` | `30` | Leeway for `exp` / `nbf` / `iat` |
| `VERIFY_SSL` | `True` | TLS verification for JWKS requests (bool or CA path) |
| `JWKS_CACHE_TTL` | `300` | JWKS cache lifetime, seconds |
| `JWKS_REFRESH_COOLDOWN` | `30` | Min. interval between forced JWKS refreshes |
| `HTTP_TIMEOUT` | `5.0` | JWKS request timeout, seconds |
| `USERNAME_CLAIM` | `preferred_username` | Claim used as the NetBox username |
| `AUTO_CREATE_USER` | `True` | Create missing users on first request |
| `GROUP_SYNC_ENABLED` | `True` | Master switch for group/flag sync |
| `ROLES_CLAIM_PATH` | `realm_access.roles` | Dot-separated path to the role list |
| `AUTO_CREATE_GROUPS` | `True` | Create mapped groups when missing |
| `ROLE_GROUP_MAPPING` | `{}` | Keycloak role → NetBox group name |
| `SUPERUSER_ROLES` | `[]` | Roles granting `is_superuser` (empty = unmanaged) |
| `STAFF_ROLES` | `[]` | Roles granting `is_staff` (empty = unmanaged) |
| `USER_CACHE_TTL` | `60` | sub+roles → user cache lifetime, seconds |

## Usage

```bash
curl -H "Authorization: Bearer $(get-keycloak-token)" \
     https://netbox.example.com/api/dcim/devices/
```

Responses are filtered by the mapped user's NetBox permissions, exactly as
with a native token. Native `Authorization: Token <key>` requests are
untouched.

## Security notes

- The plugin stores no secrets — only the realm's public JWKS is fetched.
- Tokens are never written to logs; log records reference `sub` and `jti` only.
- Failed validation always yields an opaque `401` (details at `WARNING` level
  in the `netbox_keycloak_jwt_auth` logger).
- `VERIFY_SSL = False` is for development only and produces a startup warning.
- Granting `is_superuser` from token roles is opt-in and disabled by default.

## Development

```bash
pip install -e .[test]
pytest
```

The test suite runs against a minimal Django project (no NetBox instance
required) and covers negative cases: expired/forged tokens, wrong audience or
issuer, `alg: none`, symmetric algorithms, missing `kid`, key rotation and
refresh cooldown.

## License

MIT
