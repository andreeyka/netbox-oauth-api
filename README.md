# netbox-oauth-api

OAuth 2.0 / OIDC JWT (Bearer) authentication for the NetBox REST API.

NetBox supports OIDC only for UI login (via python-social-auth); the REST API
accepts only native `Token <key>` credentials or a session. This plugin adds a
DRF authentication backend that validates JWT access tokens issued by any
OAuth 2.0 / OIDC identity provider (`Authorization: Bearer <JWT>`) directly
against the provider's JWKS and maps the token onto a NetBox user — no
token-exchange service, no admin token to store, no secrets at all (only the
provider's public keys are ever fetched).

Works with any standards-compliant provider: Keycloak, authentik, Okta,
Auth0, Microsoft Entra ID, Zitadel, Dex, …

## Features

- **Signature validation via JWKS** — the JWKS endpoint is discovered from
  `{ISSUER}/.well-known/openid-configuration` (or set explicitly via
  `JWKS_URL`), cached in the Django cache and force-refreshed once when an
  unknown `kid` appears (key rotation works without a NetBox restart, with a
  cooldown against refresh storms).
- **Strict claim checks** — `iss`, `aud`, `exp`/`nbf`/`iat` with configurable
  clock skew; `alg: none` and symmetric (HMAC) algorithms are rejected
  unconditionally.
- **User mapping by stable identity** — users are matched by the immutable
  `sub` claim first (stored in an `OIDCIdentity` record), so renames at the
  identity provider never create duplicate NetBox accounts. Missing users can
  be auto-created with profile fields from the token.
- **Group and flag sync** — provider roles (from a configurable, possibly
  nested claim path) map to NetBox groups. Only managed groups are touched:
  locally assigned groups survive. Optional `is_superuser` / `is_staff`
  control (off by default).
- **Fast hot path** — the sub+roles→user mapping is cached (default 60 s);
  a cache hit performs no writes and no network calls. The roles hash in the
  cache key makes role changes take effect immediately.
- **Chain-friendly** — any non-`Bearer` Authorization scheme is passed to the
  next authentication class, so native NetBox tokens and sessions keep
  working unchanged. NetBox 4.5+ hashed API tokens (`Bearer nbt_…`) are
  recognized and passed through as well.
- **Audit-friendly** — validated claims are exposed as
  `request.oidc_claims`; NetBox change logging attributes changes to the
  mapped user. Failures return an opaque 401 while details go to the
  `netbox_oauth_api` logger. Tokens are never logged.

## Compatibility

| Component         | Version                                              |
|-------------------|------------------------------------------------------|
| NetBox            | 4.0 – 4.6                                            |
| Python            | 3.10+                                                |
| Identity provider | Any OAuth 2.0 / OIDC provider with a JWKS endpoint and asymmetrically signed (e.g. RS256) access tokens |

Every NetBox major release in that range is exercised by the docker-compose
based integration suite on every pull request (see
[Integration tests](#integration-tests-docker-compose)).

## Installation

```bash
pip install netbox-oauth-api
```

Then restart both `netbox` and `netbox-rq`.

## Configuration

```python
PLUGINS = ['netbox_oauth_api']

PLUGINS_CONFIG = {
    'netbox_oauth_api': {
        # required
        'ISSUER': 'https://auth.example.com',   # must equal the token's `iss`
        'AUDIENCE': 'netbox',
        # validation
        'JWKS_URL': '',                         # optional; OIDC discovery when empty
        'ALLOWED_ALGORITHMS': ['RS256'],
        'CLOCK_SKEW_SECONDS': 30,
        'VERIFY_SSL': True,                     # or a path to a CA bundle
        'JWKS_CACHE_TTL': 300,
        'JWKS_REFRESH_COOLDOWN': 30,
        'HTTP_TIMEOUT': 5.0,
        # user mapping
        'USERNAME_CLAIM': 'preferred_username',
        'AUTO_CREATE_USER': True,
        # permissions
        'GROUP_SYNC_ENABLED': True,
        'ROLES_CLAIM_PATH': 'roles',
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
```

The plugin registers its authentication class in front of DRF's default chain
automatically at startup (NetBox builds `REST_FRAMEWORK` internally and does
not read it from `configuration.py`, so a manual override there would be
ignored). Native `Token` and session authentication remain in the chain. Set
`REGISTER_AUTHENTICATION = False` to opt out and wire the class up yourself —
e.g. in a plain Django/DRF project:

```python
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'netbox_oauth_api.authentication.OIDCJWTAuthentication',
        'rest_framework.authentication.SessionAuthentication',
    ],
}
```

`ISSUER` and `AUDIENCE` are mandatory: NetBox refuses to start without them
(a missing `AUDIENCE` would otherwise let any client of the provider access
the API). The configuration is validated at startup, not at the first
request.

### Settings reference

| Setting | Default | Description |
|---|---|---|
| `ISSUER` | — | Issuer URL of the identity provider; compared verbatim against the token's `iss` claim |
| `AUDIENCE` | — | Required `aud` value (your NetBox client/application) |
| `JWKS_URL` | `''` | Explicit JWKS endpoint; when empty it is read from `{ISSUER}/.well-known/openid-configuration` |
| `ALLOWED_ALGORITHMS` | `['RS256']` | Signature algorithms; `none`/HS* are always refused |
| `CLOCK_SKEW_SECONDS` | `30` | Leeway for `exp` / `nbf` / `iat` |
| `VERIFY_SSL` | `True` | TLS verification for provider requests (bool or CA path) |
| `JWKS_CACHE_TTL` | `300` | JWKS (and discovered JWKS URL) cache lifetime, seconds |
| `JWKS_REFRESH_COOLDOWN` | `30` | Min. interval between forced JWKS refreshes |
| `HTTP_TIMEOUT` | `5.0` | Discovery/JWKS request timeout, seconds |
| `USERNAME_CLAIM` | `preferred_username` | Claim used as the NetBox username |
| `AUTO_CREATE_USER` | `True` | Create missing users on first request |
| `GROUP_SYNC_ENABLED` | `True` | Master switch for group/flag sync |
| `ROLES_CLAIM_PATH` | `roles` | Dot-separated path to the role list in the token |
| `AUTO_CREATE_GROUPS` | `True` | Create mapped groups when missing |
| `ROLE_GROUP_MAPPING` | `{}` | Provider role → NetBox group name |
| `SUPERUSER_ROLES` | `[]` | Roles granting `is_superuser` (empty = unmanaged) |
| `STAFF_ROLES` | `[]` | Roles granting `is_staff` (empty = unmanaged; ignored with a warning on NetBox ≥ 4.5, which removed the field together with the Django admin) |
| `USER_CACHE_TTL` | `60` | sub+roles → user cache lifetime, seconds |
| `REGISTER_AUTHENTICATION` | `True` | Auto-insert the auth class into DRF's default chain |

### Provider examples

Only `ISSUER` (and usually `ROLES_CLAIM_PATH`) differ between providers:

| Provider | `ISSUER` | Typical `ROLES_CLAIM_PATH` |
|---|---|---|
| Keycloak | `https://keycloak.example.com/realms/<realm>` | `realm_access.roles` or `resource_access.<client>.roles` |
| authentik | `https://authentik.example.com/application/o/<slug>/` | `roles` (via a custom scope mapping) |
| Microsoft Entra ID | `https://login.microsoftonline.com/<tenant-id>/v2.0` | `roles` (app roles) |
| Okta | `https://<org>.okta.com/oauth2/<auth-server-id>` | `groups` (groups claim) |

`ISSUER` must match the token's `iss` claim character for character —
including a trailing slash if your provider issues one. When in doubt, check
the `issuer` field of `{ISSUER}/.well-known/openid-configuration` or decode
an access token.

## Usage

```bash
curl -H "Authorization: Bearer $(get-access-token)" \
     https://netbox.example.com/api/dcim/devices/
```

Responses are filtered by the mapped user's NetBox permissions, exactly as
with a native token. Native `Authorization: Token <key>` requests are
untouched.

## Security notes

- The plugin stores no secrets — only the provider's public JWKS is fetched.
- Tokens are never written to logs; log records reference `sub` and `jti` only.
- Failed validation always yields an opaque `401` (details at `WARNING` level
  in the `netbox_oauth_api` logger).
- `VERIFY_SSL = False` is for development only and produces a startup warning.
- Granting `is_superuser` from token roles is opt-in and disabled by default.

## Development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e .[dev]
pre-commit install
make lint test
```

The unit suite runs against a minimal Django project (no NetBox instance or
docker required) and covers negative cases: expired/forged tokens, wrong
audience or issuer, `alg: none`, symmetric algorithms, missing `kid`, key
rotation and refresh cooldown.

### Integration tests (docker-compose)

`docker/docker-compose.yml` starts a complete stack — PostgreSQL, Redis, a
Keycloak dev instance as the OIDC identity provider (with a pre-imported
`infra` realm: client, roles and test users) and NetBox with the plugin
installed from the working tree. The e2e suite in `integration_tests/`
obtains real tokens via the password grant and exercises the REST API end to
end, including group-based object permissions and the native-token
fallthrough.

```bash
make integration                       # single version, default v4.6
make integration NETBOX_IMAGE_TAG=v4.1 # any of v4.0 … v4.6
make integration-all                   # the full matrix, sequentially
```

CI runs this suite for every supported NetBox major version on each pull
request and weekly against the moving `v4.x` image tags. See
[CONTRIBUTING.md](CONTRIBUTING.md) for details.

### Releases

Releases are tag-driven: bump the version, update `CHANGELOG.md`, push a
`vX.Y.Z` tag — GitHub Actions validates the tag against the package version,
builds the package, creates a GitHub Release and publishes to PyPI via
trusted publishing. The process is described in
[CONTRIBUTING.md](CONTRIBUTING.md#releasing).

## License

MIT
