# Contributing

## Development setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e .[dev]
pre-commit install
```

Day-to-day commands (see `make help`):

```bash
make lint     # ruff check + format check
make format   # autofix
make test     # unit tests — no docker or NetBox required
make build    # sdist + wheel + twine check
```

## Tests

**Unit tests** (`tests/`) run against a minimal Django project with a fake
JWKS endpoint — they cover token validation, user/group mapping and
configuration handling and are the fast, default feedback loop.

**Integration tests** (`integration_tests/`) run against a real NetBox with
the plugin installed and a real Keycloak issuing tokens. The stack lives in
`docker/docker-compose.yml`:

| Service  | Image                                  | Host port |
|----------|----------------------------------------|-----------|
| NetBox   | `netboxcommunity/netbox:$NETBOX_IMAGE_TAG` + plugin | 8000 |
| Keycloak | `quay.io/keycloak/keycloak` (dev mode, realm `infra` pre-imported) | 8081 |
| PostgreSQL / Redis | `postgres:16-alpine` / `redis:7-alpine` | — |

The `infra` realm ships a public client `netbox` (direct access grants +
audience mapper), realm roles `netbox-admin`/`netbox-write`/`netbox-read`
and users `alice` (admin), `bob` (read), `carol` (no roles); passwords are
`<username>-password`. A NetBox superuser `admin` with a fixed API token is
created for test bookkeeping.

```bash
make integration                       # one version (default v4.6)
make integration NETBOX_IMAGE_TAG=v4.1 # any of v4.0 … v4.6
make integration-all                   # the whole matrix, sequentially
```

Or manually: `make compose-up`, `make e2e` (repeatable), `make compose-down`.
Endpoints and credentials can be overridden with `E2E_*` environment
variables (see `integration_tests/conftest.py`).

> **Troubleshooting:** if the netbox container exits right after
> `Applying configuration from /etc/unit/nginx-unit.json` with
> `socket("[::]:8080") failed (97: Address family not supported)`, your
> docker host has IPv6 disabled at the kernel level. Mount a copy of
> `/etc/unit/nginx-unit.json` with the `[::]` listeners removed over the
> original (a compose override file is enough); GitHub-hosted runners are
> unaffected.

CI runs the unit matrix on every push/PR and the full NetBox version matrix
(`v4.0`–`v4.6`, in parallel) on every PR plus a weekly schedule, so new
NetBox patch releases are caught automatically.

## Releasing

Releases are tag-driven (`.github/workflows/release.yml`):

1. Update the version in **both** `pyproject.toml` and
   `netbox_keycloak_jwt_auth/__init__.py` (`__version__`).
2. Rename the `[Unreleased]` section of `CHANGELOG.md` to the new version
   and date; start a fresh `[Unreleased]` section.
3. Commit, then tag and push:

   ```bash
   git tag v0.2.0
   git push origin v0.2.0
   ```

The workflow refuses tags that do not match the package version, runs the
unit suite, builds sdist+wheel, creates a GitHub Release with generated
notes and the artifacts attached, and publishes to PyPI.

### One-time PyPI setup (trusted publishing)

PyPI publishing uses OIDC — no API token is stored in the repository:

1. On PyPI, add a *trusted publisher* for the `netbox-keycloak-jwt-auth`
   project: owner `andreeyka`, repository `netbox-oauth-api`, workflow
   `release.yml`, environment `pypi`.
2. In the GitHub repository settings, create an environment named `pypi`
   (optionally with required reviewers to gate releases).
