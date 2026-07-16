# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Initial release (will become 0.1.0).

### Added

- DRF authentication backend validating Bearer JWTs issued by any OAuth 2.0 /
  OIDC identity provider against the provider's JWKS: signature,
  `iss`/`aud`/`exp`/`nbf`/`iat` checks, key rotation with refresh cooldown,
  `alg: none` and HMAC rejected unconditionally. The JWKS endpoint is
  resolved through OIDC discovery (`{ISSUER}/.well-known/openid-configuration`)
  or set explicitly via `JWKS_URL`.
- User mapping by the immutable `sub` claim (`OIDCIdentity`), optional
  auto-creation, profile sync, rename following.
- Role → group sync for managed groups only, optional
  `is_superuser`/`is_staff` control, sub+roles user cache. `STAFF_ROLES` is
  ignored (with a warning) on NetBox ≥ 4.5, where the user model has no
  `is_staff` field.
- Automatic registration of the authentication class in front of DRF's
  default chain at startup (opt-out via `REGISTER_AUTHENTICATION`).
- Native NetBox v2 API tokens (`Bearer nbt_…`, NetBox 4.5+) are detected
  and passed through to NetBox's own token authentication.
- Support for NetBox 4.0 – 4.6.
- Docker-compose integration environment (NetBox + Keycloak as the test
  identity provider with a pre-imported realm) and an end-to-end test-suite.
- GitHub Actions: lint + unit-test matrix + package build (CI), e2e matrix
  over NetBox v4.0–v4.6 (Integration), tag-driven GitHub Release + PyPI
  publishing (Release).

### Changed

- Renamed the project from `netbox-keycloak-jwt-auth` to `netbox-oauth-api`
  and made it provider-agnostic before the first release: package
  `netbox_keycloak_jwt_auth` → `netbox_oauth_api`, authentication class
  `KeycloakJWTAuthentication` → `OIDCJWTAuthentication`, model
  `KeycloakIdentity` → `OIDCIdentity`, request attribute `keycloak_claims` →
  `oidc_claims`; the `KEYCLOAK_URL` + `REALM` settings were replaced by
  `ISSUER` (+ optional `JWKS_URL`), and the `ROLES_CLAIM_PATH` default
  changed from Keycloak's `realm_access.roles` to `roles`.
