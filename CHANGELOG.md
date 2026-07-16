# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Initial release (will become 0.1.0).

### Added

- DRF authentication backend validating Keycloak-issued Bearer JWTs against
  the realm JWKS: signature, `iss`/`aud`/`exp`/`nbf`/`iat` checks, key
  rotation with refresh cooldown, `alg: none` and HMAC rejected
  unconditionally.
- User mapping by the immutable `sub` claim (`KeycloakIdentity`), optional
  auto-creation, profile sync, rename following.
- Role → group sync for managed groups only, optional
  `is_superuser`/`is_staff` control, sub+roles user cache. `STAFF_ROLES` is
  ignored (with a warning) on NetBox ≥ 4.5, where the user model has no
  `is_staff` field.
- Automatic registration of the authentication class in front of DRF's
  default chain at startup (opt-out via `REGISTER_AUTHENTICATION`).
- Support for NetBox 4.0 – 4.6.
- Docker-compose integration environment (NetBox + Keycloak with a
  pre-imported test realm) and an end-to-end test-suite.
- GitHub Actions: lint + unit-test matrix + package build (CI), e2e matrix
  over NetBox v4.0–v4.6 (Integration), tag-driven GitHub Release + PyPI
  publishing (Release).
