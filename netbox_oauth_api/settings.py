"""Default settings and startup validation for netbox-oauth-api."""

import logging

from django.core.exceptions import ImproperlyConfigured

logger = logging.getLogger("netbox_oauth_api")

PLUGIN_NAME = "netbox_oauth_api"

#: Settings that must be provided in PLUGINS_CONFIG — there are no safe defaults.
REQUIRED_SETTINGS = ("ISSUER", "AUDIENCE")

#: Algorithms that must never be used to verify tokens: ``none`` disables
#: signature verification entirely, and symmetric (HMAC) algorithms would let
#: anyone in possession of the public JWKS forge valid tokens.
FORBIDDEN_ALGORITHMS = frozenset({"none", "hs256", "hs384", "hs512"})

DEFAULT_SETTINGS = {
    # required — validated in validate_settings()
    "ISSUER": "",
    "AUDIENCE": "",
    # token validation
    "JWKS_URL": "",  # empty → resolved through OIDC discovery
    "ALLOWED_ALGORITHMS": ["RS256"],
    "CLOCK_SKEW_SECONDS": 30,
    "VERIFY_SSL": True,
    "JWKS_CACHE_TTL": 300,
    "JWKS_REFRESH_COOLDOWN": 30,
    "HTTP_TIMEOUT": 5.0,
    # user mapping
    "USERNAME_CLAIM": "preferred_username",
    "AUTO_CREATE_USER": True,
    # permission sync
    "GROUP_SYNC_ENABLED": True,
    "ROLES_CLAIM_PATH": "roles",
    "AUTO_CREATE_GROUPS": True,
    "ROLE_GROUP_MAPPING": {},
    "SUPERUSER_ROLES": [],
    "STAFF_ROLES": [],
    # caching
    "USER_CACHE_TTL": 60,
    # integration
    "REGISTER_AUTHENTICATION": True,
}


def get_settings():
    """Return the effective plugin configuration (defaults + PLUGINS_CONFIG).

    Read from ``django.conf.settings`` on every call: no module-level state,
    safe under multiple gunicorn workers and easy to override in tests.
    """
    from django.conf import settings as django_settings

    configured = getattr(django_settings, "PLUGINS_CONFIG", {}).get(PLUGIN_NAME, {})
    return {**DEFAULT_SETTINGS, **configured}


def validate_settings():
    """Validate the plugin configuration at startup.

    Raises ImproperlyConfigured so a bad deployment fails at boot instead of
    surfacing as runtime 401/500s.
    """
    config = get_settings()

    missing = [name for name in REQUIRED_SETTINGS if not config.get(name)]
    if missing:
        raise ImproperlyConfigured(
            f"{PLUGIN_NAME}: required settings are missing or empty: "
            f"{', '.join(missing)}"
        )

    algorithms = config.get("ALLOWED_ALGORITHMS")
    if not algorithms or not isinstance(algorithms, (list, tuple)):
        raise ImproperlyConfigured(
            f"{PLUGIN_NAME}: ALLOWED_ALGORITHMS must be a non-empty list"
        )
    forbidden = [alg for alg in algorithms if str(alg).lower() in FORBIDDEN_ALGORITHMS]
    if forbidden:
        raise ImproperlyConfigured(
            f"{PLUGIN_NAME}: ALLOWED_ALGORITHMS must not include 'none' or symmetric "
            f"algorithms: {', '.join(map(str, forbidden))}"
        )

    if not isinstance(config.get("ROLE_GROUP_MAPPING"), dict):
        raise ImproperlyConfigured(f"{PLUGIN_NAME}: ROLE_GROUP_MAPPING must be a dict")

    if config.get("VERIFY_SSL") is False:
        logger.warning(
            "%s: VERIFY_SSL is disabled — the TLS certificate of the identity "
            "provider will NOT be verified. Never use this in production.",
            PLUGIN_NAME,
        )


def get_issuer(config):
    """Expected ``iss`` claim value — the configured ISSUER, verbatim.

    OIDC requires an exact string match on ``iss``, and some providers
    (e.g. authentik) issue tokens with a trailing slash, so the configured
    value is never normalized.
    """
    return config["ISSUER"]


def build_discovery_url(config):
    """OIDC discovery document URL for the configured issuer."""
    return f"{config['ISSUER'].rstrip('/')}/.well-known/openid-configuration"
