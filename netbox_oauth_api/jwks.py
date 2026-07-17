"""Fetching, caching and rotation of the provider's JWKS (public signing keys)."""

import logging

import httpx
import jwt
from django.core.cache import cache

from .settings import build_discovery_url

logger = logging.getLogger("netbox_oauth_api")

JWKS_CACHE_KEY = "jwtauth:jwks"
JWKS_COOLDOWN_KEY = "jwtauth:jwks:refresh-cooldown"
JWKS_URL_CACHE_KEY = "jwtauth:jwks-url"


class JWKSError(Exception):
    """The JWKS or discovery endpoint could not be fetched or returned garbage."""


def _fetch_json(url, config):
    try:
        with httpx.Client(
            verify=config["VERIFY_SSL"], timeout=config["HTTP_TIMEOUT"]
        ) as client:
            response = client.get(url)
            response.raise_for_status()
            document = response.json()
    except httpx.HTTPError as exc:
        raise JWKSError(f"failed to fetch {url}: {exc}") from exc
    except ValueError as exc:
        raise JWKSError(f"{url} returned invalid JSON") from exc
    if not isinstance(document, dict):
        raise JWKSError(f"{url} returned an unexpected document")
    return document


def get_jwks_url(config):
    """Return the JWKS endpoint URL for the configured provider.

    An explicitly configured JWKS_URL wins; otherwise the URL is read from
    the provider's OIDC discovery document (``jwks_uri``) and cached for
    JWKS_CACHE_TTL seconds.
    """
    if config["JWKS_URL"]:
        return config["JWKS_URL"]
    cached = cache.get(JWKS_URL_CACHE_KEY)
    if cached is not None:
        return cached
    discovery_url = build_discovery_url(config)
    document = _fetch_json(discovery_url, config)
    jwks_url = document.get("jwks_uri")
    if not isinstance(jwks_url, str) or not jwks_url:
        raise JWKSError(f"discovery document at {discovery_url} has no jwks_uri")
    cache.set(JWKS_URL_CACHE_KEY, jwks_url, config["JWKS_CACHE_TTL"])
    return jwks_url


def fetch_jwks(config):
    """Download the JWKS document from the provider."""
    url = get_jwks_url(config)
    document = _fetch_json(url, config)
    if not isinstance(document.get("keys"), list):
        raise JWKSError(f"JWKS endpoint {url} returned an unexpected document")
    return document


def get_jwks(config, force_refresh=False):
    """Return the JWKS document, using the Django cache (TTL JWKS_CACHE_TTL)."""
    if not force_refresh:
        document = cache.get(JWKS_CACHE_KEY)
        if document is not None:
            return document
    document = fetch_jwks(config)
    cache.set(JWKS_CACHE_KEY, document, config["JWKS_CACHE_TTL"])
    return document


def _find_key(document, kid):
    for jwk_data in document.get("keys", []):
        if jwk_data.get("kid") == kid and jwk_data.get("use", "sig") == "sig":
            return jwk_data
    return None


def get_signing_key(kid, config):
    """Return the public key for *kid*, or None when it is unknown.

    An unknown ``kid`` usually means the provider's keys were rotated, so the
    JWKS is force-refreshed once — but at most once per JWKS_REFRESH_COOLDOWN
    seconds (``cache.add`` is atomic), so a flood of forged tokens cannot
    hammer the provider's endpoint.
    """
    document = get_jwks(config)
    jwk_data = _find_key(document, kid)
    if jwk_data is None and cache.add(
        JWKS_COOLDOWN_KEY, True, config["JWKS_REFRESH_COOLDOWN"]
    ):
        logger.info("kid %r not found in cached JWKS, forcing a refresh", kid)
        document = get_jwks(config, force_refresh=True)
        jwk_data = _find_key(document, kid)
    if jwk_data is None:
        return None
    try:
        return jwt.PyJWK.from_dict(jwk_data).key
    except (jwt.exceptions.PyJWKError, jwt.exceptions.InvalidKeyError) as exc:
        logger.warning("cannot load JWK kid=%r: %s", kid, exc)
        return None
