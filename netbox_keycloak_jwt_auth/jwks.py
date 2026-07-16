"""Fetching, caching and rotation of the Keycloak JWKS (public signing keys)."""

import logging

import httpx
import jwt
from django.core.cache import cache

from .settings import build_jwks_url

logger = logging.getLogger("netbox_keycloak_jwt_auth")

JWKS_CACHE_KEY = "jwtauth:jwks"
JWKS_COOLDOWN_KEY = "jwtauth:jwks:refresh-cooldown"


class JWKSError(Exception):
    """The JWKS endpoint could not be fetched or returned an invalid document."""


def fetch_jwks(config):
    """Download the JWKS document from Keycloak."""
    url = build_jwks_url(config)
    try:
        with httpx.Client(
            verify=config["VERIFY_SSL"], timeout=config["HTTP_TIMEOUT"]
        ) as client:
            response = client.get(url)
            response.raise_for_status()
            document = response.json()
    except httpx.HTTPError as exc:
        raise JWKSError(f"failed to fetch JWKS from {url}: {exc}") from exc
    except ValueError as exc:
        raise JWKSError(f"JWKS endpoint {url} returned invalid JSON") from exc
    if not isinstance(document, dict) or not isinstance(document.get("keys"), list):
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

    An unknown ``kid`` usually means the realm keys were rotated, so the JWKS
    is force-refreshed once — but at most once per JWKS_REFRESH_COOLDOWN
    seconds (``cache.add`` is atomic), so a flood of forged tokens cannot
    hammer the Keycloak endpoint.
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
