"""DRF authentication backend validating Keycloak-issued JWT access tokens."""

import logging

import jwt
from rest_framework.authentication import BaseAuthentication, get_authorization_header
from rest_framework.exceptions import AuthenticationFailed

from .jwks import JWKSError, get_signing_key
from .mapping import MappingError, resolve_user
from .settings import FORBIDDEN_ALGORITHMS, build_issuer, get_settings

logger = logging.getLogger("netbox_keycloak_jwt_auth")

#: Generic client-facing error; details go to the log only, never the response.
GENERIC_ERROR = "Invalid or expired token."


class KeycloakJWTAuthentication(BaseAuthentication):
    """Authenticate ``Authorization: Bearer <JWT>`` against the Keycloak JWKS.

    Any other Authorization scheme (e.g. NetBox's native ``Token``) is passed
    through to the next authentication class in the chain by returning None.
    """

    keyword = "Bearer"

    def authenticate(self, request):
        header = get_authorization_header(request)
        if not header:
            return None
        parts = header.split()
        if parts[0].lower() != self.keyword.lower().encode():
            # Different scheme — let the next backend handle it.
            return None
        if len(parts) != 2:
            logger.warning("malformed Bearer authorization header")
            raise AuthenticationFailed(GENERIC_ERROR)

        try:
            token = parts[1].decode()
        except UnicodeDecodeError as exc:
            logger.warning("Bearer token contains invalid characters")
            raise AuthenticationFailed(GENERIC_ERROR) from exc

        config = get_settings()
        claims = self._validate_token(token, config)

        try:
            user = resolve_user(claims, config)
        except MappingError as exc:
            logger.warning(
                "user mapping failed (sub=%s, jti=%s): %s",
                claims.get("sub"),
                claims.get("jti"),
                exc,
            )
            raise AuthenticationFailed(GENERIC_ERROR) from exc

        # Expose the validated claims for change logging and middleware.
        request.keycloak_claims = claims
        http_request = getattr(request, "_request", None)
        if http_request is not None:
            http_request.keycloak_claims = claims

        return (user, None)

    def authenticate_header(self, request):
        return 'Bearer realm="netbox"'

    def _validate_token(self, token, config):
        # Filter forbidden algorithms even if they slipped into the config:
        # 'none' and HMAC verification must be impossible, not just discouraged.
        algorithms = [
            alg
            for alg in config["ALLOWED_ALGORITHMS"]
            if str(alg).lower() not in FORBIDDEN_ALGORITHMS
        ]

        try:
            header = jwt.get_unverified_header(token)
        except jwt.InvalidTokenError as exc:
            logger.warning("cannot parse JWT header: %s", exc)
            raise AuthenticationFailed(GENERIC_ERROR) from exc

        if header.get("alg") not in algorithms:
            logger.warning("JWT uses disallowed algorithm %r", header.get("alg"))
            raise AuthenticationFailed(GENERIC_ERROR)

        kid = header.get("kid")
        if not kid:
            logger.warning("JWT header has no kid")
            raise AuthenticationFailed(GENERIC_ERROR)

        try:
            key = get_signing_key(kid, config)
        except JWKSError as exc:
            logger.warning("JWKS unavailable: %s", exc)
            raise AuthenticationFailed(GENERIC_ERROR) from exc
        if key is None:
            logger.warning("JWT signed with unknown kid %r", kid)
            raise AuthenticationFailed(GENERIC_ERROR)

        try:
            claims = jwt.decode(
                token,
                key=key,
                algorithms=algorithms,
                audience=config["AUDIENCE"],
                issuer=build_issuer(config),
                leeway=config["CLOCK_SKEW_SECONDS"],
                options={"require": ["exp", "iat", "sub"]},
            )
        except jwt.InvalidTokenError as exc:
            # The exception text never contains the token itself.
            logger.warning("JWT validation failed: %s", exc)
            raise AuthenticationFailed(GENERIC_ERROR) from exc

        return claims
