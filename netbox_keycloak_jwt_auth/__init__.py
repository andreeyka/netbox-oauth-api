"""NetBox plugin: Keycloak JWT (Bearer) authentication for the REST API."""

try:
    from netbox.plugins import PluginConfig
except ImportError:  # pragma: no cover — running outside NetBox (test suite)
    from django.apps import AppConfig

    class PluginConfig(AppConfig):  # type: ignore[no-redef]
        """Minimal stand-in so the package can be tested without NetBox."""

from .settings import DEFAULT_SETTINGS, REQUIRED_SETTINGS

__version__ = "0.1.0"


class NetBoxKeycloakJWTAuthConfig(PluginConfig):
    name = "netbox_keycloak_jwt_auth"
    verbose_name = "Keycloak JWT Authentication"
    description = (
        "Authenticate NetBox REST API requests with Keycloak-issued JWT access tokens"
    )
    version = __version__
    author = "andreeyka"
    base_url = "keycloak-jwt-auth"
    min_version = "4.0.0"
    max_version = "4.2.99"
    default_auto_field = "django.db.models.BigAutoField"

    # NetBox refuses to start when any of these is absent from PLUGINS_CONFIG.
    required_settings = list(REQUIRED_SETTINGS)
    default_settings = {
        key: value for key, value in DEFAULT_SETTINGS.items() if key not in REQUIRED_SETTINGS
    }

    def ready(self):
        super().ready()
        from .settings import validate_settings

        validate_settings()


config = NetBoxKeycloakJWTAuthConfig
