"""NetBox plugin: Keycloak JWT (Bearer) authentication for the REST API."""

import sys

try:
    from netbox.plugins import PluginConfig
except ImportError:  # pragma: no cover — running outside NetBox (test suite)
    from django.apps import AppConfig

    class PluginConfig(AppConfig):  # type: ignore[no-redef]
        """Minimal stand-in so the package can be tested without NetBox."""


from .settings import DEFAULT_SETTINGS, REQUIRED_SETTINGS

__version__ = "0.1.0"

#: Dotted path of the DRF authentication class provided by this plugin.
AUTHENTICATION_CLASS = (
    "netbox_keycloak_jwt_auth.authentication.KeycloakJWTAuthentication"
)


def register_authentication_class():
    """Prepend the plugin's authentication class to DRF's default chain.

    NetBox builds ``REST_FRAMEWORK`` inside its own ``settings.py`` and does
    not read it back from ``configuration.py``, so the only reliable way to
    hook into the API authentication chain is to amend the setting at app
    startup. Native ``Token`` and session authentication stay in the chain.

    Returns True when the class was inserted, False when it was already
    present or registration is disabled via ``REGISTER_AUTHENTICATION``.
    """
    from django.conf import settings as django_settings

    from .settings import get_settings

    if not get_settings().get("REGISTER_AUTHENTICATION", True):
        return False

    rest_framework = getattr(django_settings, "REST_FRAMEWORK", None)
    if rest_framework is None:
        rest_framework = {}
        django_settings.REST_FRAMEWORK = rest_framework

    if "DEFAULT_AUTHENTICATION_CLASSES" in rest_framework:
        current = list(rest_framework["DEFAULT_AUTHENTICATION_CLASSES"])
    else:
        # Fall back to DRF's implicit defaults so they are not silently dropped.
        from rest_framework.settings import DEFAULTS

        current = list(DEFAULTS["DEFAULT_AUTHENTICATION_CLASSES"])

    if AUTHENTICATION_CLASS in current:
        return False

    rest_framework["DEFAULT_AUTHENTICATION_CLASSES"] = [AUTHENTICATION_CLASS, *current]

    # Drop DRF's settings cache in case something already read it.
    from rest_framework.settings import api_settings

    api_settings.reload()

    # NetBox imports rest_framework.views while its own apps load — long
    # before any plugin's ready() runs — so APIView has already captured the
    # old default chain as a class attribute. Point it at the live setting;
    # views that set authentication_classes explicitly are unaffected.
    views = sys.modules.get("rest_framework.views")
    if views is not None:
        classes = api_settings.DEFAULT_AUTHENTICATION_CLASSES
        views.APIView.authentication_classes = classes
    return True


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
    max_version = "4.4.99"
    default_auto_field = "django.db.models.BigAutoField"

    # NetBox refuses to start when any of these is absent from PLUGINS_CONFIG.
    required_settings = list(REQUIRED_SETTINGS)
    default_settings = {
        key: value
        for key, value in DEFAULT_SETTINGS.items()
        if key not in REQUIRED_SETTINGS
    }

    def ready(self):
        super().ready()
        from .settings import validate_settings

        validate_settings()
        register_authentication_class()


config = NetBoxKeycloakJWTAuthConfig
