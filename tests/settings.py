"""Minimal Django settings for running the plugin test suite without NetBox."""

SECRET_KEY = "test-secret-key"
DEBUG = True

INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.auth",
    "rest_framework",
    "netbox_oauth_api.NetBoxOAuthAPIConfig",
]

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    }
}

CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
    }
}

USE_TZ = True
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
ROOT_URLCONF = "tests.urls"

PLUGINS_CONFIG = {
    "netbox_oauth_api": {
        "ISSUER": "https://idp.test",
        "AUDIENCE": "netbox",
        "ROLE_GROUP_MAPPING": {
            "netbox-admin": "NetBox Administrators",
            "netbox-write": "NetBox Writers",
            "netbox-read": "NetBox Readers",
        },
    }
}
