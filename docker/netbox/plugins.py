"""Extra NetBox configuration for the integration stack.

Mounted into /etc/netbox/config/, where the netbox-docker configuration
loader picks up every *.py file.
"""

PLUGINS = ["netbox_keycloak_jwt_auth"]

PLUGINS_CONFIG = {
    "netbox_keycloak_jwt_auth": {
        "KEYCLOAK_URL": "http://keycloak:8080",
        "REALM": "infra",
        "AUDIENCE": "netbox",
        "ROLE_GROUP_MAPPING": {
            "netbox-admin": "NetBox Administrators",
            "netbox-write": "NetBox Writers",
            "netbox-read": "NetBox Readers",
        },
        "SUPERUSER_ROLES": ["netbox-admin"],
        "STAFF_ROLES": ["netbox-admin"],
        # Keep the user cache short so permission changes made by the
        # test-suite (e.g. granting an ObjectPermission) apply immediately.
        "USER_CACHE_TTL": 1,
    }
}
