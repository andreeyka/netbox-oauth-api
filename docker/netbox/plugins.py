"""Extra NetBox configuration for the integration stack.

Mounted into /etc/netbox/config/, where the netbox-docker configuration
loader picks up every *.py file. The stack's identity provider is a Keycloak
dev instance (see docker-compose.yml) — any other OIDC provider would be
configured the same way, only ISSUER and ROLES_CLAIM_PATH differ.
"""

PLUGINS = ["netbox_oauth_api"]

PLUGINS_CONFIG = {
    "netbox_oauth_api": {
        "ISSUER": "http://keycloak:8080/realms/infra",
        "AUDIENCE": "netbox",
        # Keycloak publishes realm roles in a nested claim.
        "ROLES_CLAIM_PATH": "realm_access.roles",
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
