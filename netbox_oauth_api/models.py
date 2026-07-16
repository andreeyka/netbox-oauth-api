from django.conf import settings
from django.db import models


class OIDCIdentity(models.Model):
    """Stable link between a NetBox user and an identity-provider account.

    Users are looked up by the immutable ``sub`` claim first, so renaming an
    account at the identity provider re-uses the existing NetBox user instead
    of creating a duplicate.
    """

    user = models.OneToOneField(
        to=settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="oidc_identity",
    )
    sub = models.CharField(max_length=255, unique=True)
    last_seen = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "OIDC identity"
        verbose_name_plural = "OIDC identities"

    def __str__(self):
        return f"{self.user} ({self.sub})"
