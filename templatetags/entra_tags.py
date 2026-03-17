"""
entra_auth.templatetags.entra_tags
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Template tags and filters for Entra ID auth.

Load in templates:

    {% load entra_tags %}

    {% entra_login_url %}               → /entra/login/
    {% entra_logout_url %}              → /entra/logout/
    {% if request.user|is_in_group:"finance" %} ... {% endif %}
"""

from django import template
from django.urls import reverse

register = template.Library()


@register.simple_tag
def entra_login_url(next_url: str = "") -> str:
    """Return the Entra login URL, with optional ?next= parameter."""
    url = reverse("entra_auth:login")
    if next_url:
        url = f"{url}?next={next_url}"
    return url


@register.simple_tag
def entra_logout_url() -> str:
    """Return the Entra logout URL."""
    return reverse("entra_auth:logout")


@register.filter(name="is_in_group")
def is_in_group(user, group_name: str) -> bool:
    """
    Return True if the user belongs to the named Django group.

        {% if request.user|is_in_group:"finance" %}
    """
    if not user or not user.is_authenticated:
        return False
    return user.groups.filter(name=group_name).exists()
