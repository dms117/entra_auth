"""
entra_auth.urls
~~~~~~~~~~~~~~~
Include in your root URLconf:

    from django.urls import include, path

    urlpatterns = [
        ...
        path("entra/", include("entra_auth.urls")),
    ]

This exposes:
  /entra/login/     — start login
  /entra/callback/  — OAuth2 redirect handler
  /entra/logout/    — sign out
"""

from django.urls import path

from . import views

app_name = "entra_auth"

urlpatterns = [
    path("login/", views.EntraLoginView.as_view(), name="login"),
    path("callback/", views.EntraCallbackView.as_view(), name="callback"),
    path("logout/", views.EntraLogoutView.as_view(), name="logout"),
]
