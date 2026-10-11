"""The URLs of the project: ``/whoami`` and one path per probe operation."""

from __future__ import annotations

from django.urls import path
from djapp import views

urlpatterns = [
    path("whoami", views.whoami),
    path("<str:op>", views.probe),
]
