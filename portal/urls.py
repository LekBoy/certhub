from django.contrib.auth import views as auth_views
from django.urls import path

from . import views

app_name = "portal"
urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("certificates/", views.certificates, name="certificates"),
    path("history/", views.history, name="history"),
    path("tokens/", views.tokens, name="tokens"),
    path("tokens/<int:pk>/revoke/", views.revoke_token, name="revoke_token"),
    path("login/", auth_views.LoginView.as_view(template_name="registration/login.html", redirect_authenticated_user=True), name="login"),
    path("logout/", auth_views.LogoutView.as_view(), name="logout"),
]
