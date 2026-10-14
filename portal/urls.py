from django.contrib.auth import views as auth_views
from django.urls import path

from . import certs, manage, views

app_name = "portal"
urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("certificates/", views.certificates, name="certificates"),
    path("certificates/new/", certs.certificate_create, name="certificate_create"),
    path("certificates/<int:pk>/", certs.certificate_edit, name="certificate_edit"),
    path("certificates/<int:pk>/test/", certs.certificate_test, name="certificate_test"),
    path("certificates/<int:pk>/delete/", certs.certificate_delete, name="certificate_delete"),
    path("history/", views.history, name="history"),
    path("tokens/", views.tokens, name="tokens"),
    path("tokens/<int:pk>/revoke/", views.revoke_token, name="revoke_token"),
    path("account/", manage.account, name="account"),
    path("account/password/", manage.PasswordChange.as_view(), name="password"),
    path("manage/users/", manage.users, name="users"),
    path("manage/users/new/", manage.user_create, name="user_create"),
    path("manage/users/<int:pk>/", manage.user_edit, name="user_edit"),
    path("manage/users/<int:pk>/reset-password/", manage.user_reset_password, name="user_reset_password"),
    path("manage/users/<int:pk>/delete/", manage.user_delete, name="user_delete"),
    path("manage/groups/", manage.groups, name="groups"),
    path("manage/groups/new/", manage.group_create, name="group_create"),
    path("manage/groups/<int:pk>/", manage.group_edit, name="group_edit"),
    path("manage/groups/<int:pk>/delete/", manage.group_delete, name="group_delete"),
    path("manage/tokens/", manage.tokens_all, name="tokens_all"),
    path("manage/tokens/<int:pk>/revoke/", manage.token_revoke, name="token_revoke"),
    path("manage/settings/", manage.settings_page, name="settings"),
    path("manage/audit/", manage.audit_log, name="audit"),
    path("login/", auth_views.LoginView.as_view(template_name="registration/login.html", redirect_authenticated_user=True), name="login"),
    path("logout/", auth_views.LogoutView.as_view(), name="logout"),
]
