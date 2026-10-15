"""
URL configuration for config project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path

from signing import views as signing_views
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import include, path

from signing import views as signing_views

admin.site.site_header = 'InfraHub · Administração'
admin.site.site_title = 'InfraHub'
admin.site.index_title = 'Utilizadores, grupos e certificados'

# O Django admin fica só para superadministradores (emergência); a gestão normal é feita no InfraHub.
admin.site.has_permission = lambda request: request.user.is_active and request.user.is_superuser

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/sign/', signing_views.sign_api, name='api_sign'),  # contrato estável para os pipelines
    path('certhub/', include('signing.urls')),
    path('certhub/inventory/', include('inventory.urls')),
    path('', include('portal.urls')),
]
