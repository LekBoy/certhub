from django.contrib import admin
from portal.models import Teste


class FileTeste(admin.ModelAdmin):
    list_display = ('file','item_name')
    #list_filter = ('entidade','estado')

admin.site.register(Teste, FileTeste)