from django.contrib import admin
from .models import User

@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ('email', 'name', 'role', 'is_admin', 'is_superadmin')
    list_filter = ('role',)
    search_fields = ('email', 'name')