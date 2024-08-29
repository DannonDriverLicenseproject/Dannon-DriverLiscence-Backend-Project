from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import CustomUser, Profile

@admin.register(CustomUser)
class CustomUserAdmin(UserAdmin):
    """Admin view for CustomUser model with additional features."""
    
    model = CustomUser
    list_display = ('email', 'full_name', 'is_staff', 'is_active', 'created_at')
    list_filter = ('is_staff', 'is_active', 'created_at')
    search_fields = ('email', 'full_name')
    ordering = ('email',)
    
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('Personal info', {'fields': ('full_name',)}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
        ('Important dates', {'fields': ('last_login', 'created_at', 'updated_at')}),
    )
    
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'password1', 'password2', 'is_active', 'is_staff', 'is_superuser')}
        ),
    )
    
    readonly_fields = ('created_at', 'updated_at')
    filter_horizontal = ('groups', 'user_permissions')

@admin.register(Profile)
class ProfileAdmin(admin.ModelAdmin):
    """Admin view for Profile model with additional features."""
    
    list_display = ('user', 'date_of_birth', 'gender', 'NIN')
    list_filter = ('gender', 'date_of_birth')
    search_fields = ('user__email', 'user__full_name', 'NIN')
    ordering = ('user__email',)
