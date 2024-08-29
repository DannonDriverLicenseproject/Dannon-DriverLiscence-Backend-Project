from django.contrib import admin
from .models import LicenseApplication, NewLicenseApplication, RenewalLicenseApplication, ReissueLicenseApplication, ApplicationAudit

@admin.register(LicenseApplication)
class LicenseApplicationAdmin(admin.ModelAdmin):
    """Admin view for LicenseApplication model."""
    
    list_display = ('user', 'application_type', 'status', 'created_at', 'updated_at')
    list_filter = ('application_type', 'status', 'created_at')
    search_fields = ('user__email', 'user__full_name')
    ordering = ('-created_at',)

@admin.register(NewLicenseApplication)
class NewLicenseApplicationAdmin(admin.ModelAdmin):
    """Admin view for NewLicenseApplication model."""
    
    list_display = ('user', 'first_name', 'last_name', 'date_of_birth', 'NIN', 'status', 'created_at')
    list_filter = ('status', 'gender', 'created_at')
    search_fields = ('user__email', 'first_name', 'last_name', 'NIN')
    ordering = ('-created_at',)

@admin.register(RenewalLicenseApplication)
class RenewalLicenseApplicationAdmin(admin.ModelAdmin):
    """Admin view for RenewalLicenseApplication model."""
    
    list_display = ('user', 'email', 'license_id', 'status', 'created_at')
    list_filter = ('status', 'created_at')
    search_fields = ('user__email', 'email', 'license_id')
    ordering = ('-created_at',)

@admin.register(ReissueLicenseApplication)
class ReissueLicenseApplicationAdmin(admin.ModelAdmin):
    """Admin view for ReissueLicenseApplication model."""
    
    list_display = ('user', 'email', 'license_id', 'status', 'created_at')
    list_filter = ('status', 'created_at')
    search_fields = ('user__email', 'email', 'license_id')
    ordering = ('-created_at',)

@admin.register(ApplicationAudit)
class ApplicationAuditAdmin(admin.ModelAdmin):
    """Admin view for ApplicationAudit model."""
    
    list_display = ('application', 'old_status', 'new_status', 'changed_by', 'timestamp')
    list_filter = ('old_status', 'new_status', 'timestamp')
    search_fields = ('application__user__email', 'changed_by__email')
    ordering = ('-timestamp',)
