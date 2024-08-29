from rest_framework import serializers
from .models import NewLicenseApplication, RenewalLicenseApplication, ReissueLicenseApplication, ApplicationAudit

class NewLicenseApplicationSerializer(serializers.ModelSerializer):
    class Meta:
        model = NewLicenseApplication
        fields = ['id', 'user', 'application_type', 'status', 'first_name', 'last_name', 'middle_name',
                  'gender', 'date_of_birth', 'mother_maiden_name', 'NIN', 'passport_photo', 
                  'created_at', 'updated_at']
        read_only_fields = ['user', 'application_type', 'status', 'created_at', 'updated_at']

class RenewalLicenseApplicationSerializer(serializers.ModelSerializer):
    class Meta:
        model = RenewalLicenseApplication
        fields = ['id', 'user', 'application_type', 'status', 'email', 'license_id',
                  'created_at', 'updated_at']
        read_only_fields = ['user', 'application_type', 'status', 'created_at', 'updated_at']

class ReissueLicenseApplicationSerializer(serializers.ModelSerializer):
    class Meta:
        model = ReissueLicenseApplication
        fields = ['id', 'user', 'application_type', 'status', 'email', 'license_id',
                  'affidavit', 'police_report', 'created_at', 'updated_at']
        read_only_fields = ['user', 'application_type', 'status', 'created_at', 'updated_at']

class ApplicationAuditSerializer(serializers.ModelSerializer):
    class Meta:
        model = ApplicationAudit
        fields = ['id', 'application', 'old_status', 'new_status', 'changed_by', 'timestamp', 'notes']
        read_only_fields = ['application', 'old_status', 'new_status', 'changed_by', 'timestamp']
