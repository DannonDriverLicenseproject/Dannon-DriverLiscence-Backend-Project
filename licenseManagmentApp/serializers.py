from rest_framework import serializers
from .models import License

class LicenseSerializer(serializers.ModelSerializer):
    class Meta:
        model = License
        fields = ['id', 'user', 'license_number', 'issue_date', 'expiration_date', 'status', 'created_at', 'updated_at']
        read_only_fields = ['status', 'created_at', 'updated_at']

class LicenseCheckSerializer(serializers.Serializer):
    """Serializer for checking the validity and expiry of a license."""
    license_number = serializers.CharField(max_length=20)
