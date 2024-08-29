from django.db import models
from django.conf import settings
from django.utils import timezone
from datetime import timedelta

class License(models.Model):
    """Model to manage the lifecycle of a driver's license."""
    
    VALID = 'valid'
    EXPIRED = 'expired'
    REVOKED = 'revoked'
    SUSPENDED = 'suspended'

    LICENSE_STATUSES = [
        (VALID, 'Valid'),
        (EXPIRED, 'Expired'),
        (REVOKED, 'Revoked'),
        (SUSPENDED, 'Suspended'),
    ]

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    license_number = models.CharField(max_length=20, unique=True)
    issue_date = models.DateField()
    expiration_date = models.DateField()
    status = models.CharField(max_length=10, choices=LICENSE_STATUSES, default=VALID)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.license_number} - {self.get_status_display()}"

    def is_valid(self):
        """Check if the license is currently valid."""
        return self.status == self.VALID and not self.is_expired()

    def is_expired(self):
        """Check if the license is expired."""
        return self.expiration_date < timezone.now().date()

    @classmethod
    def check_expiry(cls, license_number):
        """Class method to determine if a license is expired by its license number."""
        license = cls.objects.filter(license_number=license_number).first()
        if license:
            return license.is_expired()
        return None  # License not found

    @classmethod
    def check_validity(cls, license_number):
        """Class method to confirm if the license is valid based on its status and expiration date."""
        license = cls.objects.filter(license_number=license_number).first()
        if license:
            return license.is_valid()
        return None  # License not found

    @classmethod
    def not_found_handling(cls, license_number):
        """Handle the case where a license number does not exist in the database."""
        if not cls.objects.filter(license_number=license_number).exists():
            return 'License not found'
        return 'License exists'

    def save(self, *args, **kwargs):
        """Override save method to ensure the license status is updated correctly on save."""
        if self.is_expired():
            self.status = self.EXPIRED
        super().save(*args, **kwargs)
