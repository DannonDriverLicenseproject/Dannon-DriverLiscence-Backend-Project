from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
from django.core.cache import cache
from django.conf import settings
class UserManager(BaseUserManager):
    """Manager to handle user creation and superuser creation."""
    
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        return self.create_user(email, password, **extra_fields)

class CustomUser(AbstractBaseUser, PermissionsMixin):
    """Custom User model where email is the unique identifier."""
    
    email = models.EmailField(unique=True)
    full_name = models.CharField(max_length=255, blank=True, null=True)
    is_active = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # Avoid conflicts by providing unique related names
    groups = models.ManyToManyField(
        'auth.Group',
        related_name='customuser_set', 
        blank=True
    )
    user_permissions = models.ManyToManyField(
        'auth.Permission',
        related_name='customuser_permissions_set', 
        blank=True
    )

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    def __str__(self):
        return self.email

    @classmethod
    def get_user_by_email(cls, email):
        """Retrieve user from cache or database by email."""
        cache_key = f"user_email_{email}"
        user = cache.get(cache_key)
        if not user:
            user = cls.objects.filter(email=email).first()
            if user:
                cache.set(cache_key, user, timeout=300)
        return user

    @classmethod
    def get_user_by_id(cls, user_id):
        """Retrieve user from cache or database by ID."""
        cache_key = f"user_id_{user_id}"
        user = cache.get(cache_key)
        if not user:
            user = cls.objects.filter(id=user_id).first()
            if user:
                cache.set(cache_key, user, timeout=300)
        return user

    def save(self, *args, **kwargs):
        """Override save method to clear cache when user is updated."""
        super().save(*args, **kwargs)
        cache.delete(f"user_email_{self.email}")
        cache.delete(f"user_id_{self.id}")

    def delete(self, *args, **kwargs):
        """Override delete method to clear cache when user is deleted."""
        cache.delete(f"user_email_{self.email}")
        cache.delete(f"user_id_{self.id}")
        super().delete(*args, **kwargs)

class Profile(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    # phone_number = models.CharField(max_length=15, blank=True, null=True)
    # address = models.TextField(blank=True, null=True)
    date_of_birth = models.DateField(blank=True, null=True)
    gender = models.CharField(max_length=10, blank=True, null=True)
    mother_maiden_name = models.CharField(max_length=100, blank=True, null=True)
    NIN = models.CharField(max_length=20, unique=True, blank=True, null=True)
    passport_photo = models.ImageField(upload_to='passport_photos/', blank=True, null=True)

    def __str__(self):
        return self.user.email
    
    @classmethod
    def get_profile_by_id(cls, profile_id):
        """Retrieve profile from cache or database by profile ID."""
        cache_key = f"profile_id_{profile_id}"
        profile = cache.get(cache_key)
        if not profile:
            profile = cls.objects.filter(id=profile_id).first()
            if profile:
                cache.set(cache_key, profile, timeout=300)
        return profile

    def save(self, *args, **kwargs):
        """Override save method to clear cache when profile is updated."""
        super().save(*args, **kwargs)
        cache.delete(f"profile_user_id_{self.user_id}")
        cache.delete(f"profile_id_{self.id}")

    def delete(self, *args, **kwargs):
        """Override delete method to clear cache when profile is deleted."""
        cache.delete(f"profile_user_id_{self.user_id}")
        cache.delete(f"profile_id_{self.id}")
        super().delete(*args, **kwargs)