from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import CustomUser, Profile
from licenseApplication.models import NewLicenseApplication  

@receiver(post_save, sender=CustomUser)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        Profile.objects.create(user=instance)

@receiver(post_save, sender=CustomUser)
def save_user_profile(sender, instance, **kwargs):
    instance.profile.save()


@receiver(post_save, sender=NewLicenseApplication)
def update_profile_from_application(sender, instance, created, **kwargs):
    if created:
        profile, _ = Profile.objects.get_or_create(user=instance.user)
        profile.full_name = f"{instance.first_name} {instance.last_name}"
        profile.date_of_birth = instance.date_of_birth
        profile.gender = instance.gender
        profile.mother_maiden_name = instance.mother_maiden_name
        profile.NIN = instance.NIN
        profile.passport_photo = instance.passport_photo
        profile.save()