# Generated by Django 5.0.6 on 2024-08-28 20:28

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('userAuth', '0002_profile'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='profile',
            name='address',
        ),
        migrations.RemoveField(
            model_name='profile',
            name='phone_number',
        ),
    ]
