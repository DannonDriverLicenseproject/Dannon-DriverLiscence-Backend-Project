# Generated by Django 5.0.6 on 2024-08-28 13:51

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='LicenseApplication',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('application_type', models.CharField(choices=[('new', 'New License'), ('renewal', 'License Renewal'), ('reissue', 'License Reissue')], max_length=10)),
                ('status', models.CharField(choices=[('pending', 'Pending'), ('approved', 'Approved'), ('rejected', 'Rejected')], default='pending', max_length=10)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='NewLicenseApplication',
            fields=[
                ('licenseapplication_ptr', models.OneToOneField(auto_created=True, on_delete=django.db.models.deletion.CASCADE, parent_link=True, primary_key=True, serialize=False, to='licenseApplication.licenseapplication')),
                ('first_name', models.CharField(max_length=50)),
                ('last_name', models.CharField(max_length=50)),
                ('middle_name', models.CharField(blank=True, max_length=50, null=True)),
                ('gender', models.CharField(choices=[('male', 'Male'), ('female', 'Female')], max_length=10)),
                ('date_of_birth', models.DateField()),
                ('mother_maiden_name', models.CharField(max_length=100)),
                ('NIN', models.CharField(max_length=20, unique=True)),
                ('passport_photo', models.ImageField(upload_to='passport_photos/')),
            ],
            options={
                'verbose_name': 'New License Application',
                'verbose_name_plural': 'New License Applications',
            },
            bases=('licenseApplication.licenseapplication',),
        ),
        migrations.CreateModel(
            name='ReissueLicenseApplication',
            fields=[
                ('licenseapplication_ptr', models.OneToOneField(auto_created=True, on_delete=django.db.models.deletion.CASCADE, parent_link=True, primary_key=True, serialize=False, to='licenseApplication.licenseapplication')),
                ('email', models.EmailField(max_length=254)),
                ('license_id', models.CharField(max_length=20)),
                ('affidavit', models.FileField(upload_to='affidavits/')),
                ('police_report', models.FileField(upload_to='police_reports/')),
            ],
            options={
                'verbose_name': 'License Reissue Application',
                'verbose_name_plural': 'License Reissue Applications',
            },
            bases=('licenseApplication.licenseapplication',),
        ),
        migrations.CreateModel(
            name='RenewalLicenseApplication',
            fields=[
                ('licenseapplication_ptr', models.OneToOneField(auto_created=True, on_delete=django.db.models.deletion.CASCADE, parent_link=True, primary_key=True, serialize=False, to='licenseApplication.licenseapplication')),
                ('email', models.EmailField(max_length=254)),
                ('license_id', models.CharField(max_length=20)),
            ],
            options={
                'verbose_name': 'License Renewal Application',
                'verbose_name_plural': 'License Renewal Applications',
            },
            bases=('licenseApplication.licenseapplication',),
        ),
        migrations.CreateModel(
            name='ApplicationAudit',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('old_status', models.CharField(choices=[('pending', 'Pending'), ('approved', 'Approved'), ('rejected', 'Rejected')], max_length=10)),
                ('new_status', models.CharField(choices=[('pending', 'Pending'), ('approved', 'Approved'), ('rejected', 'Rejected')], max_length=10)),
                ('timestamp', models.DateTimeField(auto_now_add=True)),
                ('notes', models.TextField(blank=True, null=True)),
                ('changed_by', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
                ('application', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='audits', to='licenseApplication.licenseapplication')),
            ],
        ),
    ]
