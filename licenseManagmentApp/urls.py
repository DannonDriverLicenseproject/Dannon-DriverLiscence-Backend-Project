from django.urls import path
from .views import (
    LicenseListCreateView,
    LicenseRetrieveUpdateDestroyView,
    LicenseCheckView
)

urlpatterns = [
    path('licenses/', LicenseListCreateView.as_view(), name='license-list-create'),
    path('licenses/<int:pk>/', LicenseRetrieveUpdateDestroyView.as_view(), name='license-detail'),
    path('licenses/check/', LicenseCheckView.as_view(), name='license-check'),

   ]
