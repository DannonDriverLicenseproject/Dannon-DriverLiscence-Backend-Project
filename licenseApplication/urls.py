from django.urls import path
from .views import (
    NewLicenseApplicationListCreateView,
    RenewalLicenseApplicationListCreateView,
    ReissueLicenseApplicationListCreateView,
    LicenseApplicationDetailView,
    ApplicationAuditListView, ApplicationSlipView
)

urlpatterns = [
    path('applications/new/', NewLicenseApplicationListCreateView.as_view(), name='new-license-application-list-create'),
    path('applications/renewal/', RenewalLicenseApplicationListCreateView.as_view(), name='renewal-license-application-list-create'),
    path('applications/reissue/', ReissueLicenseApplicationListCreateView.as_view(), name='reissue-license-application-list-create'),
   path('applications/<str:application_type>/<int:pk>/', LicenseApplicationDetailView.as_view(), name='license-application-detail'),    
   path('applications/<int:application_id>/audits/', ApplicationAuditListView.as_view(), name='application-audit-list'),
    path('application-slip/<str:application_type>/<int:application_id>/', ApplicationSlipView.as_view(), name='application_slip'),

]

