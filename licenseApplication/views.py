import logging
import requests

from django.shortcuts import render, get_object_or_404
from django.http import HttpResponse, Http404
from django.contrib.auth.mixins import LoginRequiredMixin
from django.views import View

from rest_framework import generics, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.response import Response

from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

from paymentApp.models import Payment
from .models import NewLicenseApplication, RenewalLicenseApplication, ReissueLicenseApplication, ApplicationAudit
from .serializers import (
    NewLicenseApplicationSerializer,
    RenewalLicenseApplicationSerializer,
    ReissueLicenseApplicationSerializer,
    ApplicationAuditSerializer,
)
from .payment import verify_payment

# Set up logging
logger = logging.getLogger(__name__)

# Helper function to format error responses with status code
def format_error_response(status_code, error_code, message, details=None):
    return {
        "status": "error",
        "status_code": status_code,
        "error": {
            "code": error_code,
            "message": message,
            "details": details or {}
        }
    }

# Helper function to handle payments
def handle_payment(request, application):
    payment_reference = request.data.get('reference')
    payment_amount = request.data.get('amount')
    transaction_id = request.data.get('transaction_id')

    if not payment_reference or not payment_amount:
        return Response(
            format_error_response(
                status_code=status.HTTP_400_BAD_REQUEST,
                error_code="PAYMENT_ERROR",
                message="Payment details are required."
            ),
            status=status.HTTP_400_BAD_REQUEST
        )

    try:
        verification_response = verify_payment(payment_reference)
        if verification_response['data']['status'] != 'success':
            return Response(
                format_error_response(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    error_code="PAYMENT_VERIFICATION_FAILED",
                    message="Payment verification failed."
                ),
                status=status.HTTP_400_BAD_REQUEST
            )
    except requests.exceptions.RequestException as e:
        return Response(
            format_error_response(
                status_code=status.HTTP_502_BAD_GATEWAY,
                error_code="PAYMENT_VERIFICATION_ERROR",
                message="There was an error verifying the payment.",
                details=str(e)
            ),
            status=status.HTTP_502_BAD_GATEWAY
        )

    Payment.objects.create(
        user=request.user,
        application=application,
        transaction_id=transaction_id,
        reference=payment_reference,
        amount=payment_amount,
        status='COMPLETED'
    )

    return None

# Base class for handling license applications
class BaseLicenseApplicationView(generics.ListCreateAPIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    @swagger_auto_schema(
        operation_description="Create a new license application with payment.",
        responses={
            201: openapi.Response("Application created successfully."),
            400: openapi.Response("Validation error or payment verification failed."),
            500: openapi.Response("Server error during application creation.")
        }
    )
    def create_application(self, request, *args, **kwargs):
        try:
            serializer = self.get_serializer(data=request.data)
            if not serializer.is_valid():
                logger.warning(f"Invalid data submitted for {self.__class__.__name__}.")
                return Response(
                    format_error_response(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        error_code="VALIDATION_ERROR",
                        message="Invalid or incomplete data provided.",
                        details=serializer.errors
                    ),
                    status=status.HTTP_400_BAD_REQUEST
                )

            application = serializer.save(user=request.user, application_type=self.application_type)

            payment_response = handle_payment(request, application)
            if payment_response:
                return payment_response

            headers = self.get_success_headers(serializer.data)
            return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)

        except Exception as e:
            logger.error(f"Error in {self.__class__.__name__}: {str(e)}", exc_info=True)
            return Response(
                format_error_response(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    error_code="APPLICATION_CREATION_ERROR",
                    message="An error occurred during the creation of the application.",
                    details={"exception": str(e)}
                ),
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def create(self, request, *args, **kwargs):
        return self.create_application(request, *args, **kwargs)

# Views for different license applications
class NewLicenseApplicationListCreateView(BaseLicenseApplicationView):
    queryset = NewLicenseApplication.objects.all()
    serializer_class = NewLicenseApplicationSerializer
    application_type = NewLicenseApplication.NEW

    @swagger_auto_schema(
        operation_description="List or create new license applications.",
        responses={
            200: openapi.Response("List of new license applications."),
            201: openapi.Response("New license application created successfully."),
            400: openapi.Response("Validation error or payment verification failed.")
        }
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

class RenewalLicenseApplicationListCreateView(BaseLicenseApplicationView):
    queryset = RenewalLicenseApplication.objects.all()
    serializer_class = RenewalLicenseApplicationSerializer
    application_type = RenewalLicenseApplication.RENEWAL

    @swagger_auto_schema(
        operation_description="List or create renewal license applications.",
        responses={
            200: openapi.Response("List of renewal license applications."),
            201: openapi.Response("Renewal license application created successfully."),
            400: openapi.Response("Validation error or payment verification failed.")
        }
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

class ReissueLicenseApplicationListCreateView(BaseLicenseApplicationView):
    queryset = ReissueLicenseApplication.objects.all()
    serializer_class = ReissueLicenseApplicationSerializer
    application_type = ReissueLicenseApplication.REISSUE

    @swagger_auto_schema(
        operation_description="List or create reissue license applications.",
        responses={
            200: openapi.Response("List of reissue license applications."),
            201: openapi.Response("Reissue license application created successfully."),
            400: openapi.Response("Validation error or payment verification failed.")
        }
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

# View to handle license application detail retrieval
class LicenseApplicationDetailView(generics.RetrieveAPIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Retrieve a specific license application.",
        responses={
            200: openapi.Response("License application retrieved successfully."),
            400: openapi.Response("Invalid application type provided."),
            404: openapi.Response("Application not found."),
            500: openapi.Response("Server error during retrieval.")
        }
    )
    def get(self, request, *args, **kwargs):
        try:
            queryset = self.get_queryset()
            if queryset is None:
                raise ValueError("Invalid application type")
            application = get_object_or_404(queryset, pk=self.kwargs.get('pk'))
            serializer = self.get_serializer(application)
            logger.info(f"License application retrieved: {application.id} for user {request.user.email}")
            return Response(serializer.data, status=status.HTTP_200_OK)
        except ValueError as ve:
            logger.error(f"Invalid application type: {str(ve)}", exc_info=True)
            return Response(
                format_error_response(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    error_code="INVALID_APPLICATION_TYPE",
                    message="Invalid application type provided.",
                    details={"error": str(ve)}
                ),
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            logger.error(f"Error retrieving license application: {str(e)}", exc_info=True)
            return Response(
                format_error_response(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    error_code="APPLICATION_RETRIEVE_ERROR",
                    message="An error occurred while retrieving the license application.",
                    details={"exception": str(e)}
                ),
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def get_queryset(self):
        application_type = self.kwargs.get('application_type')
        application_map = {
            NewLicenseApplication.NEW: NewLicenseApplication,
            RenewalLicenseApplication.RENEWAL: RenewalLicenseApplication,
            ReissueLicenseApplication.REISSUE: ReissueLicenseApplication
        }
        return application_map.get(application_type, None).objects.all()

    def get_serializer_class(self):
        application_type = self.kwargs.get('application_type')
        serializer_map = {
            NewLicenseApplication.NEW: NewLicenseApplicationSerializer,
            RenewalLicenseApplication.RENEWAL: RenewalLicenseApplicationSerializer,
            ReissueLicenseApplication.REISSUE: ReissueLicenseApplicationSerializer
        }
        return serializer_map.get(application_type, None)

# View to list audits related to a specific application
class ApplicationAuditListView(generics.ListAPIView):
    serializer_class = ApplicationAuditSerializer
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="List audits related to a specific application.",
        responses={
            200: openapi.Response("List of application audits."),
            400: openapi.Response("Invalid application ID provided."),
            500: openapi.Response("Server error during audit retrieval.")
        }
    )
    def get(self, request, *args, **kwargs):
        try:
            application_id = self.kwargs['application_id']
            return super().get_queryset().filter(application_id=application_id)
        except Exception as e:
            logger.error(f"Error retrieving application audits: {str(e)}", exc_info=True)
            raise

# View to display the application slip and provide a printer-friendly version
class ApplicationSlipView(LoginRequiredMixin, View):

    @swagger_auto_schema(
        operation_description="Display the application slip and provide a printer-friendly version.",
        responses={
            200: openapi.Response("Application slip rendered successfully."),
            404: openapi.Response("Application not found."),
            500: openapi.Response("Server error during slip rendering.")
        }
    )
    def get(self, request, application_type, application_id, *args, **kwargs):
        try:
            application = self.get_application(application_type, application_id)
            payments = Payment.objects.filter(application=application)
            context = {
                'application': application,
                'payments': payments,
                'is_printable': 'print' in request.GET,
            }
            template_name = 'appSlip/application_slip_print.html' if context['is_printable'] else 'application_slip.html'
            return render(request, template_name, context)
        except Http404:
            return HttpResponse("Application not found.", status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.error(f"Error displaying application slip: {str(e)}", exc_info=True)
            return HttpResponse("An error occurred while displaying the application slip.", status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def get_application(self, application_type, application_id):
        try:
            application_map = {
                'new': NewLicenseApplication,
                'renewal': RenewalLicenseApplication,
                'reissue': ReissueLicenseApplication,
            }
            model = application_map.get(application_type)
            if model is None:
                raise ValueError("Invalid application type")
            return get_object_or_404(model, pk=application_id, user=self.request.user)
        except ValueError as ve:
            logger.error(f"Invalid application type: {str(ve)}", exc_info=True)
            raise Http404("Invalid application type")
        except Exception as e:
            logger.error(f"Error retrieving application: {str(e)}", exc_info=True)
            raise Http404("Error retrieving application")
