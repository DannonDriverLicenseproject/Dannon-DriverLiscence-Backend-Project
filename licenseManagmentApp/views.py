from rest_framework import generics, status
from rest_framework.views import APIView
from rest_framework.response import Response
import logging
from .models import License
from .serializers import LicenseSerializer, LicenseCheckSerializer

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

class LicenseListCreateView(generics.ListCreateAPIView):
    """View to list all licenses or create a new license."""
    queryset = License.objects.all()
    serializer_class = LicenseSerializer

    def perform_create(self, serializer):
        try:
            serializer.save(user=self.request.user)
            logger.info(f"License created for user: {self.request.user.email}")
        except Exception as e:
            logger.error(f"Error creating license for user {self.request.user.email}: {str(e)}", exc_info=True)
            raise

class LicenseRetrieveUpdateDestroyView(generics.RetrieveUpdateDestroyAPIView):
    """View to retrieve, update, or delete a specific license."""
    queryset = License.objects.all()
    serializer_class = LicenseSerializer

    def get(self, request, *args, **kwargs):
        """Retrieve a specific license."""
        try:
            license = self.get_object()
            serializer = self.get_serializer(license)
            logger.info(f"License retrieved: {license.license_number} for user {request.user.email}")
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Error retrieving license: {str(e)}", exc_info=True)
            return Response(format_error_response(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                error_code="LICENSE_RETRIEVE_ERROR",
                message="An error occurred while retrieving the license.",
                details={"exception": str(e)}
            ), status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def update(self, request, *args, **kwargs):
        """Update a specific license."""
        try:
            partial = kwargs.pop('partial', False)
            instance = self.get_object()
            serializer = self.get_serializer(instance, data=request.data, partial=partial)
            serializer.is_valid(raise_exception=True)
            self.perform_update(serializer)
            logger.info(f"License updated: {instance.license_number} by user {request.user.email}")
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Error updating license: {str(e)}", exc_info=True)
            return Response(format_error_response(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                error_code="LICENSE_UPDATE_ERROR",
                message="An error occurred while updating the license.",
                details={"exception": str(e)}
            ), status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def delete(self, request, *args, **kwargs):
        """Delete a specific license."""
        try:
            instance = self.get_object()
            self.perform_destroy(instance)
            logger.info(f"License deleted: {instance.license_number} by user {request.user.email}")
            return Response(status=status.HTTP_204_NO_CONTENT)
        except Exception as e:
            logger.error(f"Error deleting license: {str(e)}", exc_info=True)
            return Response(format_error_response(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                error_code="LICENSE_DELETE_ERROR",
                message="An error occurred while deleting the license.",
                details={"exception": str(e)}
            ), status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class LicenseCheckView(APIView):
    """View to check both the validity and expiry status of a license by license number."""
    
    def post(self, request, *args, **kwargs):
        try:
            serializer = LicenseCheckSerializer(data=request.data)
            if serializer.is_valid():
                license_number = serializer.validated_data['license_number']
                license = License.objects.filter(license_number=license_number).first()
                
                if not license:
                    logger.warning(f"License not found: {license_number}")
                    return Response(format_error_response(
                        status_code=status.HTTP_404_NOT_FOUND,
                        error_code="LICENSE_NOT_FOUND",
                        message="License not found.",
                        details={"license_number": license_number}
                    ), status=status.HTTP_404_NOT_FOUND)
                
                is_valid = license.is_valid()
                is_expired = license.is_expired()

                logger.info(f"License check performed: {license_number}")
                return Response({
                    "license_number": license_number,
                    "is_valid": is_valid,
                    "is_expired": is_expired,
                    "status": license.get_status_display()
                }, status=status.HTTP_200_OK)
            
            logger.warning("Invalid data for license check.")
            return Response(format_error_response(
                status_code=status.HTTP_400_BAD_REQUEST,
                error_code="VALIDATION_ERROR",
                message="Invalid or incomplete data provided.",
                details=serializer.errors
            ), status=status.HTTP_400_BAD_REQUEST)
        
        except Exception as e:
            logger.error(f"Error checking license: {str(e)}", exc_info=True)
            return Response(format_error_response(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                error_code="LICENSE_CHECK_ERROR",
                message="An error occurred while checking the license.",
                details={"exception": str(e)}
            ), status=status.HTTP_500_INTERNAL_SERVER_ERROR)
