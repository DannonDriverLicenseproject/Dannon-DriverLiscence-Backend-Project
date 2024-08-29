import logging
from django.conf import settings
from django.core.cache import cache
from django.core.mail import EmailMessage
from django.http import HttpResponse
from django.shortcuts import render
from django.utils.encoding import force_bytes, force_str
from django.contrib.sites.shortcuts import get_current_site
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.template.loader import render_to_string
from django.shortcuts import get_object_or_404
from django.http import Http404

from rest_framework import generics, status, permissions
from rest_framework.generics import RetrieveAPIView
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from rest_framework_simplejwt.tokens import RefreshToken

from .models import CustomUser, Profile
from .serializers import (
    UserSerializer, ProfileSerializer, LoginSerializer,
    PasswordResetSerializer, PasswordResetConfirmSerializer, LogoutSerializer
)
from .tokens import password_reset_token_generator
from django.contrib.auth.hashers import make_password

# Set up logging
logger = logging.getLogger(__name__)

# Utility functions
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

def get_user_by_email(email):
    user = cache.get(f"user_email_{email}")
    if not user:
        user = CustomUser.get_user_by_email(email)
        if user:
            cache.set(f"user_email_{email}", user)
    return user

def send_email(subject, body, to_email):
    try:
        email_message = EmailMessage(
            subject=subject,
            body=body,
            from_email=settings.EMAIL_HOST_USER,
            to=[to_email]
        )
        email_message.content_subtype = 'html'
        email_message.send()
        logger.info(f"Email sent to: {to_email}")
    except Exception as e:
        logger.error(f"Error sending email: {str(e)}", exc_info=True)
        raise

# Base class for user-related views
class BaseUserView(APIView):
    permission_classes = [AllowAny]

    def create_token_and_send_email(self, serializer_data, request):
        token_data = {
            'full_name': serializer_data['full_name'],
            'email': serializer_data['email'],
            'password': make_password(serializer_data['password']),
        }
        s = URLSafeTimedSerializer(settings.SECRET_KEY)
        token = s.dumps(token_data, salt='email-confirmation')

        current_site = get_current_site(request).domain
        verification_link = f'http://{current_site}/api/v1/verify-email/{token}/'

        email_body = render_to_string('email/activate.html', {'verification_link': verification_link})
        send_email('Activate Your Account', email_body, serializer_data['email'])

# Views
class RegisterView(BaseUserView, generics.GenericAPIView):
    serializer_class = UserSerializer

    @swagger_auto_schema(
        operation_description="Register a new user.",
        responses={
            200: openapi.Response("Please check your email to complete registration."),
            400: openapi.Response("User with this email already exists.")
        }
    )
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if not serializer.is_valid():
            logger.warning("Validation errors during registration.")
            return Response(format_error_response(
                status_code=status.HTTP_400_BAD_REQUEST,
                error_code="VALIDATION_ERROR",
                message="Invalid or incomplete data provided.",
                details=serializer.errors
            ), status=status.HTTP_400_BAD_REQUEST)

        email = serializer.validated_data['email']
        if get_user_by_email(email):
            logger.info(f"Registration attempt with existing email: {email}")
            return Response(format_error_response(
                status_code=status.HTTP_400_BAD_REQUEST,
                error_code="USER_EXISTS",
                message="User with this email already exists.",
                details={"email": email}
            ), status=status.HTTP_400_BAD_REQUEST)

        try:
            self.create_token_and_send_email(serializer.validated_data, request)
            return Response({'details': 'Please check your email to complete registration.'}, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Error during registration: {str(e)}", exc_info=True)
            return Response(format_error_response(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                error_code="EMAIL_ERROR",
                message="Error sending email.",
                details={"exception": str(e)}
            ), status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class VerifyEmailView(BaseUserView):

    @swagger_auto_schema(
        operation_description="Verify a user's email using the provided token.",
        responses={
            200: openapi.Response("Email verification successful."),
            400: openapi.Response("Invalid or expired verification link.")
        }
    )
    def get(self, request, token, *args, **kwargs):
        s = URLSafeTimedSerializer(settings.SECRET_KEY)
        try:
            token_data = s.loads(token, salt='email-confirmation', max_age=3600)
            email = token_data.get('email')

            if get_user_by_email(email):
                logger.warning(f"Verification attempt with already verified email: {email}")
                return Response(format_error_response(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    error_code="EMAIL_ALREADY_VERIFIED",
                    message="Email already verified.",
                    details={"email": email}
                ), status=status.HTTP_400_BAD_REQUEST)

            CustomUser.objects.create(
                full_name=token_data['full_name'],
                email=email,
                password=token_data['password'],
                is_active=True
            )
            cache.delete(f"user_email_{email}")

            logger.info(f"Email verification successful for: {email}")
            return Response({'message': 'Email verification successful'}, status=status.HTTP_200_OK)

        except SignatureExpired:
            logger.warning("Verification link expired.")
            return Response(format_error_response(
                status_code=status.HTTP_400_BAD_REQUEST,
                error_code="LINK_EXPIRED",
                message="The verification link has expired."
            ), status=status.HTTP_400_BAD_REQUEST)
        except BadSignature:
            logger.warning("Invalid verification link.")
            return Response(format_error_response(
                status_code=status.HTTP_400_BAD_REQUEST,
                error_code="INVALID_LINK",
                message="Invalid verification link."
            ), status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"Unexpected error during email verification: {str(e)}", exc_info=True)
            return Response(format_error_response(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                error_code="VERIFICATION_ERROR",
                message="An unexpected error occurred.",
                details={"exception": str(e)}
            ), status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class LoginView(BaseUserView, generics.GenericAPIView):
    serializer_class = LoginSerializer

    @swagger_auto_schema(
        operation_description="Login a user.",
        responses={
            200: openapi.Response("Successful login with access and refresh tokens."),
            401: openapi.Response("Invalid email or password.")
        }
    )
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']
        password = serializer.validated_data['password']
        user = get_user_by_email(email)

        if user and user.check_password(password):
            refresh = RefreshToken.for_user(user)
            logger.info(f"User logged in: {email}")
            return Response({'refresh': str(refresh), 'access': str(refresh.access_token)}, status=status.HTTP_200_OK)
        else:
            logger.warning(f"Invalid login attempt for email: {email}")
            return Response(format_error_response(
                status_code=status.HTTP_401_UNAUTHORIZED,
                error_code="INVALID_CREDENTIALS",
                message="Invalid email or password.",
                details={"email": email}
            ), status=status.HTTP_401_UNAUTHORIZED)

class PasswordResetView(BaseUserView, generics.GenericAPIView):
    serializer_class = PasswordResetSerializer

    @swagger_auto_schema(
        operation_description="Request a password reset.",
        responses={
            200: openapi.Response("Password reset instructions have been sent to your email."),
            404: openapi.Response("Email not found.")
        }
    )
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']
        user = get_user_by_email(email)

        if user:
            self.send_password_reset_email(user.id, request)
            return Response({'message': 'Password reset instructions have been sent to your email.'}, status=status.HTTP_200_OK)
        else:
            logger.info(f"Password reset request for non-existent email: {email}")
            return Response(format_error_response(
                status_code=status.HTTP_404_NOT_FOUND,
                error_code="EMAIL_NOT_FOUND",
                message="The email address was not found.",
                details={"email": email}
            ), status=status.HTTP_404_NOT_FOUND)

    def send_password_reset_email(self, user_id, request):
        try:
            user = CustomUser.objects.get(id=user_id)
            token = password_reset_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            domain = get_current_site(request).domain
            reset_link = f'http://{domain}/api/v1/password-reset-confirm/{uid}/{token}/'

            email_body = render_to_string('email/password_reset_email.html', {
                'user': user,
                'reset_link': reset_link,
            })
            send_email('Password Reset', email_body, user.email)
        except Exception as e:
            logger.error(f"Error sending password reset email: {str(e)}", exc_info=True)

class PasswordResetConfirmView(BaseUserView):

    @swagger_auto_schema(
        operation_description="Render password reset form for a given token and user ID."
    )
    def get(self, request, uidb64, token, *args, **kwargs):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = CustomUser.get_user_by_id(uid)

            if user and password_reset_token_generator.check_token(user, token):
                context = {'uidb64': uidb64, 'token': token}
                return render(request, 'email/password_reset_form.html', context)
            else:
                return HttpResponse("Invalid password reset link.", status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"Error rendering password reset form: {str(e)}", exc_info=True)
            return HttpResponse("An error occurred.", status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @swagger_auto_schema(
        operation_description="Handle form submission for password reset.",
        responses={
            200: openapi.Response("Password reset successful."),
            400: openapi.Response("Invalid token or user.")
        }
    )
    def post(self, request, uidb64, token, *args, **kwargs):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = CustomUser.get_user_by_id(uid)

            if user and password_reset_token_generator.check_token(user, token):
                password = request.POST.get('password')
                if not password:
                    return render(request, 'email/password_reset_form.html', {
                        'uidb64': uidb64,
                        'token': token,
                        'error': "Password field cannot be empty."
                    })

                user.set_password(password)
                user.save()

                logger.info(f"Password reset successful for user: {user.email}")
                return render(request, "email/password_success.html", status=status.HTTP_200_OK)
            else:
                logger.warning(f"Invalid token or user for password reset. UID: {uid}")
                return HttpResponse("Invalid token or user.", status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"Error during password reset confirmation: {str(e)}", exc_info=True)
            return HttpResponse("An error occurred.", status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class LogoutView(generics.GenericAPIView):
    serializer_class = LogoutSerializer
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Logout a user by invalidating their refresh token.",
        responses={
            200: openapi.Response("Logout successful."),
            400: openapi.Response("Invalid refresh token.")
        }
    )
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            refresh_token = serializer.validated_data['refresh_token']
            token = RefreshToken(refresh_token)
            token.blacklist()

            logger.info(f"User logged out: {request.user.email}")
            return Response({'message': 'Logout successful'}, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Error during logout: {str(e)}", exc_info=True)
            return Response(format_error_response(
                status_code=status.HTTP_400_BAD_REQUEST,
                error_code="LOGOUT_ERROR",
                message="An error occurred during logout.",
                details={"exception": str(e)}
            ), status=status.HTTP_400_BAD_REQUEST)

class ProfileDetail(RetrieveAPIView):
    serializer_class = ProfileSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return Profile.objects.filter(user=self.request.user)

    def get_object(self):
        queryset = self.get_queryset()
        pk = self.kwargs.get('pk')
        return get_object_or_404(queryset, pk=pk)

    def get(self, request, *args, **kwargs):
        try:
            profile = self.get_object()
            serializer = self.get_serializer(profile)
            logger.info(f"Profile retrieved for user: {request.user.email}")
            return Response(serializer.data, status=status.HTTP_200_OK)

        except Http404:
            logger.warning(f"Profile not found for user {request.user.email} with pk={self.kwargs.get('pk')}")
            return Response(format_error_response(
                status_code=status.HTTP_404_NOT_FOUND,
                error_code="PROFILE_NOT_FOUND",
                message="Profile not found.",
                details={"pk": self.kwargs.get('pk')}
            ), status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            logger.error(f"Error retrieving profile for user {request.user.email}: {str(e)}", exc_info=True)
            return Response(format_error_response(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                error_code="PROFILE_RETRIEVAL_ERROR",
                message="An error occurred while retrieving the profile.",
                details={"exception": str(e)}
            ), status=status.HTTP_500_INTERNAL_SERVER_ERROR)
