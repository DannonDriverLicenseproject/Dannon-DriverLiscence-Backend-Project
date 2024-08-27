import logging
from django.shortcuts import render
from django.http import HttpResponse
from django.conf import settings
from django.core.cache import cache
from django.core.mail import EmailMessage
from django.utils.encoding import force_bytes, force_str
from django.contrib.sites.shortcuts import get_current_site
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.template.loader import render_to_string
from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenRefreshView

from .models import CustomUser
from .serializers import (
    UserSerializer, UserSerializerWithToken, LoginSerializer,
    PasswordResetSerializer, PasswordResetConfirmSerializer, LogoutSerializer
)
from .tokens import account_activation_token, password_reset_token_generator
from django.contrib.auth.hashers import make_password

# Set up logging
logger = logging.getLogger(__name__)

# Updated helper function to format error responses with status code
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

# Helper function to get user by email and cache result
def get_user_by_email(email):
    user = cache.get(f"user_email_{email}")
    if not user:
        user = CustomUser.get_user_by_email(email)
        if user:
            cache.set(f"user_email_{email}", user)
    return user


class RegisterView(generics.GenericAPIView):
    """
    Register a new user with email and password. Sends a verification email upon successful registration.
    """
    serializer_class = UserSerializer
    permission_classes = [AllowAny]

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
            # Collect validation errors
            validation_errors = serializer.errors
            return Response(format_error_response(
                status_code=status.HTTP_400_BAD_REQUEST,
                error_code="VALIDATION_ERROR",
                message="Invalid or incomplete data provided.",
                details=validation_errors
            ), status=status.HTTP_400_BAD_REQUEST)
        serializer.is_valid(raise_exception=True)

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
            token_data = {
                'full_name': serializer.validated_data['full_name'],
                'email': email,
                'password': make_password(serializer.validated_data['password']),
            }
            s = URLSafeTimedSerializer(settings.SECRET_KEY)
            token = s.dumps(token_data, salt='email-confirmation')
            
            current_site = get_current_site(request).domain
            verification_link = f'http://{current_site}/api/v1/verify-email/{token}/'

            email_subject = 'Activate Your Account'
            email_body = render_to_string('activate.html', {
                'verification_link': verification_link,
            })

            email_message = EmailMessage(
                subject=email_subject,
                body=email_body,
                from_email=settings.EMAIL_HOST_USER,
                to=[email]
            )
            email_message.content_subtype = 'html'
            email_message.send()

            logger.info(f"Verification email sent to: {email}")
            return Response({'details': 'Please check your email to complete registration.'}, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Error during registration: {str(e)}", exc_info=True)
            return Response(format_error_response(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                error_code="EMAIL_ERROR",
                message="Error sending email.",
                details={"exception": str(e)}
            ), status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class VerifyEmailView(APIView):
    """
    Verifies the user's email using the token sent in the verification email.
    """
    permission_classes = [AllowAny]

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

            user = CustomUser.objects.create(
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


class LoginView(generics.GenericAPIView):
    """
    Login a user using email and password.
    """
    serializer_class = LoginSerializer
    permission_classes = [AllowAny]

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
            data = {
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            }
            logger.info(f"User logged in: {email}")
            return Response(data, status=status.HTTP_200_OK)
        else:
            logger.warning(f"Invalid login attempt for email: {email}")
            return Response(format_error_response(
                status_code=status.HTTP_401_UNAUTHORIZED,
                error_code="INVALID_CREDENTIALS",
                message="Invalid email or password.",
                details={"email": email}
            ), status=status.HTTP_401_UNAUTHORIZED)


class PasswordResetView(generics.GenericAPIView):
    """
    Request a password reset for a user.
    Sends a password reset email if the user exists.
    """
    serializer_class = PasswordResetSerializer
    permission_classes = [AllowAny]

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
        """
        Send a password reset email to the user with the given ID.
        """
        try:
            user = CustomUser.objects.get(id=user_id)
            token = password_reset_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            domain = get_current_site(request).domain
            reset_link = f'http://{domain}/api/v1/password-reset-confirm/{uid}/{token}/'
            email_subject = 'Password Reset'
            email_body = render_to_string('password_reset_email.html', {
                'user': user,
                'reset_link': reset_link,
            })
            email = EmailMessage(
                subject=email_subject,
                body=email_body,
                from_email=settings.EMAIL_HOST_USER,
                to=[user.email],
            )
            email.content_subtype = 'html'
            email.send()
            logger.info(f"Password reset email sent to: {user.email}")
        except Exception as e:
            logger.error(f"Error sending password reset email: {str(e)}", exc_info=True)

class PasswordResetConfirmView(APIView):
    """
    Render a form for password reset and handle the form submission.
    """
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_description="Render password reset form for a given token and user ID."
    )
    def get(self, request, uidb64, token, *args, **kwargs):
        """
        Render a password reset form with the token and uid included.
        """
        try:
            # Attempt to decode the user ID
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = CustomUser.get_user_by_id(uid)

            # Validate the token
            if user and password_reset_token_generator.check_token(user, token):
                # Render the form template
                context = {
                    'uidb64': uidb64,
                    'token': token
                }
                return render(request, 'password_reset_form.html', context)
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
        """
        Handle the password reset form submission.
        """
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = CustomUser.get_user_by_id(uid)

            if user and password_reset_token_generator.check_token(user, token):
                password = request.POST.get('password')
                if not password:
                    return render(request, 'password_reset_form.html', {
                        'uidb64': uidb64,
                        'token': token,
                        'error': "Password field cannot be empty."
                    })

                # Validate and update the password
                user.set_password(password)
                user.save()

                logger.info(f"Password reset successful for user: {user.email}")
                return render(request, "password_success.html", status=status.HTTP_200_OK)
            else:
                logger.warning(f"Invalid token or user for password reset. UID: {uid}")
                return HttpResponse("Invalid token or user.", status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"Error during password reset confirmation: {str(e)}", exc_info=True)
            return HttpResponse("An error occurred.", status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class LogoutView(generics.GenericAPIView):
    """
    Logout a user by blacklisting the refresh token.
    """
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
