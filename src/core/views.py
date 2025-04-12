import token
from django.urls import reverse
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from core.models import User
from .permissions import IsAdmin
from rest_framework.permissions import AllowAny
import uuid
from django.core.mail import send_mail
from .serializers import CSVUploadSerializer, CustomTokenObtainPairSerializer, ForgotPasswordConfirmSerializer, ForgotPasswordResetSerializer,  StudentPasswordResetSerializer,  StudentProfileSerializer, UserListSerializer
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from django.db.models import Count, Q
from collections import defaultdict
from datetime import datetime
from django.shortcuts import get_object_or_404
import json
from rest_framework.parsers import JSONParser
from rest_framework import status
from django.core.mail import send_mail
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.conf import settings
import uuid
class UploadCSVView(APIView):
    permission_classes = [IsAuthenticated, IsAdmin]

    def post(self, request):
        serializer = CSVUploadSerializer(data=request.data)
        if serializer.is_valid():
            serializer.process_csv()
            return Response({"message": "CSV processed successfully"}, status=201)
        return Response(serializer.errors, status=400)
from rest_framework_simplejwt.views import TokenObtainPairView

class CustomTokenObtainPairView(TokenObtainPairView):
    def post(self, request):
        serializer = CustomTokenObtainPairSerializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        return Response(serializer.validated_data, status=200)
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from .permissions import IsStudent
from .utils import get_tokens_for_user
import logging

class ForgotPasswordResetView(APIView):
    def post(self, request):
        serializer = ForgotPasswordResetSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            try:
                user = User.objects.get(email=email)
                reset_token = str(uuid.uuid4())
                user.reset_token = reset_token
                user.save()

                reset_url = request.build_absolute_uri(
                    reverse('forgot_password_reset_confirm', kwargs={
                        'uidb64': urlsafe_base64_encode(force_bytes(user.pk)),
                        'token': reset_token
                    })
                )
                subject = 'Forgot Password Reset Request'
                message = f'Click to reset your password: {reset_url}\n\nThis link expires in 24 hours.'
                send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [email], fail_silently=False)
                return Response({"message": "Password reset link sent to your email."}, status=status.HTTP_200_OK)
            except User.DoesNotExist:
                return Response({"message": "Password reset link sent (check your email)."}, status=status.HTTP_200_OK)  # Avoid leaking info
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
logger = logging.getLogger(__name__)
class ForgotPasswordResetConfirmView(APIView):
    def post(self, request, uidb64, token):
        logger.debug(f"View received uidb64={uidb64}, token={token}")
        if not uidb64 or not token:
            logger.error(f"Invalid URL parameters: uidb64={uidb64}, token={token}")
            return Response({"non_field_errors": ["Invalid reset link parameters."]}, status=status.HTTP_400_BAD_REQUEST)

        serializer = ForgotPasswordConfirmSerializer(data=request.data, context={'uidb64': uidb64, 'token': token})
        logger.debug(f"Serializer initialized with uidb64={serializer.uidb64}, token={serializer.token}")
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Password has been reset successfully."}, status=status.HTTP_200_OK)
        logger.debug(f"Serializer errors: {serializer.errors}")
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class StudentPasswordResetView(APIView):
    permission_classes = [IsAuthenticated, IsStudent]

    def post(self, request):
        serializer = StudentPasswordResetSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            tokens = get_tokens_for_user(request.user)
            return Response({"message": "Password reset successfully", "tokens": tokens}, status=200)
        return Response(serializer.errors, status=400)
class StudentDashboardView(APIView):
    permission_classes = [IsAuthenticated, IsStudent]

    def get(self, request):
        if request.user.must_reset_password:
            return Response({"error": "Must reset password first",
                "redirect": "/api/password-reset/"}, status=403)
        serializer = StudentProfileSerializer(request.user)
        return Response(serializer.data, status=200)
class AdminDashboardView(APIView):
    permission_classes = [IsAuthenticated, IsAdmin]

    def get(self, request):
        students = User.objects.filter(role='student')
        serializer = UserListSerializer(students, many=True)
        return Response(serializer.data, status=200)
# views.py
from .permissions import IsSuperAdmin

class SuperAdminDashboardView(APIView):
    permission_classes = [IsAuthenticated, IsSuperAdmin]

    def get(self, request):
        users = User.objects.all()
        serializer = UserListSerializer(users, many=True)
        return Response(serializer.data, status=200)

class AdminManagementView(APIView):
    permission_classes = [IsAuthenticated, IsSuperAdmin]

    def post(self, request):  # Add admin
        email = request.data.get('email')
        user = User.objects.filter(email=email).first()
        if not user:
            return Response({"error": "User not found"}, status=404)
        user.role = 'admin'
        user.is_admin = True
        user.save()
        return Response({"message": f"{email} is now an admin"}, status=200)

    def delete(self, request):  # Remove admin
        email = request.data.get('email')
        user = User.objects.filter(email=email, role='admin').first()
        if not user:
            return Response({"error": "Admin not found"}, status=404)
        user.role = 'student'
        user.is_admin = False
        user.save()
        return Response({"message": f"{email} admin access removed"}, status=200)

