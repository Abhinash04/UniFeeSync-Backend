# serializers.py
from charset_normalizer import from_bytes
from rest_framework import serializers
import csv
from io import StringIO
from .models import User  # Ensure correct import
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
# src/core/serializers.py
from rest_framework import serializers
import csv
from io import StringIO
from .models import User
from django.contrib.auth import authenticate
from rest_framework import serializers

from django.contrib.auth.password_validation import validate_password
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.urls import reverse

from django.core.exceptions import ObjectDoesNotExist
from datetime import datetime   

class CSVUploadSerializer(serializers.Serializer):
    csv_file = serializers.FileField()

    def validate_csv_file(self, value):
        if not value.name.endswith('.csv'):
            raise serializers.ValidationError("File must be a CSV.")
        return value

    def process_csv(self):
        file = self.validated_data['csv_file']
        decoded_file = file.read().decode('utf-8')
        io_string = StringIO(decoded_file)
        reader = csv.DictReader(io_string)

        required_fields = {'email', 'name', 'role', 'mobile_no', 'address', 'course', 'branch', 'hostel', 'roll_number'}
        if not all(field in reader.fieldnames for field in required_fields):
            raise serializers.ValidationError("CSV missing one or more required fields.")

        for row in reader:
            email = row['email']
            if row['role'].lower() != 'student':
                continue
            if User.objects.filter(email=email).exists():
                continue
            if User.objects.filter(roll_number=row['roll_number']).exists():
                raise serializers.ValidationError(f"Roll number {row['roll_number']} already exists.")
            try:
                user = User.objects.create_user(
                    email=email,
                    name=row['name'],
                    role='student'
                )
                user.mobile_no = row['mobile_no']
                user.address = row['address']
                user.course = row['course']
                user.branch = row['branch']
                user.hostel = row['hostel']
                user.roll_number = row['roll_number']
                user.is_active = True
                user.must_reset_password = True
                user.save()
                print(f"Saved user: {user.email}, Roll: {user.roll_number}")
            except Exception as e:
                raise serializers.ValidationError(f"Error creating user {email}: {str(e)}")
class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    email = serializers.EmailField(required=True)
    password = serializers.CharField(required=False, write_only=True)
    roll_number = serializers.CharField(required=False, write_only=True)

    def validate(self, attrs):
        email = attrs.get("email")
        password = attrs.get("password")
        roll_number = attrs.get("roll_number")

        if password and roll_number:
            raise serializers.ValidationError("Provide either password or roll_number, not both.")
        
        if not password and not roll_number:
            raise serializers.ValidationError("Either password or roll_number is required.")

        if password:
            # Admin/Superadmin login with email and password
            user = authenticate(request=self.context['request'], email=email, password=password)
            if not user:
                raise serializers.ValidationError("No user found with the given email and password.")
        else:
            # Student first login with email and roll_number
            try:
                user = User.objects.get(email=email, roll_number=roll_number)
                if user.password:  # If password is set, roll_number login isn’t allowed
                    raise serializers.ValidationError("Use email and password for login.")
            except User.DoesNotExist:
                raise serializers.ValidationError("No user found with the given email and roll number.")

        if not user.is_active:
            raise serializers.ValidationError("Account is not active.")

        
from rest_framework import serializers
from rest_framework_simplejwt.tokens import RefreshToken
from .models import User
from django.contrib.auth import authenticate
import logging

logger = logging.getLogger(__name__)

class CustomTokenObtainPairSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    password = serializers.CharField(required=False, write_only=True)
    roll_number = serializers.CharField(required=False, write_only=True)

    def validate(self, attrs):
        email = attrs.get("email")
        password = attrs.get("password")
        roll_number = attrs.get("roll_number")

        if password and roll_number:
            raise serializers.ValidationError("Provide either password or roll_number, not both.")
        
        if not password and not roll_number:
            raise serializers.ValidationError("Either password or roll_number is required.")

        if password:
            # Admin/Superadmin login with email and password
            user = authenticate(request=self.context['request'], email=email, password=password)
            if not user:
                raise serializers.ValidationError("No user found with the given email and password.")
        else:
            # Student first login with email and roll_number
            try:
                user = User.objects.get(email=email, roll_number=roll_number)
                if user.password:  # If password is set, roll_number login isn’t allowed
                    raise serializers.ValidationError("Use email and password for login.")
            except User.DoesNotExist:
                raise serializers.ValidationError("No user found with the given email and roll_number.")

        if not user.is_active:
            raise serializers.ValidationError("Account is not active.")

        # Generate tokens
        refresh = RefreshToken.for_user(user)
        refresh['role'] = user.role
        refresh['must_reset_password'] = user.must_reset_password

        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }


class StudentPasswordResetSerializer(serializers.Serializer):
    new_password = serializers.CharField(write_only=True)

    def validate(self, data):
        user = self.context['request'].user
        if not user.must_reset_password:
            raise serializers.ValidationError("Password reset not required.")
        return data

    def save(self):
        user = self.context['request'].user
        user.set_password(self.validated_data['new_password'])
        user.must_reset_password = False
        user.is_active = True  # Activate after reset
        user.save()
        return user
from rest_framework import serializers
from .models import User

class StudentProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['email', 'name', 'mobile_no', 'address', 'course', 'branch', 'hostel', 'roll_number']
class UserListSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'email', 'name', 'role', 'mobile_no', 'course', 'branch', 'hostel', 'roll_number']
from rest_framework import serializers
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import force_str
from .models import User
import uuid

# Existing student first-login reset serializer (assumed)
class StudentPasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField()
    roll_number = serializers.CharField(max_length=20)

    def validate(self, data):
        try:
            user = User.objects.get(email=data['email'], roll_number=data['roll_number'])
            if not user.must_reset_password:
                raise serializers.ValidationError("Password reset not required for this user.")
        except User.DoesNotExist:
            raise serializers.ValidationError("Invalid email or roll number.")
        return data

# New forgot password serializer for all users
class ForgotPasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        try:
            user = User.objects.get(email=value)
            if not user.is_active:
                raise serializers.ValidationError("User account is not active.")
        except User.DoesNotExist:
            raise serializers.ValidationError("No user found with this email.")
        return value
    
logger = logging.getLogger(__name__)
class ForgotPasswordConfirmSerializer(serializers.Serializer):
    new_password = serializers.CharField(write_only=True, min_length=8)

    def __init__(self, *args, **kwargs):
        # Extract uidb64 and token from kwargs, falling back to context if not present
        self.uidb64 = kwargs.pop('uidb64', kwargs.get('context', {}).get('uidb64', None))
        self.token = kwargs.pop('token', kwargs.get('context', {}).get('token', None))
        logger.debug(f"Serializer initialized with uidb64={self.uidb64}, token={self.token}")
        super().__init__(*args, **kwargs)

    def validate(self, data):
        logger.debug(f"Validating with uidb64={self.uidb64}, token={self.token}")
        if not self.uidb64 or not self.token:
            logger.debug(f"Validation failed: uidb64={self.uidb64}, token={self.token}")
            raise serializers.ValidationError("Invalid reset link parameters.")
        
        try:
            uid = force_str(urlsafe_base64_decode(self.uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            raise serializers.ValidationError("Invalid user ID.")

        if user.reset_token != self.token:
            raise serializers.ValidationError("Invalid or expired token.")

        return data

    def save(self):
        uid = force_str(urlsafe_base64_decode(self.uidb64))
        user = User.objects.get(pk=uid)
        user.set_password(self.validated_data['new_password'])
        user.reset_token = None
        user.must_reset_password = False
        user.save()
        return user