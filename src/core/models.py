from django.db import models
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser, PermissionsMixin

class UserManager(BaseUserManager):
    def create_user(self, email, name, role='student', password=None):
        if not email:
            raise ValueError('Email is required')
        user = self.model(
            email=self.normalize_email(email),
            name=name,
            role=role,
        )
        if password:
            user.set_password(password)  # Hash password if provided
        else:
            user.password = ''  # Explicitly set to empty if no password
        user.save(using=self._db)
        return user

    def create_student(self, email, name, password=None, role='student'):
        return self.create_user(email, name, role=role, password=password)

    def create_admin(self, email, name, password=None, role='admin'):
        user = self.create_user(email, name, role=role, password=password)
        user.is_admin = True
        user.save(using=self._db)
        return user

    def create_superuser(self, email, name, password=None, role='superadmin'):
        user = self.create_user(email, name, role=role, password=password)
        user.is_admin = True
        user.is_superadmin = True
        user.save(using=self._db)
        return user

class User(AbstractBaseUser, PermissionsMixin):
    ROLES = (
        ('student', 'Student'),
        ('admin', 'Admin'),
        ('superadmin', 'Superadmin'),
    )
    email = models.EmailField(unique=True)
    name = models.CharField(max_length=200)
    role = models.CharField(max_length=10, choices=ROLES, default='student')
    mobile_no = models.CharField(max_length=15, blank=True, null=True)
    address = models.TextField(blank=True, null=True)
    course = models.CharField(max_length=100, blank=True, null=True)
    branch = models.CharField(max_length=100, blank=True, null=True)
    hostel = models.CharField(max_length=100, blank=True, null=True)
    roll_number = models.CharField(max_length=20, unique=True, blank=True, null=True)  # Added from HostelStudent
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)
    is_superadmin = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    must_reset_password = models.BooleanField(default=False)
    reset_token = models.CharField(max_length=36, blank=True, null=True)

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['name']

    def __str__(self):
        return self.email

    def has_perm(self, perm, obj=None):
        return self.is_admin or self.is_superadmin

    def has_module_perms(self, app_label):
        return self.is_admin or self.is_superadmin

    @property
    def is_staff(self):
        return self.is_admin or self.is_superadmin