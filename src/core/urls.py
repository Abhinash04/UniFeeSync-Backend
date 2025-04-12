
from django.urls import path
from .views import (
   StudentPasswordResetView, UploadCSVView, CustomTokenObtainPairView, TokenRefreshView,
     StudentDashboardView, AdminDashboardView,
    SuperAdminDashboardView, AdminManagementView, ForgotPasswordResetView, ForgotPasswordResetConfirmView
)

urlpatterns = [
    path('upload-csv/', UploadCSVView.as_view(), name='upload_csv'),
    path('token/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('password-reset/', StudentPasswordResetView.as_view(), name='password_reset'),
    path('password-reset/forgot/', ForgotPasswordResetView.as_view(), name='forgot_password_reset'),  # Forgot password reset
    path('password-reset/forgot-confirm/<uidb64>/<token>/', ForgotPasswordResetConfirmView.as_view(), name='forgot_password_reset_confirm'),
    path('student/dashboard/', StudentDashboardView.as_view(), name='student_dashboard'),
    path('admin/dashboard/', AdminDashboardView.as_view(), name='admin_dashboard'),
    path('superadmin/dashboard/', SuperAdminDashboardView.as_view(), name='superadmin_dashboard'),
    path('superadmin/manage-admins/', AdminManagementView.as_view(), name='admin_management'),
]