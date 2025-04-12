# utils.py
from rest_framework_simplejwt.tokens import RefreshToken

def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    refresh['role'] = user.role
    refresh['must_reset_password'] = user.must_reset_password
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

# serializers.py

# views.py
