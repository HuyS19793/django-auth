from django.urls import path

from core.views import RegisterAPIView, LoginAPIView, UserAPIView, RefreshAPIView, LogoutAPIView, ResetPasswordAPIView, \
    TwoFactorAPIView, GoogleAuthAPIView

urlpatterns = [
    path('register/', RegisterAPIView.as_view(), name='register'),
    path('login/', LoginAPIView.as_view(), name='login'),
    path('two-factor/', TwoFactorAPIView.as_view(), name='two-factor'),
    path('google-auth/', GoogleAuthAPIView.as_view(), name='two-factor'),
    path('user/', UserAPIView.as_view(), name='user_info'),
    path('refresh/', RefreshAPIView.as_view(), name='refresh_token'),
    path('logout/', LogoutAPIView.as_view(), name='logout'),
    path('reset/', ResetPasswordAPIView.as_view(), name='reset_password'),
]
