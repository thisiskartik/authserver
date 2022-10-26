from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from django.urls import path
from .views import user, register, verify_email, reset_password

urlpatterns = [
    path('', user),
    path('token/', TokenObtainPairView.as_view()),
    path('token/refresh', TokenRefreshView.as_view()),
    path('register/', register),
    path('verify/', verify_email),
    path('reset-password/', reset_password),
]
