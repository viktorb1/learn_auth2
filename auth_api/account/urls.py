from django.contrib import admin
from django.urls import path
from .views import (
    UserRegistration,
    UserLogin,
    UserProfile,
    UserChangePassword,
    SentResetPasswordEmail,
    UserPasswordReset,
    LogoutUser,
)

urlpatterns = [
    path("register/", UserRegistration.as_view(), name="register"),
    path("login/", UserLogin.as_view(), name="login"),
    path("profile/", UserProfile.as_view()),
    path("changepassword/", UserChangePassword.as_view(), name="changepassword"),
    path("reset-password/", SentResetPasswordEmail.as_view(), name="reset-password"),
    path(
        "reset-password/<uid>/<token>/",
        UserPasswordReset.as_view(),
        name="user-reset-password",
    ),
    path("logout/", LogoutUser.as_view(), name="logout"),
]
