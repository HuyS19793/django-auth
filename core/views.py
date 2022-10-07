import datetime
import random
import string

import pyotp
from django.core.mail import send_mail
from rest_framework import exceptions
from rest_framework.response import Response
from rest_framework.views import APIView

from core.authentication import create_access_token, create_refresh_token, JWTAuthentication, decode_refresh_token
from core.models import User, UserToken, ResetPasswordToken
from core.serializers import UserSerializer

from google.oauth2 import id_token
from google.auth.transport.requests import Request as GoogleRequest


class RegisterAPIView(APIView):
    def post(self, request):
        data = request.data

        if data['password'] != data['password_confirm']:
            raise exceptions.ValidationError('Passwords do not match!')

        serializer = UserSerializer(data=data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(serializer.data)


class LoginAPIView(APIView):
    def post(self, request):
        data = request.data

        email = data['email']
        password = data['password']

        user = User.objects.filter(email=email).first()

        if user is None:
            raise exceptions.AuthenticationFailed('User not found!')

        if not user.check_password(password):
            raise exceptions.AuthenticationFailed('Incorrect password!')

        if user.tfa_secret:
            return Response({
                'id': user.id,
            })

        secret = pyotp.random_base32()
        otpauth_url = pyotp.totp.TOTP(secret).provisioning_uri(issuer_name='My App')

        return Response({
            'id': user.id,
            'secret': secret,
            'otpauth_url': otpauth_url,
        })


class TwoFactorAPIView(APIView):

    def post(self, request):
        user_id = request.data['id']

        user = User.objects.filter(id=user_id).first()

        if user is None:
            raise exceptions.AuthenticationFailed('User not found!')

        secret = user.tfa_secret if user.tfa_secret else request.data['secret']

        totp = pyotp.TOTP(secret)

        if not totp.verify(request.data['code']):
            raise exceptions.AuthenticationFailed('Invalid code!')

        if user.tfa_secret is None:
            user.tfa_secret = secret
            user.save()

        access_token = create_access_token(user_id)

        refresh_token = create_refresh_token(user_id)

        UserToken.objects.create(
            user_id=user_id,
            token=refresh_token,
            expired_at=datetime.datetime.utcnow() + datetime.timedelta(days=7)
        )

        response = Response()

        response.data = {
            'access_token': access_token,
            'refresh_token': refresh_token,
        }

        response.set_cookie(key='refresh_token', value=refresh_token, httponly=True)

        return response


class UserAPIView(APIView):
    authentication_classes = [JWTAuthentication]

    def get(self, request):
        return Response(UserSerializer(request.user).data)


class RefreshAPIView(APIView):
    def post(self, request):
        refresh_token = request.COOKIES.get('refresh_token')
        user_id = decode_refresh_token(refresh_token)

        if not UserToken.objects.filter(
                user_id=user_id,
                token=refresh_token,
                expired_at__gt=datetime.datetime.now(tz=datetime.timezone.utc)
        ).exists():
            raise exceptions.AuthenticationFailed('Unauthenticated!')

        access_token = create_access_token(user_id)

        return Response({
            'access_token': access_token
        })


class LogoutAPIView(APIView):
    def post(self, request):
        refresh_token = request.COOKIES.get('refresh_token')
        UserToken.objects.filter(token=refresh_token).delete()

        response = Response()

        response.delete_cookie('refresh_token')

        response.data = {
            'message': 'success'
        }

        return response


class ResetPasswordAPIView(APIView):
    def post(self, request):
        data = request.data

        email = data['email']

        user = User.objects.filter(email=email).first()

        if user is None:
            raise exceptions.AuthenticationFailed('User not found!')

        token = ''.join(random.choice(string.ascii_lowercase) for i in range(18))

        ResetPasswordToken.objects.create(email=email, token=token)

        url = f'http://localhost:3000/reset/{token}'

        send_mail(
            subject='Reset your password',
            message='Click <a href="' + url + '">here</a> to reset your password',
            from_email='admin@ca-adv.co.jp',
            recipient_list=[email],
        )

        return Response({
            'message': 'success!'
        })


class GoogleAuthAPIView(APIView):
    def post(self, request):
        token = request.data['token']

        google_user = id_token.verify_token(token, GoogleRequest())

        if not google_user:
            raise exceptions.AuthenticationFailed('Unauthenticated!')

        user = User.objects.filter(email=google_user['email']).first()

        if not user:
            user = User.objects.create(
                email=google_user['email'],
                first_name=google_user['given_name'],
                last_name=google_user['family_name'],
            )
            user.set_password(token)
            user.save()
            
        user_id = user.id

        access_token = create_access_token(user_id)

        refresh_token = create_refresh_token(user_id)

        UserToken.objects.create(
            user_id=user_id,
            token=refresh_token,
            expired_at=datetime.datetime.utcnow() + datetime.timedelta(days=7)
        )

        response = Response()

        response.data = {
            'access_token': access_token,
            'refresh_token': refresh_token,
        }

        response.set_cookie(key='refresh_token', value=refresh_token, httponly=True)

        return response
