from datetime import datetime, timedelta

import jwt
from rest_framework import exceptions
from rest_framework.authentication import get_authorization_header, BaseAuthentication
from core.models import User


class JWTAuthentication(BaseAuthentication):
    def authenticate(self, request):
        auth = get_authorization_header(request).split()

        if auth and len(auth) == 2:
            access_token = auth[1].decode('utf-8')
            user_id = decode_access_token(access_token)
            user = User.objects.filter(id=user_id).first()

            return (user, None)

        raise exceptions.AuthenticationFailed('Unauthenticated!')


def create_access_token(user_id):
    return jwt.encode(
        {
            'user_id': user_id,
            'exp': datetime.utcnow() + timedelta(minutes=15),
            'iat': datetime.utcnow(),
        }, 'access_secret', algorithm='HS256'
    )


def decode_access_token(token):
    try:
        payload = jwt.decode(token, 'access_secret', algorithms=['HS256'])
        return payload['user_id']
    except:
        raise exceptions.AuthenticationFailed('Invalid token!')


def decode_refresh_token(token):
    try:
        payload = jwt.decode(token, 'refresh_secret', algorithms=['HS256'])
        return payload['user_id']
    except:
        raise exceptions.AuthenticationFailed('Invalid token!')


def create_refresh_token(user_id):
    return jwt.encode(
        {
            'user_id': user_id,
            'exp': datetime.utcnow() + timedelta(hours=8),
            'iat': datetime.utcnow(),
        }, 'refresh_secret', algorithm='HS256'
    )
