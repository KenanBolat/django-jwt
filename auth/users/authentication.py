from datetime import datetime, timedelta
import jwt
from rest_framework import exceptions
from jwt import InvalidTokenError


def create_access_token(identity):
    return jwt.encode({
        'user_id': identity,
        'exp': datetime.utcnow() + timedelta(seconds=30),
        'iat': datetime.utcnow()
    }, 'access_secret', algorithm='HS256')


def create_refresh_token(identity):
    return jwt.encode({
        'user_id': identity,
        'exp': datetime.utcnow() + timedelta(days=7),
        'iat': datetime.utcnow()
    }, 'refresh_secret', algorithm='HS256')


def decode_access_token(token):
    try:
        payload = jwt.decode(token, 'access_secret', algorithms=['HS256'])
        return payload['user_id']
    except :
        raise exceptions.AuthenticationFailed('unauthorized')


def decode_refresh_token(token):
    try:
        payload = jwt.decode(token, 'refresh_secret', algorithms=['HS256'])
        return payload['user_id']
    except exceptions.AuthenticationFailed:
        raise exceptions.AuthenticationError('unauthorized')
