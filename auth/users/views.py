import jsonify as jsonify
from django.shortcuts import render
from rest_framework.authentication import get_authorization_header
from rest_framework.exceptions import AuthenticationFailed, APIException
from rest_framework.views import APIView

from .authentication import create_access_token, create_refresh_token, decode_access_token, decode_refresh_token
from .serializers import UserSerializer
from rest_framework.response import Response
from .models import User
import jwt
import datetime


# Create your views here.
class RegisterView(APIView):
    def get(self, request):
        return render(request, 'register.html')

    def post(self, request):
        serializer = UserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)


class LoginView(APIView):
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        user = User.objects.filter(email=email).first()
        if user is None:
            raise APIException('User not found')

        if not user.check_password(password):
            raise APIException('Invalid credentials')
            # return Response({'message': 'Invalid credentials'})

        access_token = create_access_token(user.id)
        refresh_token = create_refresh_token(user.id)
        response = Response()
        response.set_cookie(key='refresh_token', value=refresh_token, httponly=True)
        response.data = {
            'access_token': access_token
        }
        return response


class UserView(APIView):
    def get(self, request):

        auth = get_authorization_header(request).split()
        if not auth or auth[0].lower() != b'bearer':
            raise AuthenticationFailed('Missing authentication')
        else:
            token = auth[1].decode('utf-8')
            id = decode_access_token(token)
            user = User.objects.filter(id=id).first()
            serializer = UserSerializer(user)
            return Response(serializer.data)

        raise exceptions.AuthenticationFailed('Missing authentication')


class RefreshView(APIView):
    def post(self, request):
        refresh_token = request.COOKIES.get('refresh_token')
        id = decode_refresh_token(refresh_token)
        access_token = create_access_token(id)
        return Response({'access_token': access_token})


class LogoutView(APIView):
    def post(self, request):
        response = Response()
        response.delete_cookie(key='refresh_token')
        response.data = {
            'message': 'sucess'
        }
        return response
