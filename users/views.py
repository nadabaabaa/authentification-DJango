###l code li ken yekhdm
'''
from django.shortcuts import render

# Create your views here.
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth import login, authenticate
from django.http import JsonResponse
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
#
from rest_framework.response import Response
from rest_framework.exceptions import AuthenticationFailed
from .serializers import UserSerializer
from rest_framework.views import APIView
from .models import User
import jwt,  datetime
from django.core.exceptions import ObjectDoesNotExist
from rest_framework import status
from rest_framework.authtoken.models import Token




@api_view(['POST'])
@permission_classes([AllowAny])
def api_signup(request):
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password1')
            user = authenticate(username=username, password=password)
            login(request, user)
            return JsonResponse({'message': 'User registered and logged in successfully'})
        else:
            return JsonResponse({'message': 'Registration failed', 'errors': form.errors}, status=400)

#
# Create your views here.
class RegisterView(APIView):
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)

@api_view(['POST'])
def user_login(request):
    if request.method == 'POST':
        username = request.data.get('username')
        password = request.data.get('password')

        user = None
        if '@' in username:
            try:
                user = User.objects.get(email=username)
            except ObjectDoesNotExist:
                pass

        if not user:
            user = authenticate(username=username, password=password)

        if user:
            token, _ = Token.objects.get_or_create(user=user)
            return Response({'token': token.key}, status=status.HTTP_200_OK)

        return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

class LoginView(APIView):
    def post(self, request):
        email = request.data['email']
        password = request.data['password']

        user = User.objects.filter(email=email).first()

        if user is None:
            raise AuthenticationFailed('User not found!')

        if not user.check_password(password):
            raise AuthenticationFailed('Incorrect password!')

        payload = {
            'id': user.id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=60),
            'iat': datetime.datetime.utcnow()
        }

        token = jwt.encode(payload, 'secret', algorithm='HS256').decode('utf-8')

        response = Response()

        response.set_cookie(key='jwt', value=token, httponly=True)
        response.data = {
            'jwt': token
        }
        return response
        '''
#####
""""""
"""class UserView(APIView):

    def get(self, request):
        token = request.COOKIES.get('jwt')

        if not token:
            raise AuthenticationFailed('Unauthenticated!')

        try:
            payload = jwt.decode(token, 'secret', algorithm=['HS256'])
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('Unauthenticated!')

        user = User.objects.filter(id=payload['id']).first()
        serializer = UserSerializer(user)
        return Response(serializer.data)


class LogoutView(APIView):
    def post(self, request):
        response = Response()
        response.delete_cookie('jwt')
        response.data = {
            'message': 'success'
        }
        return response
"""
# accounts/views.py

from datetime import timedelta, timezone
from rest_framework import status
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from .serializers import UserSerializer
from rest_framework.authtoken.models import Token
from django.contrib.auth import authenticate
from rest_framework.decorators import api_view, permission_classes
from django.core.exceptions import ObjectDoesNotExist
from rest_framework.permissions import IsAuthenticated
from .models import User
#####
from .models import UniqueToken
#from django.contrib.auth.models import User
import uuid
from django.contrib.auth import update_session_auth_hash
from .serializers import ChangePasswordSerializer
from .serializers import LoginSerializer  # Import your LoginSerializer
from drf_yasg.utils import swagger_auto_schema


'''from django.contrib.auth import authenticate
from django.http import JsonResponse
from rest_framework.permissions import AllowAny
'''
@swagger_auto_schema(method='POST',
    request_body=UserSerializer,
    responses={200: 'Successfully created an account', 400: 'Bad request. Invalid input data.',
    401: 'Unauthorized. Invalid credentials.',
    404: 'User does not exist.',
    500: 'Internal server error. Failed to generate a token.',
},
)   

@api_view(['POST'])
def register_user(request):
    if request.method == 'POST':
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
@swagger_auto_schema(method='POST',
    request_body=LoginSerializer,
    responses={200: 'Successfully logged in and token generated', 400: 'Bad request. Invalid input data.',
    401: 'Unauthorized. Invalid credentials.',
    404: 'User does not exist.',
    500: 'Internal server error. Failed to generate a token.',
},
)   
@api_view(['POST'])
def user_login(request):
    if request.method == 'POST':
      serializer = LoginSerializer(data=request.data)
    if serializer.is_valid():

         username = serializer.data.get('username')
         password = serializer.data.get('password')
        # user = None

         if '@' in username:
            try:
                user = User.objects.get(email=username)
            except ObjectDoesNotExist:
                return Response({'error': 'User does not exist'}, status=status.HTTP_404_NOT_FOUND)

         if not user:
            user = authenticate(username=username, password=password)

         if user:
            # Generate a unique token for the user
            token = generate_unique_token(user)

            if not token:
                return Response({'error': 'Failed to generate a token'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            return Response({'token': str(token)}, status=status.HTTP_200_OK)
        
         return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
    
            ########## 
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def user_logout(request):
    if request.method == 'POST':
        try:
            # Delete the user's token to logout
            request.user.auth_token.delete()
            return Response({'message': 'Successfully logged out.'}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)    

def generate_unique_token(user):
    token = UniqueToken(user=user)
    token.save()
    return token

def validate_unique_token(user, token):
    try:
        unique_token = UniqueToken.objects.get(user=user, token=token, used=False)
        unique_token.used = True
        unique_token.save()
        return True
    except UniqueToken.DoesNotExist:
        return False
    
 #   
@swagger_auto_schema(method='POST',
    request_body=ChangePasswordSerializer,
    responses={200: 'Successfully logged in and you can change your password', 400: 'Bad request. Invalid input data.',
    401: 'Unauthorized. Invalid credentials.',
    404: 'User does not exist.',
    500: 'Internal server error. Failed to generate a token.',
},
)   
    
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def change_password(request):
    if request.method == 'POST':
        serializer = ChangePasswordSerializer(data=request.data)
        if serializer.is_valid():
            user = request.user
            if user.check_password(serializer.data.get('old_password')):
                user.set_password(serializer.data.get('new_password'))
                user.save()
                update_session_auth_hash(request, user)  # To update session after password change
                return Response({'message': 'Password changed successfully.'}, status=status.HTTP_200_OK)
            else:

              return Response({'error': 'Incorrect old password.'}, status=status.HTTP_400_BAD_REQUEST)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)