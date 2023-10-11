from rest_framework import status
from rest_framework.response import Response
from rest_framework.decorators import api_view
from rest_framework_jwt.settings import api_settings
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth.models import User
from django.contrib.auth import logout
from django.contrib.auth.hashers import make_password
from rest_framework.decorators import permission_classes
from rest_framework.permissions import IsAuthenticated


@api_view(['POST'])
def user_registration(request):
    if request.method == 'POST':
        obj = User(username=request.data['username'],password=make_password(request.data['password']),email=request.data['email'])
        obj.save()
        if obj:
            return Response({'message': 'User registered successfully'}, status=status.HTTP_201_CREATED)
        return Response({'Error occurd while creating user..!'}, status=status.HTTP_400_BAD_REQUEST)

jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def user_logout(request):
    print(request,request.user)
    if request.method == 'POST':
        logout(request)
        return Response({'message': 'Logout successful'})
    return Response({'message': 'User not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)