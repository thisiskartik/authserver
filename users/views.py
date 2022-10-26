from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework.status import HTTP_400_BAD_REQUEST, HTTP_403_FORBIDDEN, HTTP_201_CREATED, HTTP_200_OK
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from email_validator import validate_email, EmailNotValidError
from .models import User


@api_view(['POST'])
def register(request):
    if 'email' not in request.data or \
            'password' not in request.data or \
            'first_name' not in request.data or \
            'last_name' not in request.data:
        return Response({'error': 'Missing Credentials'},
                        status=HTTP_400_BAD_REQUEST)

    try:
        validate_email(request.data['email'])
    except EmailNotValidError:
        return Response({'error': 'Invalid Email Address'},
                        status=HTTP_400_BAD_REQUEST)

    if User.objects.filter(email=request.data['email']).exists():
        return Response({'error': f"An account already exists with {request.data['email']} email address. Please login."},
                        status=HTTP_403_FORBIDDEN)

    try:
        validate_password(request.data['password'])
    except ValidationError as e:
        return Response({'error': e},
                        status=HTTP_400_BAD_REQUEST)

    try:
        new_user = User.objects.create_user(email=request.data['email'],
                                            password=request.data['password'],
                                            first_name=request.data['first_name'],
                                            last_name=request.data['last_name'])
    except ValueError as e:
        return Response({'error': str(e)},
                        status=HTTP_400_BAD_REQUEST)

    return Response({'error': 'Registration Successful'}, HTTP_201_CREATED)
