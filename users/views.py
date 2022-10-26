from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.status import HTTP_400_BAD_REQUEST, HTTP_403_FORBIDDEN, HTTP_201_CREATED, HTTP_200_OK
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.tokens import default_token_generator
from django.conf import settings
from django.core import mail
from django.core.exceptions import ValidationError, ObjectDoesNotExist
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from email_validator import validate_email, EmailNotValidError
from .models import User
from .serializers import UserSerializer
from .managers import UserManager


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


@api_view(['POST'])
def verify_email(request):
    if 'token' not in request.data or 'id' not in request.data:
        return Response({'error': 'Missing Token'}, status=HTTP_400_BAD_REQUEST)

    try:
        user = User.objects.get(pk=request.data['id'])
    except (ObjectDoesNotExist, ValueError):
        return Response({'error': 'Invalid ID'}, status=HTTP_403_FORBIDDEN)

    if default_token_generator.check_token(user, request.data['token']):
        user.is_active = True
        user.save()
        return Response({'success': 'Verified'}, status=HTTP_200_OK)
    else:
        return Response({'error': 'Invalid Token'}, status=HTTP_403_FORBIDDEN)


@api_view(['POST'])
def reset_password(request):
    if 'email' in request.data:
        try:
            user = User.objects.get(email=request.data['email'])
        except ObjectDoesNotExist:
            return Response({'error': 'No Email Found'}, status=HTTP_403_FORBIDDEN)

        token = default_token_generator.make_token(user)
        subject = 'Reset Password'
        html_message = render_to_string('reset_password.html',
                                        {'token': token, 'id': user.pk})
        plain_message = strip_tags(html_message)
        from_email = settings.EMAIL_HOST_USER
        to = user.email
        mail.send_mail(subject, plain_message, from_email, [to], html_message=html_message)
        return Response({'success': 'Password Reset Link Sent'}, status=HTTP_200_OK)
    elif 'token' in request.data and 'id' in request.data and 'password' in request.data:
        try:
            user = User.objects.get(pk=request.data['id'])
        except (ObjectDoesNotExist, ValueError):
            return Response({'error': 'Invalid ID'}, status=HTTP_403_FORBIDDEN)

        if default_token_generator.check_token(user, request.data['token']):
            try:
                validate_password(request.data['password'])
            except ValidationError as e:
                return Response({'error': e},
                                status=HTTP_400_BAD_REQUEST)
            user.set_password(request.data['password'])
            user.save()
            return Response({'success': 'Password Reset Successfully'}, status=HTTP_200_OK)
        else:
            return Response({'error': 'Invalid Token'}, status=HTTP_403_FORBIDDEN)
    else:
        return Response({'error': 'Missing Parameters'}, status=HTTP_400_BAD_REQUEST)


@api_view(['GET', 'PUT', 'DELETE'])
@permission_classes([IsAuthenticated])
def user(request):
    if request.method == 'GET':
        user = UserSerializer(request.user, many=False).data
        return Response(user, HTTP_200_OK)
    elif request.method == 'PUT':
        if 'first_name' in request.data:
            request.user.first_name = request.data['first_name']
        if 'last_name' in request.data:
            request.user.first_name = request.data['last_name']
        if 'email' in request.data:
            try:
                validate_email(request.data['email'])
            except EmailNotValidError:
                return Response({'error': 'Invalid Email Address'},
                                status=HTTP_400_BAD_REQUEST)
            if User.objects.filter(email=request.data['email']).exists():
                return Response(
                    {'error': f"An account already exists with {request.data['email']} email address."},
                    status=HTTP_403_FORBIDDEN)
            request.user.email = UserManager.normalize_email(request.data['email'])
            request.user.is_active = False
            token = default_token_generator.make_token(request.user)
            subject = f'Update Email Verification'
            html_message = render_to_string('email_verification.html',
                                            {'token': token, 'id': request.user.pk})
            plain_message = strip_tags(html_message)
            from_email = settings.EMAIL_HOST_USER
            to = request.user.email
            mail.send_mail(subject, plain_message, from_email, [to], html_message=html_message)
        request.user.save()
        return Response({'success': 'User information updated successfully'}, status=HTTP_200_OK)
    elif request.method == 'DELETE':
        request.user.delete()
        return Response({'success': 'User deleted successfully'}, status=HTTP_200_OK)
