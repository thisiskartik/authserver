from django.contrib.auth.base_user import BaseUserManager
from django.core import mail
from django.contrib.auth.tokens import default_token_generator
from django.conf import settings
from django.template.loader import render_to_string
from django.utils.html import strip_tags


class UserManager(BaseUserManager):

    def create_user(self, email, password, **extra_fields):
        if not email:
            raise ValueError('Email must be set')
        if not extra_fields.get('first_name'):
            raise ValueError('First Name must be set')
        if not extra_fields.get('last_name'):
            raise ValueError('Last Name must be set')

        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save()

        token = default_token_generator.make_token(user)
        subject = f'Email Verification | Welcome {user.first_name} {user.last_name}'
        html_message = render_to_string('email_verification.html',
                                        {'token': token, 'id': user.pk})
        plain_message = strip_tags(html_message)
        from_email = settings.EMAIL_HOST_USER
        to = user.email
        mail.send_mail(subject, plain_message, from_email, [to], html_message=html_message)
        return user

    def create_superuser(self, email, password, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')
        return self.create_user(email, password, **extra_fields)
