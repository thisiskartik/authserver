from rest_framework.serializers import ModelSerializer
from .models import User


class UserSerializer(ModelSerializer):
    class Meta:
        model = User
        fields = ('email',
                  'first_name',
                  'last_name',
                  'is_active',
                  'is_staff',
                  'is_superuser')
