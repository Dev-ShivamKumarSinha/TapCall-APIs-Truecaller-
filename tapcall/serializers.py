from rest_framework import serializers
from .models import RegisteredUser, UserContacts, UserContactMapping
from django.contrib.auth.models import User

class RegisteredUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = RegisteredUser
        fields = '__all__'
    
class UserContactsSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserContacts
        fields = '__all__'
"""
class UserContactMappingSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserContactMapping
        fields = '__all__'
"""