from django.db import models
from django.core.validators import RegexValidator
from django.contrib.auth.models import User

# Create your models here.
phoneNoRegex = '^[0-9]{10}$'
class UserContacts(models.Model):
    name=models.CharField(max_length=200, null=False)
    phone_number=models.CharField(max_length=15, null=False, validators=[RegexValidator(regex=phoneNoRegex, message="Phone Number should consist on 10 digits", code="Invalid Phone No.")])
    email=models.EmailField(max_length=100, null=True)
    spam=models.BooleanField(default=False)

    def __str__(self):
        return self.name
    
class UserContactMapping(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=False)
    userContact = models.ForeignKey(UserContacts, on_delete=models.CASCADE, null=False)

    def __str__(self):
        return str(self.user)+','+str(self.userContact)

class RegisteredUser(models.Model):
    registeredUser=models.OneToOneField(User, on_delete=models.CASCADE, null=False)
    phone_number=models.CharField(max_length=15, null=False, unique=True, validators=[RegexValidator(regex=phoneNoRegex, message="Phone Number should consist on 10 digits", code="Invalid Phone No.")])
    email=models.EmailField(max_length=100, null=True)
    spam=models.BooleanField(default=False)

    def __str__(self):
        return str(self.registeredUser)
     
    
    