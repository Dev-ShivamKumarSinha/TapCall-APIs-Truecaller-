from django.contrib import admin
from .models import *
# Register your models here.
admin.site.register(RegisteredUser)
admin.site.register(UserContacts)
admin.site.register(UserContactMapping)
