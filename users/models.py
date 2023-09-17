'''from django.contrib.auth.models import AbstractUser
from django.db import models

class User(AbstractUser):
    #name = models.CharField(max_length=255)
    email = models.CharField(max_length=255, unique=True)
    password = models.CharField(max_length=255)
    username =  models.CharField(max_length=100, default='default_value_here')
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []
'''
# accounts/models.py

from django.contrib.auth.models import AbstractUser
from django.db import models

from django.contrib.auth.models import AbstractUser
from django.db import models
##
from django.contrib.auth.models import User
import uuid
class User(AbstractUser):
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=255)
  #  username = models.CharField(max_length=150, unique=True)
    
   # USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    # Add custom fields here, if needed

    def __str__(self):
        return self.email
###
class UniqueToken(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    token = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    used = models.BooleanField(default=False)

    def __str__(self):
        return str(self.token)