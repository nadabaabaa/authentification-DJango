from django.contrib.auth.models import AbstractUser
from django.db import models

class User(AbstractUser):
    #name = models.CharField(max_length=255)
    email = models.CharField(max_length=255, unique=True)
    password = models.CharField(max_length=255)
    username =  models.CharField(max_length=100, default='default_value_here')
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []



