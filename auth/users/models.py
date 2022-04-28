from django.db import models
from django.contrib.auth.models import AbstractUser

# Create your models here.
class User(AbstractUser):
    """
    Custom user model.
    """
    name = models.CharField(max_length=255, blank=True, null=True)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=255)
    username = None  # Remove username field
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []


