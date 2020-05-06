from django.db import models

class User(models.Model):
    username = models.CharField(max_length = 50)
    email = models.EmailField(max_length = 250)
    password = models.CharField(max_length = 9999)
    logged_in_as = models.CharField(max_length=50)