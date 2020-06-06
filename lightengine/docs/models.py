from django.db import models

class DocmentationArticle(models.Model):
    title = models.CharField(max_length=50)


class DocumentationContent(models.Model):
    article = models.ForeignKey(DocmentationArticle, on_delete=models.CASCADE)
    text = models.CharField(max_length=9999)
    image = models.ImageField(upload_to='docs/images')

class User(models.Model):
    username = models.CharField(max_length = 50)
    email = models.EmailField(max_length = 250)
    password = models.CharField(max_length = 9999)
    theme = models.CharField(max_length=5, default="light")
    logged_in_as = models.CharField(max_length=50)