from django.db import models


class Product(models.Model):
    title = models.CharField(max_length=255)
    count = models.IntegerField(default=0)
    price = models.PositiveIntegerField(default=0)
    image = models.ImageField(upload_to='media')

    def __str__(self):
        return self.title
