from rest_framework import generics

from .models import Product

from .serializers import ProductSerializers

from rest_framework.permissions import IsAuthenticated


class ProductListView(generics.ListAPIView):
    queryset = Product.objects.all()
    serializer_class = ProductSerializers
    permission_classes = [IsAuthenticated, ]
