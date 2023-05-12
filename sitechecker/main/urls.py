"""sitechecker URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.urls import path
from .views import index, ScanHost, ScanHostDetails, login, logout, pricing

urlpatterns = [
    path('', index, name='main'),
    path('api/scanhost', ScanHost.as_view(), name='scan'),
    path('api/scanhost/details', ScanHostDetails.as_view(), name='details'),
    path('login', login, name='login'),
    path('logout', logout, name='logout'),
    path('pricing', pricing, name='pricing'),
]
