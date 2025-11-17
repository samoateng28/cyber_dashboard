from django.urls import path
from . import views

urlpatterns = [
    path('', views.login_view, name='login'),
    path('dashboard/', views.dashboard_view, name='dashboard'),
    path('logout/', views.logout_view, name='logout'),
    path('ip-lookup/', views.ip_lookup_view, name='ip_lookup'),
      path('domain-lookup/', views.domain_lookup_view, name='domain_lookup'), 
]