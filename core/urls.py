from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

router = DefaultRouter()
router.register(r'hosts', views.HostViewSet, basename='host')
router.register(r'secretaries', views.SecretaryViewSet, basename='secretary')
router.register(r'visitors', views.VisitorViewSet, basename='visitor')
router.register(r'cards', views.CardViewSet, basename='card')
router.register(r'visits', views.VisitViewSet, basename='visit')
router.register(r'audit-logs', views.AuditLogViewSet, basename='audit-log')

urlpatterns = [
    # API routes (REST Framework)
    path('visitors/names/', views.visitor_names_list, name='visitor-names-list'),
    path('', include(router.urls)),
    
    # Web Auth routes
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    
    # Dashboard routes
    path('host/dashboard/', views.host_dashboard, name='host_dashboard'),
    path('secretary/dashboard/', views.secretary_dashboard, name='secretary_dashboard'),
    
    # Home (root)
    path('home/', views.home, name='home'),
    
    # Kiosk web routes (public)
    path('kiosk/', views.visitor_kiosk, name='visitor_kiosk'),
    path('kiosk/submit/', views.visitor_kiosk_submit, name='visitor_kiosk_submit'),
    path('kiosk/otp/', views.visitor_otp, name='visitor_otp'),
    path('kiosk/resend-otp/', views.visitor_resend_otp, name='visitor_resend_otp'),
]

