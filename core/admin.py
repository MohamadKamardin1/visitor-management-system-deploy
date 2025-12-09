from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.models import User
from .models import Host, Secretary, Visitor, Visit, Card, OTP, AuditLog


@admin.register(Host)
class HostAdmin(admin.ModelAdmin):
    list_display = ['user', 'phone_number', 'department', 'office_location', 'is_active', 'created_at']
    list_filter = ['is_active', 'created_at', 'department']
    search_fields = ['user__username', 'user__first_name', 'user__last_name', 'phone_number', 'department']
    readonly_fields = ['created_at', 'updated_at']


@admin.register(Secretary)
class SecretaryAdmin(admin.ModelAdmin):
    list_display = ['user', 'phone_number', 'is_active', 'created_at']
    list_filter = ['is_active', 'created_at']
    search_fields = ['user__username', 'user__first_name', 'user__last_name', 'phone_number']
    readonly_fields = ['created_at', 'updated_at']


@admin.register(Visitor)
class VisitorAdmin(admin.ModelAdmin):
    list_display = ['name', 'phone_number', 'email', 'company', 'is_blacklisted', 'created_at']
    list_filter = ['is_blacklisted', 'created_at']
    search_fields = ['name', 'phone_number', 'email', 'company']
    readonly_fields = ['created_at', 'updated_at']


@admin.register(Card)
class CardAdmin(admin.ModelAdmin):
    list_display = ['card_number', 'is_available', 'is_active', 'created_at']
    list_filter = ['is_available', 'is_active', 'created_at']
    search_fields = ['card_number']
    readonly_fields = ['created_at', 'updated_at']


@admin.register(Visit)
class VisitAdmin(admin.ModelAdmin):
    list_display = ['id', 'visitor', 'host', 'status', 'check_in_time', 'check_out_time', 'created_at']
    list_filter = ['status', 'check_in_method', 'created_at', 'check_in_time']
    search_fields = ['visitor__name', 'visitor__phone_number', 'host__user__username', 'card__card_number']
    readonly_fields = ['created_at', 'updated_at', 'check_in_time', 'check_out_time']
    date_hierarchy = 'created_at'
    
    fieldsets = (
        ('Visit Information', {
            'fields': ('visitor', 'host', 'card', 'secretary', 'status', 'purpose', 'check_in_method')
        }),
        ('Timestamps', {
            'fields': ('check_in_time', 'check_out_time', 'host_approved_at', 'host_rejected_at', 
                      'host_finished_at', 'secretary_card_assigned_at', 'secretary_card_collected_at')
        }),
        ('Host Actions', {
            'fields': ('host_instructions', 'rejection_reason')
        }),
        ('System', {
            'fields': ('created_at', 'updated_at')
        }),
    )


@admin.register(OTP)
class OTPAdmin(admin.ModelAdmin):
    list_display = ['phone_number', 'code', 'is_verified', 'attempts', 'expires_at', 'created_at']
    list_filter = ['is_verified', 'created_at', 'expires_at']
    search_fields = ['phone_number', 'code']
    readonly_fields = ['created_at', 'updated_at', 'verified_at']


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ['action', 'user', 'visit', 'created_at', 'ip_address']
    list_filter = ['action', 'created_at']
    search_fields = ['description', 'user__username', 'visit__id']
    readonly_fields = ['created_at', 'updated_at']
    date_hierarchy = 'created_at'
