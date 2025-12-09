from rest_framework import serializers
from django.contrib.auth.models import User
from django.utils import timezone
from .models import Host, Secretary, Visitor, Visit, Card, OTP, AuditLog
from .utils import create_audit_log


class UserSerializer(serializers.ModelSerializer):
    """User serializer for nested representations."""
    class Meta:
        model = User
        fields = ['id', 'username', 'first_name', 'last_name', 'email']
        read_only_fields = ['id']


class HostSerializer(serializers.ModelSerializer):
    """Host serializer."""
    user = UserSerializer(read_only=True)
    user_id = serializers.PrimaryKeyRelatedField(queryset=User.objects.all(), source='user', write_only=True, required=False)
    full_name = serializers.SerializerMethodField()
    display_name = serializers.SerializerMethodField()

    class Meta:
        model = Host
        fields = ['id', 'user', 'user_id', 'phone_number', 'department', 'office_location', 
                  'is_active', 'notification_preference', 'full_name', 'display_name', 'created_at', 'updated_at']
        read_only_fields = ['id', 'created_at', 'updated_at']

    def get_full_name(self, obj):
        return obj.user.get_full_name() or obj.user.username
    
    def get_display_name(self, obj):
        return obj.get_display_name()


class SecretarySerializer(serializers.ModelSerializer):
    """Secretary serializer."""
    user = UserSerializer(read_only=True)
    user_id = serializers.PrimaryKeyRelatedField(queryset=User.objects.all(), source='user', write_only=True, required=False)
    full_name = serializers.SerializerMethodField()

    class Meta:
        model = Secretary
        fields = ['id', 'user', 'user_id', 'phone_number', 'is_active', 'full_name', 'created_at', 'updated_at']
        read_only_fields = ['id', 'created_at', 'updated_at']

    def get_full_name(self, obj):
        return obj.user.get_full_name() or obj.user.username


class VisitorSerializer(serializers.ModelSerializer):
    """Visitor serializer."""
    class Meta:
        model = Visitor
        fields = ['id', 'phone_number', 'name', 'email', 'company', 'is_blacklisted', 
                  'blacklist_reason', 'created_at', 'updated_at']
        read_only_fields = ['id', 'created_at', 'updated_at']


class CardSerializer(serializers.ModelSerializer):
    """Card serializer."""
    class Meta:
        model = Card
        fields = ['id', 'card_number', 'is_available', 'is_active', 'notes', 'created_at', 'updated_at']
        read_only_fields = ['id', 'card_number', 'created_at', 'updated_at']


class VisitSerializer(serializers.ModelSerializer):
    """Visit serializer."""
    visitor = VisitorSerializer(read_only=True)
    host = HostSerializer(read_only=True)
    card = CardSerializer(read_only=True)
    secretary = SecretarySerializer(read_only=True)
    visitor_id = serializers.PrimaryKeyRelatedField(queryset=Visitor.objects.all(), source='visitor', write_only=True, required=False)
    host_id = serializers.PrimaryKeyRelatedField(queryset=Host.objects.all(), source='host', write_only=True, required=False)
    card_id = serializers.PrimaryKeyRelatedField(queryset=Card.objects.filter(is_available=True), source='card', write_only=True, required=False, allow_null=True)
    secretary_id = serializers.PrimaryKeyRelatedField(queryset=Secretary.objects.all(), source='secretary', write_only=True, required=False, allow_null=True)
    
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    duration = serializers.SerializerMethodField()

    class Meta:
        model = Visit
        fields = ['id', 'visitor', 'visitor_id', 'host', 'host_id', 'card', 'card_id', 
                  'secretary', 'secretary_id', 'status', 'status_display', 'purpose', 
                  'check_in_time', 'check_out_time', 'host_approved_at', 'host_rejected_at', 
                  'host_finished_at', 'secretary_card_assigned_at', 'secretary_card_collected_at',
                  'rejection_reason', 'host_instructions', 'check_in_method', 'duration',
                  'created_at', 'updated_at']
        read_only_fields = ['id', 'status', 'check_in_time', 'check_out_time', 
                          'host_approved_at', 'host_rejected_at', 'host_finished_at',
                          'secretary_card_assigned_at', 'secretary_card_collected_at',
                          'created_at', 'updated_at']

    def get_duration(self, obj):
        """Calculate visit duration in minutes."""
        if obj.check_in_time and obj.check_out_time:
            delta = obj.check_out_time - obj.check_in_time
            return int(delta.total_seconds() / 60)
        elif obj.check_in_time:
            delta = timezone.now() - obj.check_in_time
            return int(delta.total_seconds() / 60)
        return None


class OTPSerializer(serializers.ModelSerializer):
    """OTP serializer."""
    is_expired = serializers.SerializerMethodField()

    class Meta:
        model = OTP
        fields = ['id', 'phone_number', 'code', 'is_verified', 'is_expired', 'attempts', 
                  'expires_at', 'verified_at', 'created_at']
        read_only_fields = ['id', 'code', 'is_verified', 'attempts', 'expires_at', 
                          'verified_at', 'created_at']

    def get_is_expired(self, obj):
        return obj.is_expired()


class AuditLogSerializer(serializers.ModelSerializer):
    """Audit log serializer."""
    user = UserSerializer(read_only=True)
    visit = VisitSerializer(read_only=True)
    action_display = serializers.CharField(source='get_action_display', read_only=True)

    class Meta:
        model = AuditLog
        fields = ['id', 'user', 'visit', 'action', 'action_display', 'description', 
                  'ip_address', 'user_agent', 'metadata', 'created_at']
        read_only_fields = ['id', 'created_at']


# Request/Response serializers for specific endpoints

class VisitorCheckInSerializer(serializers.Serializer):
    """Serializer for visitor check-in request."""
    phone_number = serializers.CharField(max_length=20, required=True)
    name = serializers.CharField(max_length=200, required=True)
    host_id = serializers.IntegerField(required=True)
    purpose = serializers.CharField(required=False, allow_blank=True, allow_null=True)
    check_in_method = serializers.ChoiceField(choices=[('kiosk', 'Kiosk'), ('qr', 'QR Code')], default='kiosk', required=False)
    email = serializers.EmailField(required=False, allow_blank=True, allow_null=True)
    company = serializers.CharField(max_length=200, required=False, allow_blank=True, allow_null=True)
    
    def validate(self, data):
        """Convert empty strings to None for optional fields."""
        if 'purpose' in data and data['purpose'] == '':
            data['purpose'] = None
        if 'email' in data and data['email'] == '':
            data['email'] = None
        if 'company' in data and data['company'] == '':
            data['company'] = None
        return data


class OTPRequestSerializer(serializers.Serializer):
    phone_number = serializers.CharField(required=True)
    visit_id = serializers.CharField(required=False, allow_blank=True, allow_null=True)
    email = serializers.EmailField(required=False, allow_blank=True, allow_null=True)
    
    def validate_phone_number(self, value):
        # Add any phone number validation if needed
        return value

class OTPVerifySerializer(serializers.Serializer):
    """Serializer for OTP verification."""
    phone_number = serializers.CharField(max_length=20, required=True)
    code = serializers.CharField(max_length=10, required=True)
    visit_id = serializers.IntegerField(required=False, allow_null=True)


class HostActionSerializer(serializers.Serializer):
    """Serializer for host actions (approve/reject/finish)."""
    action = serializers.ChoiceField(choices=['approve', 'reject', 'finish'], required=True)
    instructions = serializers.CharField(required=False, allow_blank=True, default='')
    reason = serializers.CharField(required=False, allow_blank=True, default='')


class SecretaryCardActionSerializer(serializers.Serializer):
    """Serializer for secretary card actions."""
    action = serializers.ChoiceField(choices=['assign', 'collect'], required=True)
    card_id = serializers.IntegerField(required=False, allow_null=True)


class VisitListSerializer(serializers.ModelSerializer):
    """Lightweight serializer for visit lists."""
    visitor_name = serializers.CharField(source='visitor.name', read_only=True)
    visitor_phone = serializers.CharField(source='visitor.phone_number', read_only=True)
    host_name = serializers.SerializerMethodField()
    card_number = serializers.CharField(source='card.card_number', read_only=True, allow_null=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)

    class Meta:
        model = Visit
        fields = ['id', 'visitor_name', 'visitor_phone', 'host_name', 'card_number', 
                  'status', 'status_display', 'check_in_time', 'check_out_time', 'created_at']

    def get_host_name(self, obj):
        return obj.host.user.get_full_name() or obj.host.user.username

