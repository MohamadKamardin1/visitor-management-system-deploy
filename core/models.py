from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from django.core.validators import RegexValidator
import secrets
import string


class TimeStampedModel(models.Model):
    """Abstract base model with created_at and updated_at fields."""
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True


class Host(TimeStampedModel):
    """Host model - person who receives visitors."""
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='host_profile')
    phone_number = models.CharField(
        max_length=20,
        validators=[RegexValidator(regex=r'^\+?1?\d{9,15}$', message="Phone number must be entered in the format: '+999999999'. Up to 15 digits allowed.")]
    )
    department = models.CharField(max_length=100, blank=True)
    office_location = models.CharField(max_length=200, blank=True)
    is_active = models.BooleanField(default=True)
    notification_preference = models.CharField(
        max_length=20,
        choices=[('sms', 'SMS'), ('email', 'Email'), ('both', 'Both')],
        default='both'
    )

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['phone_number']),
            models.Index(fields=['is_active']),
        ]

    def __str__(self):
        return f"{self.user.get_full_name() or self.user.username} - {self.department}"
    
    def get_display_name(self):
        """Get display name based on HOST_DISPLAY_OPTION setting."""
        from django.conf import settings
        option = getattr(settings, 'HOST_DISPLAY_OPTION', 'name')
        
        if option == 'name':
            return self.user.get_full_name() or self.user.username
        elif option == 'department':
            return self.department or self.user.get_full_name() or self.user.username
        elif option == 'office':
            return self.office_location or self.user.get_full_name() or self.user.username
        elif option == 'both':
            parts = []
            if self.user.get_full_name():
                parts.append(self.user.get_full_name())
            if self.department:
                parts.append(f"({self.department})")
            if self.office_location:
                parts.append(f"- {self.office_location}")
            return " ".join(parts) if parts else self.user.username
        else:
            return self.user.get_full_name() or self.user.username


class Secretary(TimeStampedModel):
    """Secretary model - person who manages cards."""
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='secretary_profile')
    phone_number = models.CharField(
        max_length=20,
        validators=[RegexValidator(regex=r'^\+?1?\d{9,15}$', message="Phone number must be entered in the format: '+999999999'. Up to 15 digits allowed.")]
    )
    is_active = models.BooleanField(default=True)

    class Meta:
        ordering = ['-created_at']
        verbose_name_plural = 'Secretaries'

    def __str__(self):
        return f"{self.user.get_full_name() or self.user.username}"


class Visitor(TimeStampedModel):
    """Visitor model - person visiting."""
    phone_number = models.CharField(
        max_length=20,
        validators=[RegexValidator(regex=r'^\+?1?\d{9,15}$', message="Phone number must be entered in the format: '+999999999'. Up to 15 digits allowed.")],
        db_index=True
    )
    name = models.CharField(max_length=200)
    email = models.EmailField(blank=True, null=True)
    company = models.CharField(max_length=200, blank=True, null = True)
    is_blacklisted = models.BooleanField(default=False)
    blacklist_reason = models.TextField(blank=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['phone_number']),
            models.Index(fields=['created_at']),
        ]

    def __str__(self):
        return f"{self.name} - {self.phone_number}"


class Card(TimeStampedModel):
    """Physical card/badge model."""
    card_number = models.CharField(max_length=50, unique=True, db_index=True)
    is_available = models.BooleanField(default=True)
    is_active = models.BooleanField(default=True)
    notes = models.TextField(blank=True)

    class Meta:
        ordering = ['card_number']
        indexes = [
            models.Index(fields=['card_number']),
            models.Index(fields=['is_available']),
        ]

    def __str__(self):
        return f"Card {self.card_number}"

    @staticmethod
    def generate_card_number():
        """Generate a unique card number."""
        while True:
            # Generate a 6-digit alphanumeric card number
            card_number = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(6))
            if not Card.objects.filter(card_number=card_number).exists():
                return card_number


class Visit(TimeStampedModel):
    """Visit model - tracks visitor check-in/check-out."""
    STATUS_CHOICES = [
        ('pending_otp', 'Pending OTP Verification'),
        ('pending_card', 'Pending Card Assignment'),
        ('pending_host_approval', 'Pending Host Approval'),
        ('approved', 'Approved - In Progress'),
        ('rejected', 'Rejected by Host'),
        ('finished', 'Finished by Host'),
        ('checked_out', 'Checked Out'),
        ('cancelled', 'Cancelled'),
    ]

    visitor = models.ForeignKey(Visitor, on_delete=models.CASCADE, related_name='visits')
    host = models.ForeignKey(Host, on_delete=models.CASCADE, related_name='visits')
    card = models.ForeignKey(Card, on_delete=models.SET_NULL, null=True, blank=True, related_name='visits')
    secretary = models.ForeignKey(Secretary, on_delete=models.SET_NULL, null=True, blank=True, related_name='visits')
    
    status = models.CharField(max_length=30, choices=STATUS_CHOICES, default='pending_otp', db_index=True)
    purpose = models.TextField(blank=True , null = True)
    
    check_in_time = models.DateTimeField(null=True, blank=True)
    check_out_time = models.DateTimeField(null=True, blank=True)
    
    host_approved_at = models.DateTimeField(null=True, blank=True)
    host_rejected_at = models.DateTimeField(null=True, blank=True)
    host_finished_at = models.DateTimeField(null=True, blank=True)
    
    secretary_card_assigned_at = models.DateTimeField(null=True, blank=True)
    secretary_card_collected_at = models.DateTimeField(null=True, blank=True)
    
    rejection_reason = models.TextField(blank=True)
    host_instructions = models.TextField(blank=True)  # Instructions for visitor (e.g., office location)
    
    check_in_method = models.CharField(
        max_length=20,
        choices=[('kiosk', 'Kiosk'), ('qr', 'QR Code')],
        default='kiosk'
    )

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['status']),
            models.Index(fields=['created_at']),
            models.Index(fields=['check_in_time']),
            models.Index(fields=['visitor', 'status']),
            models.Index(fields=['host', 'status']),
        ]

    def __str__(self):
        return f"Visit {self.id} - {self.visitor.name} -> {self.host.user.get_full_name() or self.host.user.username}"

    def mark_check_in(self):
        """Mark visit as checked in."""
        self.check_in_time = timezone.now()
        self.status = 'pending_card'
        self.save()

    def assign_card(self, card, secretary):
        """Assign a card to the visit."""
        self.card = card
        self.secretary = secretary
        self.secretary_card_assigned_at = timezone.now()
        self.status = 'pending_host_approval'
        card.is_available = False
        card.save()
        self.save()

    def approve_by_host(self, instructions=''):
        """Approve visit by host."""
        self.status = 'approved'
        self.host_approved_at = timezone.now()
        self.host_instructions = instructions
        self.save()

    def reject_by_host(self, reason=''):
        """Reject visit by host."""
        self.status = 'rejected'
        self.host_rejected_at = timezone.now()
        self.rejection_reason = reason
        self.save()

    def finish_by_host(self):
        """Mark visit as finished by host."""
        self.status = 'finished'
        self.host_finished_at = timezone.now()
        self.save()

    def check_out(self, secretary):
        """Complete check-out process."""
        self.status = 'checked_out'
        self.check_out_time = timezone.now()
        self.secretary_card_collected_at = timezone.now()
        if self.card:
            self.card.is_available = True
            self.card.save()
        self.save()


class OTP(TimeStampedModel):
    """OTP model for visitor verification."""
    phone_number = models.CharField(max_length=20, db_index=True)
    code = models.CharField(max_length=10)
    visit = models.ForeignKey(Visit, on_delete=models.CASCADE, related_name='otps', null=True, blank=True)
    is_verified = models.BooleanField(default=False)
    verified_at = models.DateTimeField(null=True, blank=True)
    attempts = models.IntegerField(default=0)
    expires_at = models.DateTimeField()

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['phone_number', 'is_verified']),
            models.Index(fields=['code', 'is_verified']),
            models.Index(fields=['expires_at']),
        ]

    def __str__(self):
        return f"OTP {self.code} for {self.phone_number}"

    def is_expired(self):
        """Check if OTP is expired."""
        return timezone.now() > self.expires_at

    def verify(self, code):
        """Verify OTP code."""
        if self.is_expired():
            return False, "OTP has expired"
        if self.is_verified:
            return False, "OTP already verified"
        if self.attempts >= 5:  # Max attempts
            return False, "Maximum verification attempts exceeded"
        
        self.attempts += 1
        if self.code == code:
            self.is_verified = True
            self.verified_at = timezone.now()
            self.save()
            return True, "OTP verified successfully"
        else:
            self.save()
            return False, "Invalid OTP code"

    @staticmethod
    def generate_code(length=6):
        """Generate a random OTP code."""
        return ''.join(secrets.choice(string.digits) for _ in range(length))


class AuditLog(TimeStampedModel):
    """Audit log for tracking all system actions."""
    ACTION_CHOICES = [
        ('visitor_checkin', 'Visitor Check-in'),
        ('otp_generated', 'OTP Generated'),
        ('otp_verified', 'OTP Verified'),
        ('card_assigned', 'Card Assigned'),
        ('host_notified', 'Host Notified'),
        ('host_approved', 'Host Approved'),
        ('host_rejected', 'Host Rejected'),
        ('host_finished', 'Host Finished'),
        ('card_collected', 'Card Collected'),
        ('checkout', 'Check-out'),
        ('visit_cancelled', 'Visit Cancelled'),
    ]

    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='audit_logs')
    visit = models.ForeignKey(Visit, on_delete=models.SET_NULL, null=True, blank=True, related_name='audit_logs')
    action = models.CharField(max_length=50, choices=ACTION_CHOICES)
    description = models.TextField()
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['action']),
            models.Index(fields=['created_at']),
            models.Index(fields=['user', 'created_at']),
            models.Index(fields=['visit', 'created_at']),
        ]

    def __str__(self):
        return f"{self.action} - {self.created_at}"
