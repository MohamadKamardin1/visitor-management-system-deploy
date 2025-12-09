from django.core.management.base import BaseCommand
from django.core.mail import send_mail
from django.conf import settings
from core.utils import send_otp_email
import logging

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Test email sending functionality'

    def handle(self, *args, **options):
        self.stdout.write("=== Testing Email Settings ===")
        
        # Print email settings
        self.stdout.write("\nEmail Configuration:")
        for setting in ['EMAIL_BACKEND', 'EMAIL_HOST', 'EMAIL_PORT', 
                       'EMAIL_USE_TLS', 'EMAIL_USE_SSL', 'DEFAULT_FROM_EMAIL']:
            self.stdout.write(f"{setting}: {getattr(settings, setting, 'Not set')}")
        
        # Test direct email
        self.stdout.write("\nSending test email...")
        try:
            send_mail(
                'Test Email from Django',
                'This is a test email from Django.',
                settings.DEFAULT_FROM_EMAIL,
                ['sultankvanny@gmail.com'],
                fail_silently=False,
            )
            self.stdout.write(self.style.SUCCESS("✅ Test email sent successfully!"))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"❌ Failed to send test email: {e}"))
            logger.exception("Email sending failed")
        
        # Test OTP email
        self.stdout.write("\nSending OTP email...")
        try:
            success, message = send_otp_email('sultankvanny@gmail.com', '123456')
            if success:
                self.stdout.write(self.style.SUCCESS("✅ OTP email sent successfully!"))
            else:
                self.stdout.write(self.style.ERROR(f"❌ OTP email failed: {message}"))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"❌ Error sending OTP email: {e}"))
            logger.exception("OTP email sending failed")
