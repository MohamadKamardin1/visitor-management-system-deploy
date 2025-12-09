from django.utils import timezone
from django.conf import settings
from django.core.cache import cache
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from .models import OTP, Visit, AuditLog, Card, Visitor
from datetime import timedelta
import logging

logger = logging.getLogger(__name__)


def create_audit_log(action, description, user=None, visit=None, ip_address=None, user_agent=None, metadata=None):
    """Create an audit log entry."""
    try:
        audit_log = AuditLog.objects.create(
            user=user,
            visit=visit,
            action=action,
            description=description,
            ip_address=ip_address,
            user_agent=user_agent,
            metadata=metadata or {}
        )
        return audit_log
    except Exception as e:
        logger.error(f"Failed to create audit log: {e}")
        return None


def get_client_ip(request):
    """Get client IP address from request."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def get_user_agent(request):
    """Get user agent from request."""
    return request.META.get('HTTP_USER_AGENT', '')


def check_otp_rate_limit(phone_number):
    """Check if phone number has exceeded OTP rate limit."""
    try:
        cache_key = f'otp_rate_limit_{phone_number}'
        attempts = cache.get(cache_key, 0)
        
        if attempts >= settings.OTP_MAX_ATTEMPTS:
            return False, f"Rate limit exceeded. Maximum {settings.OTP_MAX_ATTEMPTS} OTP requests per {settings.OTP_RATE_LIMIT_HOURS} hour(s)."
        
        return True, None
    except Exception as e:
        logger.warning(f"Cache error in check_otp_rate_limit: {e}")
        # If cache fails, allow the request (fail open)
        return True, None


def increment_otp_rate_limit(phone_number):
    """Increment OTP rate limit counter."""
    try:
        cache_key = f'otp_rate_limit_{phone_number}'
        attempts = cache.get(cache_key, 0)
        cache.set(cache_key, attempts + 1, timeout=settings.OTP_RATE_LIMIT_HOURS * 3600)
    except Exception as e:
        logger.warning(f"Cache error in increment_otp_rate_limit: {e}")
        # If cache fails, continue without rate limiting


def generate_and_save_otp(phone_number, visit=None):
    """Generate and save OTP for a phone number."""
    # Check rate limit
    can_proceed, error_message = check_otp_rate_limit(phone_number)
    if not can_proceed:
        return None, error_message
    
    # Invalidate previous unverified OTPs for this phone number
    OTP.objects.filter(phone_number=phone_number, is_verified=False).update(is_verified=True)
    
    # Generate new OTP
    code = OTP.generate_code(settings.OTP_LENGTH)
    expires_at = timezone.now() + timedelta(minutes=settings.OTP_EXPIRY_MINUTES)
    
    otp = OTP.objects.create(
        phone_number=phone_number,
        code=code,
        visit=visit,
        expires_at=expires_at
    )
    
    # Increment rate limit
    increment_otp_rate_limit(phone_number)
    
    return otp, None


def send_otp_email(email, code, visit_id=None):
    """
    Send OTP to the provided email address using a professional HTML template.
    
    Args:
        email (str): Recipient's email address
        code (str): OTP code to send
        visit_id (int, optional): Visit ID to get card number and host details
        
    Returns:
        tuple: (success: bool, message: str)
    """
    logger = logging.getLogger(__name__)
    
    if not email:
        logger.warning("❌ No email address provided")
        return False, "No email address provided"
    
    if not code:
        logger.error("❌ No OTP code provided")
        return False, "No OTP code provided"
    
    logger.info(f"📧 Preparing to send OTP email to: {email}")
    
    try:
        # Validate email format
        from django.core.validators import validate_email
        from django.core.exceptions import ValidationError
        from django.template.loader import render_to_string
        from django.utils.html import strip_tags
        from django.core.mail import EmailMultiAlternatives
        
        try:
            validate_email(email)
        except ValidationError as e:
            logger.error(f"❌ Invalid email format: {email} - {str(e)}")
            return False, f"Invalid email format: {email}"
        
        # Get visit and card details if visit_id is provided
        card_number = None
        host_name = None
        if visit_id:
            try:
                from .models import Visit
                visit = Visit.objects.select_related('card', 'host__user').get(id=visit_id)
                if visit.card:
                    card_number = visit.card.card_number
                if visit.host and visit.host.user:
                    host_name = visit.host.user.get_full_name() or visit.host.user.username
            except Exception as e:
                logger.warning(f"Could not fetch visit details: {str(e)}")
        
        # Prepare context for the template
        context = {
            'code': code,
            'expiry_minutes': 5,
            'card_number': card_number,
            'host_name': host_name,
            'website_url': getattr(settings, 'FRONTEND_URL', 'https://yourwebsite.com'),
            'support_email': getattr(settings, 'SUPPORT_EMAIL', 'support@yourwebsite.com'),
            'company_name': getattr(settings, 'COMPANY_NAME', 'VMS')
        }
        
        # Render HTML and plain text versions
        html_message = render_to_string('emails/otp_email.html', context)
        plain_message = f"""
        Your verification code is: {code}
        
        This code is valid for 5 minutes.
        
        {f'Your assigned card number: {card_number}' if card_number else ''}
        {f'You are visiting: {host_name}' if host_name else ''}
        
        If you didn't request this code, please ignore this email.
        """
        
        subject = f"Your {context['company_name']} Verification Code"
        from_email = settings.DEFAULT_FROM_EMAIL
        recipient_list = [email]
        
        logger.debug(f"📤 Sending email - From: {from_email}, To: {recipient_list}")
        logger.debug(f"📧 Subject: {subject}")
        
        # Send email with HTML and plain text alternatives
        msg = EmailMultiAlternatives(
            subject=subject,
            body=strip_tags(plain_message),
            from_email=from_email,
            to=recipient_list,
            reply_to=[settings.DEFAULT_FROM_EMAIL]
        )
        msg.attach_alternative(html_message, "text/html")
        msg.send(fail_silently=False)
        
        logger.info(f"✅ Successfully sent OTP email to {email}")
        return True, "OTP sent successfully"
        
    except Exception as e:
        error_msg = f"❌ Failed to send OTP email to {email}: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return False, error_msg



        
def verify_otp(phone_number, code, visit=None):
    """Verify OTP code."""
    try:
        # Get the most recent unverified OTP for this phone number
        otp = OTP.objects.filter(
            phone_number=phone_number,
            is_verified=False,
            visit=visit
        ).order_by('-created_at').first()
        
        if not otp:
            return False, "No active OTP found for this phone number"
        
        success, message = otp.verify(code)
        return success, message

        
    except Exception as e:
        logger.error(f"OTP verification error: {e}")
        return False, "An error occurred during OTP verification"



def get_available_card():
    """Get an available card."""
    card = Card.objects.filter(is_available=True, is_active=True).first()
    return card


def assign_card_to_visit(visit, secretary=None):
    """Assign an available card to a visit."""
    card = get_available_card()
    if not card:
        return None, "No available cards at the moment"
    
    visit.assign_card(card, secretary)
    return card, None


def send_welcome_email(visit):
    """
    Send welcome email to visitor with their assigned card details.
    
    Args:
        visit (Visit): The visit instance
        
    Returns:
        tuple: (success: bool, message: str)
    """
    logger_instance = logging.getLogger(__name__)
    
    if not visit.visitor.email:
        return False, "No email address provided for the visitor"
    
    try:
        # Prepare email context
        context = {
            'visitor_name': visit.visitor.name,
            'company_name': getattr(settings, 'COMPANY_NAME', 'Our Company'),
            'card_number': visit.card.card_number if visit.card else None,
            'host_name': f"{visit.host.user.first_name} {visit.host.user.last_name}".strip() or visit.host.user.username,
            'host_instructions': visit.host_instructions,
            'current_year': timezone.now().year
        }
        
        # Render HTML and plain text versions
        html_message = render_to_string('emails/welcome_visitor.html', context)
        plain_message = f"""
        Welcome to {context['company_name']}, {context['visitor_name']}!
        
        Thank you for visiting {context['company_name']}.
        
        {f"Your assigned visitor card number is: {context['card_number']}" if context['card_number'] else ''}
        
        You are visiting: {context['host_name']}
        
        {f"Host Instructions:\n{context['host_instructions']}" if context['host_instructions'] else ''}
        
        Please keep your visitor card visible at all times during your visit.
        Return the card to the reception when leaving the premises.
        
        Thank you for your cooperation.
        """
        
        # Send email
        subject = f"Welcome to {context['company_name']} - Visitor Information"
        from_email = settings.DEFAULT_FROM_EMAIL
        to_email = [visit.visitor.email]
        
        msg = EmailMultiAlternatives(
            subject=subject,
            body=strip_tags(plain_message),
            from_email=from_email,
            to=to_email,
            reply_to=[settings.DEFAULT_FROM_EMAIL]
        )
        msg.attach_alternative(html_message, "text/html")
        msg.send(fail_silently=False)
        
        logger_instance.info(f"✅ Welcome email sent to {visit.visitor.email} for visit {visit.id}")
        return True, "Welcome email sent successfully"
        
    except Exception as e:
        error_msg = f"❌ Failed to send welcome email to {visit.visitor.email}: {str(e)}"
        logger_instance.error(error_msg, exc_info=True)
        return False, error_msg
