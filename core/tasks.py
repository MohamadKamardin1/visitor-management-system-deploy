from celery import shared_task
from django.conf import settings
from django.utils import timezone
from core.utils import send_otp_email
from core.whatsapp_service import send_otp_via_whatsapp, send_otp_via_sms
from core.models import Visit, OTP
import logging

logger = logging.getLogger(__name__)

@shared_task(bind=True, max_retries=3)
def send_otp_sms(self, phone_number, code, email=None):
    """
    Send OTP via WhatsApp (primary) + SMS (fallback) + Email
    Works on Render serverless hosting
    
    Args:
        phone_number: Recipient's phone number
        code: OTP code
        email: Recipient's email (optional)
        
    Returns:
        dict: Results of all sending attempts
    """
    logger.info("="*80)
    logger.info("🚀 Starting OTP sending task")
    logger.info(f"📱 Phone: {phone_number}")
    logger.info(f"📧 Email: {email if email else 'Not provided'}")
    logger.info(f"🔑 OTP Code: {code}")
    
    # Try WhatsApp first
    logger.info("💬 Attempting WhatsApp...")
    wa_success, wa_message = send_otp_via_whatsapp(phone_number, code)
    
    # Try SMS as fallback
    sms_success = False
    sms_message = "Not attempted"
    if not wa_success:
        logger.info("📱 WhatsApp failed, trying SMS...")
        sms_success, sms_message = send_otp_via_sms(phone_number, code)
    
    # Try Email if provided
    email_success = False
    email_message = "Not provided"
    if email:
        logger.info(f"📧 Sending email to {email}...")
        try:
            from core.utils import send_otp_email
            email_success, email_message = send_otp_email(email, code)
            if email_success:
                logger.info(f"✅ Email sent to {email}")
            else:
                logger.warning(f"⚠️ Email failed: {email_message}")
        except Exception as e:
            email_message = str(e)
            logger.error(f"❌ Email error: {str(e)}", exc_info=True)
    
    # Check if at least one method succeeded
    overall_success = wa_success or sms_success or email_success
    
    if not overall_success:
        logger.error("❌ All OTP methods failed. Retrying...")
        raise self.retry(countdown=60 * (2 ** self.request.retries), max_retries=3)
    
    result = {
        'whatsapp': {'sent': wa_success, 'message': wa_message},
        'sms': {'sent': sms_success, 'message': sms_message},
        'email': {'sent': email_success, 'message': email_message},
        'overall_success': overall_success
    }
    
    logger.info("📊 Task completed:")
    logger.info(f"💬 WhatsApp: {'✅' if wa_success else '❌'} {wa_message}")
    logger.info(f"📱 SMS: {'✅' if sms_success else '❌'} {sms_message}")
    if email:
        logger.info(f"📧 Email: {'✅' if email_success else '❌'} {email_message}")
    logger.info("="*80)
    
    return result


@shared_task
def send_visitor_approved_notification(visit_id):
    """Celery task to notify visitor about approval."""
    try:
        visit = Visit.objects.get(id=visit_id)
        visitor = visit.visitor
        host = visit.host
        
        success, result = sms_service.send_visitor_approved(
            visitor.phone_number,
            visitor.name,
            host.user.get_full_name() or host.user.username,
            visit.host_instructions
        )
        if success:
            logger.info(f"Visitor approval notification sent successfully for visit {visit_id}")
        else:
            logger.error(f"Failed to send visitor approval notification for visit {visit_id}: {result}")
        return success, result
    except Visit.DoesNotExist:
        logger.error(f"Visit {visit_id} not found")
        return False, "Visit not found"
    except Exception as e:
        logger.error(f"Error in send_visitor_approved_notification task: {e}")
        return False, str(e)


@shared_task
def send_visitor_rejected_notification(visit_id):
    """Celery task to notify visitor about rejection."""
    try:
        visit = Visit.objects.get(id=visit_id)
        visitor = visit.visitor
        host = visit.host
        
        success, result = sms_service.send_visitor_rejected(
            visitor.phone_number,
            visitor.name,
            host.user.get_full_name() or host.user.username,
            visit.rejection_reason
        )
        if success:
            logger.info(f"Visitor rejection notification sent successfully for visit {visit_id}")
        else:
            logger.error(f"Failed to send visitor rejection notification for visit {visit_id}: {result}")
        return success, result
    except Visit.DoesNotExist:
        logger.error(f"Visit {visit_id} not found")
        return False, "Visit not found"
    except Exception as e:
        logger.error(f"Error in send_visitor_rejected_notification task: {e}")
        return False, str(e)


@shared_task
def send_secretary_notification(visit_id, card_number):
    """Celery task to notify secretary about card assignment."""
    try:
        visit = Visit.objects.get(id=visit_id)
        secretary = visit.secretary
        
        if secretary:
            success, result = sms_service.send_secretary_notification(
                secretary.phone_number,
                visit.visitor.name,
                card_number
            )
            if success:
                logger.info(f"Secretary notification sent successfully for visit {visit_id}")
            else:
                logger.error(f"Failed to send secretary notification for visit {visit_id}: {result}")
            return success, result
        else:
            logger.warning(f"No secretary assigned to visit {visit_id}")
            return False, "No secretary assigned"
    except Visit.DoesNotExist:
        logger.error(f"Visit {visit_id} not found")
        return False, "Visit not found"
    except Exception as e:
        logger.error(f"Error in send_secretary_notification task: {e}")
        return False, str(e)


@shared_task
def send_host_notification(visit_id):
    """Celery task to notify host about visitor arrival."""
    try:
        visit = Visit.objects.get(id=visit_id)
        host = visit.host
        visitor = visit.visitor
        
        if host.notification_preference in ['sms', 'both']:
            success, result = sms_service.send_host_notification(
                host.phone_number,
                visitor.name,
                visitor.phone_number,
                host.user.get_full_name() or host.user.username
            )
            if success:
                logger.info(f"Host notification sent successfully for visit {visit_id}")
            else:
                logger.error(f"Failed to send host notification for visit {visit_id}: {result}")
            return success, result
        else:
            logger.info(f"Host {host.id} has SMS notifications disabled")
            return True, "SMS notifications disabled"
    except Visit.DoesNotExist:
        logger.error(f"Visit {visit_id} not found")
        return False, "Visit not found"
    except Exception as e:
        logger.error(f"Error in send_host_notification task: {e}")
        return False, str(e)


@shared_task
def cleanup_expired_otps():
    """Periodic task to clean up expired OTPs (optional)."""
    try:
        expired_otps = OTP.objects.filter(
            expires_at__lt=timezone.now(),
            is_verified=False
        )
        count = expired_otps.count()
        expired_otps.delete()
        logger.info(f"Cleaned up {count} expired OTPs")
        return count
    except Exception as e:
        logger.error(f"Error in cleanup_expired_otps task: {e}")
        return 0





