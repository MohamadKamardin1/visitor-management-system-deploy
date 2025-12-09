"""
WhatsApp OTP Service using Twilio (Free Trial Available)
Works on Render serverless hosting
"""

import logging
from typing import Tuple
from django.conf import settings

logger = logging.getLogger(__name__)


def send_otp_via_whatsapp(phone_number: str, code: str) -> Tuple[bool, str]:
    """
    Send OTP via WhatsApp using Twilio.
    
    Free: $20 trial = ~2,500 messages
    
    Setup:
    1. Sign up: https://www.twilio.com/try-twilio
    2. Get ACCOUNT_SID and AUTH_TOKEN
    3. Create WhatsApp sender (sandbox or verified)
    4. Set in .env:
       TWILIO_ACCOUNT_SID=ACxxxxxxxxx
       TWILIO_AUTH_TOKEN=xxxxxxxxx
       TWILIO_WHATSAPP_FROM=+1234567890 (your Twilio WhatsApp number)
    
    Args:
        phone_number: Recipient's WhatsApp number (e.g., +254712345678)
        code: OTP code
        
    Returns:
        Tuple of (success: bool, message: str)
    """
    try:
        from twilio.rest import Client
        
        account_sid = getattr(settings, 'TWILIO_ACCOUNT_SID', '')
        auth_token = getattr(settings, 'TWILIO_AUTH_TOKEN', '')
        whatsapp_from = getattr(settings, 'TWILIO_WHATSAPP_FROM', '')
        
        if not all([account_sid, auth_token, whatsapp_from]):
            logger.error("❌ Twilio credentials not configured")
            return False, "Twilio credentials not configured"
        
        # Initialize Twilio client
        client = Client(account_sid, auth_token)
        
        # Format phone number for WhatsApp
        if not phone_number.startswith('+'):
            phone_number = '+' + phone_number
        
        # Message content
        message_text = f"Your OTP code is: {code}\nValid for {settings.OTP_EXPIRY_MINUTES} minutes."
        
        logger.info(f"📤 Sending WhatsApp to {phone_number}")
        
        # Send via WhatsApp
        message = client.messages.create(
            body=message_text,
            from_=f"whatsapp:{whatsapp_from}",
            to=f"whatsapp:{phone_number}"
        )
        
        logger.info(f"✅ WhatsApp sent! SID: {message.sid}")
        return True, f"WhatsApp sent successfully (SID: {message.sid})"
    
    except ImportError:
        logger.error("❌ Twilio not installed: pip install twilio")
        return False, "Twilio library not installed. Install: pip install twilio"
    
    except Exception as e:
        error_msg = f"Failed to send WhatsApp: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return False, error_msg


def send_otp_via_sms(phone_number: str, code: str) -> Tuple[bool, str]:
    """
    Send OTP via SMS using Twilio (Free trial covers SMS too).
    
    Args:
        phone_number: Recipient's phone number
        code: OTP code
        
    Returns:
        Tuple of (success: bool, message: str)
    """
    try:
        from twilio.rest import Client
        
        account_sid = getattr(settings, 'TWILIO_ACCOUNT_SID', '')
        auth_token = getattr(settings, 'TWILIO_AUTH_TOKEN', '')
        sms_from = getattr(settings, 'TWILIO_SMS_FROM', '')
        
        if not all([account_sid, auth_token, sms_from]):
            logger.error("❌ Twilio SMS credentials not configured")
            return False, "Twilio SMS credentials not configured"
        
        client = Client(account_sid, auth_token)
        
        # Format phone number
        if not phone_number.startswith('+'):
            phone_number = '+' + phone_number
        
        message_text = f"Your OTP code is: {code}. Valid for {settings.OTP_EXPIRY_MINUTES} minutes."
        
        logger.info(f"📱 Sending SMS to {phone_number}")
        
        message = client.messages.create(
            body=message_text,
            from_=sms_from,
            to=phone_number
        )
        
        logger.info(f"✅ SMS sent! SID: {message.sid}")
        return True, f"SMS sent successfully (SID: {message.sid})"
    
    except ImportError:
        return False, "Twilio library not installed"
    except Exception as e:
        logger.error(f"Failed to send SMS: {str(e)}", exc_info=True)
        return False, str(e)