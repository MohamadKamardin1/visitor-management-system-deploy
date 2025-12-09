from django.conf import settings
import logging
import requests
import json

logger = logging.getLogger(__name__)


class SMSService:
    """SMS service using Telerivet."""
    
    def __init__(self):
        self.api_key = settings.TELERIVET_API_KEY
        self.project_id = settings.TELERIVET_PROJECT_ID
        self.phone_id = settings.TELERIVET_PHONE_ID
        self.api_url = "https://api.telerivet.com/v1"
        
        if not self.api_key or not self.project_id:
            logger.warning("Telerivet API credentials not configured.")
    
    def send_sms(self, to_phone, message):
        """Send SMS message via Telerivet."""
        if not self.api_key or not self.project_id:
            logger.warning("Telerivet not configured. SMS not sent.")
            # In development, log the message instead
            if settings.DEBUG:
                logger.info(f"[DEBUG SMS] To: {to_phone}, Message: {message}")
            return False, "SMS service not configured"
        
        try:
            url = f"{self.api_url}/projects/{self.project_id}/messages/send"
            headers = {
                "Content-Type": "application/json"
            }
            auth = (self.api_key, "")
            
            payload = {
                "to_number": to_phone,
                "content": message
            }
            
            # Add phone_id if specified
            if self.phone_id:
                payload["phone_id"] = self.phone_id
            
            response = requests.post(url, json=payload, auth=auth, headers=headers, timeout=10)
            
            if response.status_code == 200:
                result = response.json()
                logger.info(f"SMS sent successfully via Telerivet. Message ID: {result.get('id')}")
                return True, result.get('id')
            else:
                error_msg = f"Telerivet API error: {response.status_code} - {response.text}"
                logger.error(error_msg)
                return False, error_msg
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Telerivet request error: {e}")
            return False, str(e)
        except Exception as e:
            logger.error(f"Unexpected error sending SMS: {e}")
            return False, str(e)
    
    def send_otp(self, phone_number, otp_code):
        """Send OTP code via SMS."""
        message = f"Your visitor management system OTP code is: {otp_code}. Valid for {settings.OTP_EXPIRY_MINUTES} minutes."
        return self.send_sms(phone_number, message)
    
    def send_host_notification(self, host_phone, visitor_name, visitor_phone, host_name):
        """Send notification to host about visitor arrival."""
        message = f"Visitor Alert: {visitor_name} ({visitor_phone}) has arrived and is waiting for you, {host_name}. Please check your dashboard to approve or reject."
        return self.send_sms(host_phone, message)
    
    def send_visitor_approved(self, visitor_phone, visitor_name, host_name, instructions):
        """Send approval notification to visitor."""
        message = f"Hello {visitor_name}, your visit to {host_name} has been approved."
        if instructions:
            message += f" Instructions: {instructions}"
        return self.send_sms(visitor_phone, message)
    
    def send_visitor_rejected(self, visitor_phone, visitor_name, host_name, reason=""):
        """Send rejection notification to visitor."""
        message = f"Hello {visitor_name}, unfortunately your visit to {host_name} has been rejected."
        if reason:
            message += f" Reason: {reason}"
        return self.send_sms(visitor_phone, message)
    
    def send_secretary_notification(self, secretary_phone, visitor_name, card_number):
        """Send notification to secretary to assign card."""
        message = f"New visitor: {visitor_name} needs a card. Please assign card {card_number}."
        return self.send_sms(secretary_phone, message)


# Singleton instance
sms_service = SMSService()

