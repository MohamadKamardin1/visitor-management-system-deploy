from rest_framework import viewsets, status, permissions
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.response import Response
from rest_framework.throttling import UserRateThrottle, AnonRateThrottle
from rest_framework.permissions import AllowAny
from django.shortcuts import get_object_or_404, render, redirect
from django.contrib import messages
from django.db.models import Q
from django.db import transaction
from django.utils import timezone
import logging
from django.conf import settings
from core.utils import send_otp_email, create_audit_log, get_client_ip, get_user_agent
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_protect
from rest_framework.authtoken.models import Token

logger = logging.getLogger(__name__)

from .models import Host, Secretary, Visitor, Visit, Card, OTP, AuditLog
from .serializers import (
    HostSerializer, SecretarySerializer, VisitorSerializer, VisitSerializer,
    CardSerializer, OTPSerializer, AuditLogSerializer, VisitorCheckInSerializer,
    OTPRequestSerializer, OTPVerifySerializer, HostActionSerializer,
    SecretaryCardActionSerializer, VisitListSerializer
)
from .utils import (
    create_audit_log, get_client_ip, get_user_agent,
    generate_and_save_otp, verify_otp, assign_card_to_visit, send_otp_email,
    send_welcome_email
)
from .tasks import (
    send_otp_sms, send_host_notification, send_visitor_approved_notification,
    send_visitor_rejected_notification, send_secretary_notification
)


# Custom throttle classes
class OTPRateThrottle(AnonRateThrottle):
    """Custom throttle for OTP requests."""
    scope = 'otp_request'
    rate = '20/hour'


class OTPVerifyThrottle(AnonRateThrottle):
    """Custom throttle for OTP verification."""
    scope = 'otp_verify'
    rate = '30/hour'


class HostViewSet(viewsets.ModelViewSet):
    """ViewSet for Host management."""
    queryset = Host.objects.all()
    serializer_class = HostSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        queryset = Host.objects.all()
        if self.request.query_params.get('active_only'):
            queryset = queryset.filter(is_active=True)
        return queryset
    
    @action(detail=False, methods=['get'], permission_classes=[permissions.AllowAny])
    def for_kiosk(self, request):
        """Get active hosts for kiosk selection (public endpoint)."""
        hosts = Host.objects.filter(is_active=True).select_related('user')
        hosts_data = []
        for host in hosts:
            hosts_data.append({
                'id': host.id,
                'display_name': host.get_display_name(),
                'department': host.department,
                'office_location': host.office_location,
            })
        return Response(hosts_data)


class SecretaryViewSet(viewsets.ModelViewSet):
    """ViewSet for Secretary management."""
    queryset = Secretary.objects.all()
    serializer_class = SecretarySerializer
    permission_classes = [permissions.IsAuthenticated]


class VisitorViewSet(viewsets.ModelViewSet):
    """ViewSet for Visitor management."""
    queryset = Visitor.objects.all()
    serializer_class = VisitorSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        queryset = Visitor.objects.all()
        phone = self.request.query_params.get('phone')
        if phone:
            queryset = queryset.filter(phone_number=phone)
        return queryset


def visitor_kiosk(request):
    """Public web kiosk form for QR visitors."""
    hosts = Host.objects.filter(is_active=True)
    context = {'hosts': hosts}
    return render(request, 'visitor_kiosk.html', context)


def visitor_kiosk_submit(request):
    """Handle kiosk form submission and redirect to OTP page."""
    if request.method != 'POST':
        return redirect('visitor_kiosk')

    payload = {
        'phone_number': request.POST.get('phone_number', ''),
        'name': request.POST.get('name', ''),
        'host_id': request.POST.get('host_id'),
        'purpose': request.POST.get('purpose'),
        'email': request.POST.get('email'),
        'company': request.POST.get('company'),
        'check_in_method': 'qr',
    }
    serializer = VisitorCheckInSerializer(data=payload)
    if not serializer.is_valid():
        messages.error(request, "Please correct the highlighted errors.")
        # keep minimal message (do not expose details)
        return redirect('visitor_kiosk')

    data = serializer.validated_data

    # Host lookup
    try:
        host = Host.objects.get(id=data['host_id'], is_active=True)
    except Host.DoesNotExist:
        messages.error(request, "Selected host is not available.")
        return redirect('visitor_kiosk')

    # Visitor create/update
    visitor, created = Visitor.objects.get_or_create(
        phone_number=data['phone_number'],
        defaults={
            'name': data['name'],
            'email': data.get('email') or '',
            'company': data.get('company') or ''
        }
    )
    if not created:
        visitor.name = data['name']
        if data.get('email'):
            visitor.email = data['email']
        if data.get('company'):
            visitor.company = data['company']
        visitor.save()

    if visitor.is_blacklisted:
        messages.error(request, "You are not allowed to check in.")
        return redirect('visitor_kiosk')

    visit = Visit.objects.create(
        visitor=visitor,
        host=host,
        purpose=data.get('purpose') or '',
        check_in_method='qr',
        status='pending_otp'
    )

    create_audit_log(
        'visitor_checkin',
        f'Visitor {visitor.name} checked in for {host.user.get_full_name() or host.user.username}',
        visit=visit,
        ip_address=get_client_ip(request),
        user_agent=get_user_agent(request)
    )

    # Redirect to OTP entry page with visit_id and phone
    return redirect(f"/kiosk/otp/?visit_id={visit.id}&phone={visitor.phone_number}")


def visitor_otp(request):
    """Public OTP verification page (web)."""
    context = {}
    if request.method == 'POST':
        phone = request.POST.get('phone_number')
        code = request.POST.get('code')
        visit_id = request.POST.get('visit_id') or None
        visit = None
        if visit_id:
            visit = Visit.objects.filter(id=visit_id).first()
        success, message = verify_otp(phone, code, visit)
        if success:
            context['success'] = "OTP verified successfully. Thank you."
        else:
            context['error'] = message
    else:
        # prefill for display
        context['phone'] = request.GET.get('phone')
        context['visit_id'] = request.GET.get('visit_id')
    return render(request, 'visitor_otp.html', context)


def visitor_resend_otp(request):
    """Resend OTP for the kiosk flow (web-friendly redirect)."""
    if request.method != 'POST':
        return redirect('visitor_otp')

    phone = request.POST.get('phone_number')
    visit_id = request.POST.get('visit_id') or None
    email = request.POST.get('email') or None

    visit = None
    if visit_id:
        visit = Visit.objects.filter(id=visit_id).first()

    otp, error = generate_and_save_otp(phone, visit)
    if not otp:
        messages.error(request, error or "Could not send OTP.")
        return redirect(f"/kiosk/otp/?phone={phone or ''}&visit_id={visit_id or ''}")

    # send sms (async if celery enabled)
    try:
        send_otp_sms.delay(phone, otp.code)
    except Exception:
        send_otp_sms(phone, otp.code)

    # optional email
    if email:
        send_otp_email(email, otp.code)

    messages.success(request, "A new OTP has been sent.")
    return redirect(f"/kiosk/otp/?phone={phone or ''}&visit_id={visit_id or ''}")

class CardViewSet(viewsets.ModelViewSet):
    """ViewSet for Card management."""
    queryset = Card.objects.all()
    serializer_class = CardSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        queryset = Card.objects.all()
        if self.request.query_params.get('available_only'):
            queryset = queryset.filter(is_available=True, is_active=True)
        return queryset
    
    @action(detail=False, methods=['post'])
    def generate_cards(self, request):
        """Generate multiple cards."""
        count = int(request.data.get('count', 1))
        cards = []
        for _ in range(count):
            card_number = Card.generate_card_number()
            card = Card.objects.create(card_number=card_number)
            cards.append(card)
        
        serializer = self.get_serializer(cards, many=True)
        create_audit_log(
            'card_assigned',
            f'Generated {count} new cards',
            user=request.user,
            ip_address=get_client_ip(request),
            user_agent=get_user_agent(request)
        )
        return Response(serializer.data, status=status.HTTP_201_CREATED)


class VisitViewSet(viewsets.ModelViewSet):
    """ViewSet for Visit management."""
    queryset = Visit.objects.all()
    serializer_class = VisitSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        queryset = Visit.objects.select_related('visitor', 'host__user', 'card', 'secretary__user')
        
        # Filter by status
        status_filter = self.request.query_params.get('status')
        if status_filter:
            queryset = queryset.filter(status=status_filter)
        
        # Filter by host
        host_id = self.request.query_params.get('host_id')
        if host_id:
            queryset = queryset.filter(host_id=host_id)
        
        # Filter by visitor phone
        visitor_phone = self.request.query_params.get('visitor_phone')
        if visitor_phone:
            queryset = queryset.filter(visitor__phone_number=visitor_phone)
        
        # Filter by date range
        date_from = self.request.query_params.get('date_from')
        date_to = self.request.query_params.get('date_to')
        if date_from:
            queryset = queryset.filter(created_at__gte=date_from)
        if date_to:
            queryset = queryset.filter(created_at__lte=date_to)
        
        return queryset
    
    @action(
        detail=False, 
        methods=['post'],
        throttle_classes=[],
        permission_classes=[AllowAny]
    )
    def check_in(self, request):
        """Allow unauthenticated check-in"""
        serializer = VisitorCheckInSerializer(data=request.data)
        if not serializer.is_valid():
            logger.error(f"Check-in validation errors: {serializer.errors}, Data received: {request.data}")
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        data = serializer.validated_data
        
        # Check if visitor is blacklisted
        visitor, created = Visitor.objects.get_or_create(
            phone_number=data['phone_number'],
            defaults={
                'name': data['name'],
                'email': data.get('email', ''),
                'company': data.get('company', '')
            }
        )
        
        if not created:
            # Update visitor info if exists
            visitor.name = data['name']
            if data.get('email'):
                visitor.email = data['email']
            if data.get('company'):
                visitor.company = data['company']
            visitor.save()
        
        if visitor.is_blacklisted:
            create_audit_log(
                'visitor_checkin',
                f'Blacklisted visitor attempted check-in: {visitor.name}',
                ip_address=get_client_ip(request),
                user_agent=get_user_agent(request)
            )
            return Response(
                {'error': 'Visitor is blacklisted and cannot check in.'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Get host
        try:
            host = Host.objects.get(id=data['host_id'], is_active=True)
        except Host.DoesNotExist:
            return Response(
                {'error': 'Host not found or inactive.'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Create visit
        visit = Visit.objects.create(
            visitor=visitor,
            host=host,
            purpose=data.get('purpose', ''),
            check_in_method=data.get('check_in_method', 'kiosk'),
            status='pending_otp'
        )
        
        create_audit_log(
            'visitor_checkin',
            f'Visitor {visitor.name} checked in for {host.user.get_full_name() or host.user.username}',
            visit=visit,
            ip_address=get_client_ip(request),
            user_agent=get_user_agent(request)
        )
        
        return Response({
            'visit_id': visit.id,
            'message': 'Check-in successful. OTP will be sent to your phone.',
            'status': visit.status
        }, status=status.HTTP_201_CREATED)
    
    @action(
        detail=False, 
        methods=['post'],
        throttle_classes=[OTPRateThrottle],
        permission_classes=[AllowAny]
    )
    def request_otp(self, request):
        """Request OTP - allow unauthenticated"""
        logger.info("="*80)
        logger.info("🔄 Processing OTP request")
        logger.debug(f"📥 Request data: {request.data}")
        
        # Validate request data
        serializer = OTPRequestSerializer(data=request.data)
        if not serializer.is_valid():
            logger.error(f"❌ Invalid request data: {serializer.errors}")
            return Response(
                {'error': 'Invalid data', 'details': serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        phone_number = serializer.validated_data['phone_number']
        visit_id = serializer.validated_data.get('visit_id')
        email = serializer.validated_data.get('email')
        
        logger.info(f"📱 Processing OTP request for phone: {phone_number}")
        logger.info(f"📧 Email provided: {email if email else 'No email provided'}")
        logger.info(f"🏢 Visit ID: {visit_id if visit_id else 'No visit ID'}")
        
        # Get visit if visit_id is provided
        visit = None
        if visit_id:
            try:
                visit = Visit.objects.get(id=visit_id)
                logger.info(f"✅ Found visit: {visit_id}")
            except Visit.DoesNotExist:
                error_msg = f"❌ Visit not found: {visit_id}"
                logger.error(error_msg)
                return Response(
                    {'error': 'Visit not found.'},
                    status=status.HTTP_404_NOT_FOUND
                )
        
        # Generate OTP
        logger.info("🔑 Generating OTP...")
        otp, error = generate_and_save_otp(phone_number, visit)
        if not otp:
            logger.error(f"❌ Failed to generate OTP: {error}")
            return Response(
                {'error': 'Failed to generate OTP', 'details': error},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        logger.info(f"✅ OTP generated: {otp.code} (ID: {otp.id})")
        
        # Send OTP via SMS and optionally email
        try:
            logger.info("🚀 Queueing OTP sending task...")
            task_result = send_otp_sms.delay(phone_number, otp.code, email=email)
            
            try:
                result = task_result.get(timeout=5)
                logger.info(f"📨 Task completed: {result}")
                sms_success = result['sms']['sent']
                email_sent = result['email']['sent'] if email else False
                email_error = result['email']['message'] if not result['email']['sent'] and email else None
            except Exception as task_error:
                logger.error(f"❌ Error getting task result: {str(task_error)}")
                sms_success = False
                email_sent = False
                email_error = "Failed to send OTP"
        except Exception as e:
            logger.error(f"❌ Failed to queue OTP task: {str(e)}")
            sms_success = False
            email_sent = False
            email_error = "Failed to send OTP"
        
        # Prepare response
        response_data = {
            'message': 'OTP sent successfully to your phone.',
            'phone_number': phone_number,
            'sms_sent': sms_success,
            'email_sent': email_sent,
            'expires_in_minutes': 5
        }
        
        # Update response message based on results
        if not sms_success:
            response_data['message'] = 'Warning: Failed to send SMS. Please try again.'
        
        if email:
            if email_sent:
                response_data['message'] += ' Check your email for the code.'
            else:
                response_data['message'] += f' Email sending failed: {email_error or "Unknown error"}'
                if email_error:
                    response_data['email_error'] = email_error
        
        # Create audit log
        try:
            audit_metadata = {
                'otp_id': otp.id,
                'phone_number': phone_number,
                'email': email if email else None,
                'email_sent': email_sent,
                'sms_sent': sms_success,
                'visit_id': str(visit.id) if visit else None,
            }
            
            create_audit_log(
                'otp_generated',
                f'OTP generated for {phone_number}. Email: {email_sent}, SMS: {sms_success}',
                visit=visit,
                ip_address=get_client_ip(request),
                user_agent=get_user_agent(request),
                metadata=audit_metadata
            )
            logger.info("📝 Audit log created successfully")
        except Exception as e:
            logger.error(f"❌ Failed to create audit log: {str(e)}", exc_info=True)
        
        logger.info(f"✅ OTP request processed successfully. Response: {response_data}")
        logger.info("="*80)
        
        return Response(response_data, status=status.HTTP_200_OK)

    @action(
        detail=False, 
        methods=['post'],
        throttle_classes=[OTPVerifyThrottle],
        permission_classes=[AllowAny]
    )
    def verify_otp(self, request):
        """Verify OTP and update visit status"""
        logger.info("="*80)
        logger.info("🔍 Processing OTP verification")
        logger.debug(f"📥 Request data: {request.data}")
        
        # Validate request data
        serializer = OTPVerifySerializer(data=request.data)
        if not serializer.is_valid():
            logger.error(f"❌ Invalid verification data: {serializer.errors}")
            return Response(
                {'error': 'Invalid data', 'details': serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        phone_number = serializer.validated_data['phone_number']
        code = serializer.validated_data['code']
        visit_id = serializer.validated_data.get('visit_id')
        
        logger.info(f"🔑 Verifying OTP for phone: {phone_number}")
        logger.info(f"🏢 Visit ID: {visit_id if visit_id else 'No visit ID'}")
        
        # Get visit if visit_id is provided
        visit = None
        if visit_id:
            try:
                visit = Visit.objects.select_related('visitor', 'host__user', 'card').get(id=visit_id)
                logger.info(f"✅ Found visit: {visit_id} | Current status: {visit.status}")
            except Visit.DoesNotExist:
                error_msg = f"❌ Visit not found: {visit_id}"
                logger.error(error_msg)
                return Response(
                    {'error': 'Visit not found.'},
                    status=status.HTTP_404_NOT_FOUND
                )
        
        # Verify OTP
        logger.info("🔐 Verifying OTP...")
        success, message = verify_otp(phone_number, code, visit)
        
        if not success:
            logger.error(f"❌ OTP verification failed: {message}")
            return Response(
                {'error': message},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        logger.info(f"✅ OTP verification successful!")
        
        card_assigned = False
        welcome_email_sent = False
        card_number = None
        
        # Update visit status and assign card if visit exists
        if visit:
            try:
                with transaction.atomic():
                    logger.info(f"📝 Starting visit update transaction...")
                    
                    # First, refresh to get latest state
                    visit.refresh_from_db()
                    logger.info(f"📝 Refreshed visit status: {visit.status}")
                    
                    # Assign a card if not already assigned
                    if not visit.card:
                        logger.info(f"🎫 Attempting to assign card...")
                        card, error = assign_card_to_visit(visit)
                        if card:
                            card_assigned = True
                            card_number = card.card_number
                            logger.info(f"✅ Assigned card {card_number} to visit {visit.id}")
                        else:
                            logger.warning(f"⚠️ Could not assign card: {error}")
                    else:
                        card_number = visit.card.card_number
                        logger.info(f"🎫 Card already assigned: {card_number}")
                    
                    # Update visit status to pending_host_approval
                    old_status = visit.status
                    visit.status = 'pending_host_approval'
                    visit.save(update_fields=['status', 'updated_at'])
                    logger.info(f"✅ Updated visit {visit.id} status from '{old_status}' to 'pending_host_approval'")
                    
                    # Refresh again to confirm update
                    visit.refresh_from_db()
                    logger.info(f"✅ Confirmed new status: {visit.status}")
                    
                    # Send welcome email if visitor has email
                    if visit.visitor.email:
                        logger.info(f"📧 Sending welcome email to {visit.visitor.email}...")
                        email_success, email_message = send_welcome_email(visit)
                        if email_success:
                            welcome_email_sent = True
                            logger.info(f"✅ Sent welcome email to {visit.visitor.email}")
                        else:
                            logger.warning(f"⚠️ Failed to send welcome email: {email_message}")
                    else:
                        logger.info(f"⚠️ No email provided for visitor, skipping welcome email")
            
            except Exception as e:
                logger.error(f"❌ Error during visit update: {str(e)}", exc_info=True)
                return Response(
                    {'error': f'Failed to process OTP verification: {str(e)}'},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        
        # Get the latest visit data
        if visit:
            visit.refresh_from_db()
            logger.info(f"📊 Final visit status: {visit.status}")
            visit_data = VisitSerializer(visit).data
        else:
            visit_data = None
        
        # Create audit log
        try:
            audit_metadata = {
                'phone_number': phone_number,
                'visit_id': str(visit.id) if visit else None,
                'verification_success': True,
                'card_assigned': card_assigned,
                'card_number': card_number,
                'welcome_email_sent': welcome_email_sent,
                'final_status': visit.status if visit else None,
            }
            
            create_audit_log(
                'otp_verified',
                f'OTP verified for {phone_number}. Card: {card_number}, Status: {visit.status if visit else "N/A"}',
                visit=visit,
                ip_address=get_client_ip(request),
                user_agent=get_user_agent(request),
                metadata=audit_metadata
            )
            logger.info("📝 Audit log created successfully")
        except Exception as e:
            logger.error(f"❌ Failed to create audit log: {str(e)}", exc_info=True)
        
        logger.info("✅ OTP verification completed successfully")
        logger.info("="*80)
        
        response_data = {
            'message': 'OTP verified successfully!',
            'visit': visit_data,
            'card_assigned': card_assigned,
            'card_number': card_number,
            'welcome_email_sent': welcome_email_sent,
            'status': visit.status if visit else None,
        }
        
        return Response(response_data, status=status.HTTP_200_OK)

    @action(detail=True, methods=['post'], permission_classes=[permissions.IsAuthenticated])
    def host_action(self, request, pk=None):
        """Host actions: approve, reject, or finish visit."""
        visit = self.get_object()
        serializer = HostActionSerializer(data=request.data)
        
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        action_type = serializer.validated_data['action']
        
        # Verify user is the host
        if not hasattr(request.user, 'host_profile') or request.user.host_profile != visit.host:
            return Response(
                {'error': 'You are not authorized to perform this action.'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        if action_type == 'approve':
            visit.approve_by_host(serializer.validated_data.get('instructions', ''))
            send_visitor_approved_notification.delay(visit.id)
            create_audit_log(
                'host_approved',
                f'Host approved visit {visit.id}',
                user=request.user,
                visit=visit,
                ip_address=get_client_ip(request),
                user_agent=get_user_agent(request)
            )
            return Response({
                'message': 'Visit approved successfully.',
                'visit': VisitSerializer(visit).data
            }, status=status.HTTP_200_OK)
        
        elif action_type == 'reject':
            visit.reject_by_host(serializer.validated_data.get('reason', ''))
            send_visitor_rejected_notification.delay(visit.id)
            create_audit_log(
                'host_rejected',
                f'Host rejected visit {visit.id}',
                user=request.user,
                visit=visit,
                ip_address=get_client_ip(request),
                user_agent=get_user_agent(request)
            )
            return Response({
                'message': 'Visit rejected successfully.',
                'visit': VisitSerializer(visit).data
            }, status=status.HTTP_200_OK)
        
        elif action_type == 'finish':
            visit.finish_by_host()
            create_audit_log(
                'host_finished',
                f'Host finished visit {visit.id}',
                user=request.user,
                visit=visit,
                ip_address=get_client_ip(request),
                user_agent=get_user_agent(request)
            )
            return Response({
                'message': 'Visit marked as finished.',
                'visit': VisitSerializer(visit).data
            }, status=status.HTTP_200_OK)
        
        return Response(
            {'error': 'Invalid action.'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    @action(detail=True, methods=['post'], permission_classes=[permissions.IsAuthenticated])
    def secretary_action(self, request, pk=None):
        """Secretary actions: assign or collect card."""
        visit = self.get_object()
        serializer = SecretaryCardActionSerializer(data=request.data)
        
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        action_type = serializer.validated_data['action']
        
        # Verify user is a secretary
        if not hasattr(request.user, 'secretary_profile'):
            return Response(
                {'error': 'You are not authorized to perform this action.'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        secretary = request.user.secretary_profile
        
        if action_type == 'assign':
            card_id = serializer.validated_data.get('card_id')
            if card_id:
                try:
                    card = Card.objects.get(id=card_id, is_available=True, is_active=True)
                except Card.DoesNotExist:
                    return Response(
                        {'error': 'Card not found or not available.'},
                        status=status.HTTP_404_NOT_FOUND
                    )
            else:
                card, error = assign_card_to_visit(visit, secretary)
                if not card:
                    return Response({'error': error}, status=status.HTTP_400_BAD_REQUEST)
            
            visit.assign_card(card, secretary)
            send_host_notification.delay(visit.id)
            create_audit_log(
                'card_assigned',
                f'Card {card.card_number} assigned to visit {visit.id}',
                user=request.user,
                visit=visit,
                ip_address=get_client_ip(request),
                user_agent=get_user_agent(request)
            )
            return Response({
                'message': 'Card assigned successfully.',
                'visit': VisitSerializer(visit).data
            }, status=status.HTTP_200_OK)
        
        elif action_type == 'collect':
            if visit.status != 'finished':
                return Response(
                    {'error': 'Visit must be finished by host before card collection.'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            visit.check_out(secretary)
            create_audit_log(
                'card_collected',
                f'Card collected from visit {visit.id}',
                user=request.user,
                visit=visit,
                ip_address=get_client_ip(request),
                user_agent=get_user_agent(request)
            )
            return Response({
                'message': 'Card collected and visit checked out successfully.',
                'visit': VisitSerializer(visit).data
            }, status=status.HTTP_200_OK)
        
        return Response(
            {'error': 'Invalid action.'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    @action(detail=False, methods=['get'], permission_classes=[permissions.IsAuthenticated])
    def my_visits(self, request):
        """Get visits for current user (host or secretary)."""
        if hasattr(request.user, 'host_profile'):
            visits = Visit.objects.filter(host=request.user.host_profile)
        elif hasattr(request.user, 'secretary_profile'):
            visits = Visit.objects.filter(secretary=request.user.secretary_profile)
        else:
            visits = Visit.objects.none()
        
        serializer = VisitListSerializer(visits, many=True)
        return Response(serializer.data)


class AuditLogViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet for Audit Log (read-only)."""
    queryset = AuditLog.objects.all()
    serializer_class = AuditLogSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        queryset = AuditLog.objects.select_related('user', 'visit')
        
        # Filter by action
        action = self.request.query_params.get('action')
        if action:
            queryset = queryset.filter(action=action)
        
        # Filter by visit
        visit_id = self.request.query_params.get('visit_id')
        if visit_id:
            queryset = queryset.filter(visit_id=visit_id)
        
        # Filter by date range
        date_from = self.request.query_params.get('date_from')
        date_to = self.request.query_params.get('date_to')
        if date_from:
            queryset = queryset.filter(created_at__gte=date_from)
        if date_to:
            queryset = queryset.filter(created_at__lte=date_to)
        
        return queryset


@api_view(['GET'])
@permission_classes([AllowAny])
def visitor_names_list(request):
    """
    Get list of all visitor names for autocomplete in kiosk
    """
    try:
        visitors = Visitor.objects.values_list('name', flat=True).distinct().order_by('name')
        return Response(list(visitors))
    except Exception as e:
        return Response(
            {'error': f'Failed to load visitor names: {str(e)}'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@require_http_methods(["GET", "POST"])
def login_view(request):
    """Handle user login - redirects based on user type (host/secretary/admin)."""
    if request.user.is_authenticated:
        # Already logged in, redirect to appropriate dashboard
        if hasattr(request.user, 'host_profile'):
            return redirect('host_dashboard')
        elif hasattr(request.user, 'secretary_profile'):
            return redirect('secretary_dashboard')
        elif request.user.is_staff:
            return redirect('admin:index')  # Django admin
        else:
            return redirect('home')
    
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            messages.success(request, f'Welcome back, {user.get_full_name() or user.username}!')
            
            # Redirect based on user type
            if hasattr(user, 'host_profile'):
                return redirect('host_dashboard')
            elif hasattr(user, 'secretary_profile'):
                return redirect('secretary_dashboard')
            elif user.is_staff:
                return redirect('admin:index')  # Django admin
            else:
                return redirect('home')
        else:
            messages.error(request, 'Invalid username or password.')
    
    return render(request, 'core/login.html')


def logout_view(request):
    """Handle user logout - clear tokens and sessions."""
    try:
        # Delete the auth token if it exists
        Token.objects.get(user=request.user).delete()
    except Token.DoesNotExist:
        pass
    
    # Logout the user
    logout(request)
    messages.success(request, 'You have been logged out successfully.')
    return redirect('home')


@login_required(login_url='login')
def admin_dashboard(request):
    """Admin dashboard view - redirect to Django admin."""
    if not request.user.is_staff:
        messages.error(request, 'You do not have access to this page.')
        return redirect('home')
    
    # Redirect to Django admin
    return redirect('admin:index')


@login_required(login_url='login')
def host_dashboard(request):
    """Host dashboard view."""
    # Check if user has host profile
    if not hasattr(request.user, 'host_profile'):
        messages.error(request, 'You do not have access to this page.')
        return redirect('home')
    
    host = request.user.host_profile
    
    # Get visit querysets (not counts)
    pending_visits = Visit.objects.filter(
        host=host,
        status__in=['pending_host_approval', 'approved']
    ).select_related('visitor', 'card')
    
    finished_visits = Visit.objects.filter(
        host=host,
        status__in=['finished', 'checked_out']
    ).select_related('visitor', 'card').order_by('-host_finished_at', '-updated_at')
    
    context = {
        'host': host,
        'pending_visits': pending_visits,
        'finished_visits': finished_visits,
        'pending_count': pending_visits.count(),
        'finished_count': finished_visits.count(),
    }
    
    return render(request, 'core/host_dashboard.html', context)


@login_required(login_url='login')
def secretary_dashboard(request):
    """Secretary dashboard view."""
    # Check if user has secretary profile
    if not hasattr(request.user, 'secretary_profile'):
        messages.error(request, 'You do not have access to this page.')
        return redirect('home')
    
    secretary = request.user.secretary_profile
    from django.utils import timezone
    from datetime import timedelta
    
    today = timezone.now().date()
    
    # ===== VISITS NEEDING CARD ASSIGNMENT =====
    # These are visits that:
    # - Have OTP verified (status is NOT 'pending_otp')
    # - Do NOT have a card assigned yet
    # - Have not been rejected
    needs_card = Visit.objects.filter(
        status__in=['pending_host_approval', 'approved'],
        card__isnull=True
    ).exclude(
        status='rejected'
    ).select_related('visitor', 'host__user').order_by('-created_at')
    
    # ===== VISITS READY FOR CARD COLLECTION =====
    # These are visits that:
    # - Host has finished (status = 'finished')
    # - Have a card assigned
    # - Have not been checked out yet
    needs_collection = Visit.objects.filter(
        status='finished',
        card__isnull=False
    ).select_related('visitor', 'host__user', 'card').order_by('-host_finished_at')
    
    # ===== ALL VISITS (for full list with filtering) =====
    # Get all visits except cancelled ones, ordered by most recent
    all_visits = Visit.objects.exclude(
        status='cancelled'
    ).select_related('visitor', 'host__user', 'card').order_by('-created_at')
    
    # Apply optional status filter
    status_filter = request.GET.get('status')
    if status_filter:
        all_visits = all_visits.filter(status=status_filter)
    
    # ===== STATISTICS =====
    # Today's visits
    today_visits = Visit.objects.filter(
        created_at__date=today
    )
    today_count = today_visits.count()
    today_checked_in = today_visits.exclude(check_in_time__isnull=True).count()
    today_checked_out = today_visits.filter(status='checked_out').count()
    
    # Card statistics
    available_cards = Card.objects.filter(is_available=True, is_active=True).count()
    total_cards = Card.objects.filter(is_active=True).count()
    
    context = {
        'secretary': secretary,
        # Main data for secretary functions
        'needs_card': needs_card,
        'needs_collection': needs_collection,
        'visits': all_visits,
        # Counts
        'needs_card_count': needs_card.count(),
        'needs_collection_count': needs_collection.count(),
        'total_visits_count': all_visits.count(),
        # Statistics
        'today_count': today_count,
        'today_checked_in': today_checked_in,
        'today_checked_out': today_checked_out,
        'available_cards': available_cards,
        'total_cards': total_cards,
    }
    
    return render(request, 'core/secretary_dashboard.html', context)


@login_required(login_url='login')
def admin_dashboard(request):
    """Admin dashboard view."""
    if not request.user.is_staff:
        messages.error(request, 'You do not have access to this page.')
        return redirect('home')
    
    context = {
        'total_hosts': Host.objects.count(),
        'total_secretaries': Secretary.objects.count(),
        'total_visitors': Visitor.objects.count(),
        'pending_visits': Visit.objects.filter(status='pending_host_approval').count(),
    }
    
    return render(request, 'admin/dashboard.html', context)


@require_http_methods(["GET"])
def home(request):
    """Main homepage - shows different content for logged in vs logged out users."""
    context = {}
    
    if request.user.is_authenticated:
        # Show main dashboard content
        if hasattr(request.user, 'host_profile'):
            context['user_type'] = 'host'
        elif hasattr(request.user, 'secretary_profile'):
            context['user_type'] = 'secretary'
        else:
            context['user_type'] = 'admin'
    
    return render(request, 'home.html', context)
