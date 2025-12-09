from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, authenticate, logout as auth_logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.utils import timezone
from django.db.models import Q, Count
from datetime import timedelta

from .models import Host, Secretary, Visit, Card, AuditLog
from .serializers import VisitSerializer, VisitListSerializer
from .utils import create_audit_log, get_client_ip, get_user_agent


def login_view(request):
    """Login view for hosts and secretaries."""
    if request.user.is_authenticated:
        # Redirect based on user type
        if hasattr(request.user, 'host_profile'):
            return redirect('host_dashboard')
        elif hasattr(request.user, 'secretary_profile'):
            return redirect('secretary_dashboard')
        else:
            return redirect('admin:index')
    
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            # Redirect based on user type
            if hasattr(user, 'host_profile'):
                return redirect('host_dashboard')
            elif hasattr(user, 'secretary_profile'):
                return redirect('secretary_dashboard')
            else:
                return redirect('admin:index')
        else:
            messages.error(request, 'Invalid username or password.')
    
    return render(request, 'core/login.html')


def logout_view(request):
    """
    Logout view: clears session and redirects to home.
    Also deletes DRF auth token if present.
    """
    try:
        if request.user.is_authenticated:
            from rest_framework.authtoken.models import Token
            Token.objects.filter(user=request.user).delete()
    except Exception:
        pass

    auth_logout(request)
    return redirect('/')


@login_required
def host_dashboard(request):
    """Host dashboard - view and manage visits."""
    if not hasattr(request.user, 'host_profile'):
        messages.error(request, 'You are not authorized to access this page.')
        return redirect('login')
    
    host = request.user.host_profile
    
    # Get visits for this host
    visits = Visit.objects.filter(host=host).select_related('visitor', 'card').order_by('-created_at')
    
    # Filter by status if provided
    status_filter = request.GET.get('status', '')
    if status_filter:
        visits = visits.filter(status=status_filter)
    
    # Get pending visits (need action)
    pending_visits = visits.filter(status__in=['pending_host_approval', 'approved'])
    
    # Get today's statistics
    today = timezone.now().date()
    today_visits = visits.filter(created_at__date=today)
    today_count = today_visits.count()
    today_approved = today_visits.filter(status='approved').count()
    today_finished = today_visits.filter(status='finished').count()
    
    # Get recent visits (last 7 days)
    week_ago = timezone.now() - timedelta(days=7)
    recent_visits = visits.filter(created_at__gte=week_ago)[:10]
    
    context = {
        'host': host,
        'visits': visits[:20],  # Latest 20 visits
        'pending_visits': pending_visits,
        'recent_visits': recent_visits,
        'today_count': today_count,
        'today_approved': today_approved,
        'today_finished': today_finished,
        'status_filter': status_filter,
    }
    
    return render(request, 'core/host_dashboard.html', context)


@login_required
@require_http_methods(["POST"])
def host_action_view(request, visit_id):
    """Handle host actions (approve/reject/finish) via AJAX."""
    if not hasattr(request.user, 'host_profile'):
        return JsonResponse({'error': 'Unauthorized'}, status=403)
    
    host = request.user.host_profile
    visit = get_object_or_404(Visit, id=visit_id, host=host)
    
    action = request.POST.get('action')
    
    if action == 'approve':
        instructions = request.POST.get('instructions', '')
        visit.approve_by_host(instructions)
        from .tasks import send_visitor_approved_notification
        send_visitor_approved_notification.delay(visit.id)
        create_audit_log(
            'host_approved',
            f'Host approved visit {visit.id}',
            user=request.user,
            visit=visit,
            ip_address=get_client_ip(request),
            user_agent=get_user_agent(request)
        )
        return JsonResponse({
            'success': True,
            'message': 'Visit approved successfully.',
            'status': visit.status
        })
    
    elif action == 'reject':
        reason = request.POST.get('reason', '')
        visit.reject_by_host(reason)
        from .tasks import send_visitor_rejected_notification
        send_visitor_rejected_notification.delay(visit.id)
        create_audit_log(
            'host_rejected',
            f'Host rejected visit {visit.id}',
            user=request.user,
            visit=visit,
            ip_address=get_client_ip(request),
            user_agent=get_user_agent(request)
        )
        return JsonResponse({
            'success': True,
            'message': 'Visit rejected successfully.',
            'status': visit.status
        })
    
    elif action == 'finish':
        visit.finish_by_host()
        create_audit_log(
            'host_finished',
            f'Host finished visit {visit.id}',
            user=request.user,
            visit=visit,
            ip_address=get_client_ip(request),
            user_agent=get_user_agent(request)
        )
        return JsonResponse({
            'success': True,
            'message': 'Visit marked as finished.',
            'status': visit.status
        })
    
    return JsonResponse({'error': 'Invalid action'}, status=400)


@login_required
def host_visits_api(request):
    """API endpoint for host to get their visits (AJAX)."""
    if not hasattr(request.user, 'host_profile'):
        return JsonResponse({'error': 'Unauthorized'}, status=403)
    
    host = request.user.host_profile
    visits = Visit.objects.filter(host=host).select_related('visitor', 'card').order_by('-created_at')
    
    # Apply filters
    status_filter = request.GET.get('status')
    if status_filter:
        visits = visits.filter(status=status_filter)
    
    serializer = VisitListSerializer(visits[:50], many=True)
    return JsonResponse({'visits': serializer.data})


@login_required
def secretary_dashboard(request):
    """Secretary/Admin dashboard - manage all visits and cards."""
    if not hasattr(request.user, 'secretary_profile'):
        messages.error(request, 'You are not authorized to access this page.')
        return redirect('login')
    
    secretary = request.user.secretary_profile
    
    # Get all visits
    visits = Visit.objects.select_related('visitor', 'host__user', 'card').order_by('-created_at')
    
    # Filter by status if provided
    status_filter = request.GET.get('status', '')
    if status_filter:
        visits = visits.filter(status=status_filter)
    
    # Get visits needing card assignment
    needs_card = visits.filter(status='pending_card')
    
    # Get visits waiting for card collection
    needs_collection = visits.filter(status='finished')
    
    # Get today's statistics
    today = timezone.now().date()
    today_visits = visits.filter(created_at__date=today)
    today_count = today_visits.count()
    today_checked_in = today_visits.filter(status__in=['pending_card', 'pending_host_approval', 'approved']).count()
    today_checked_out = today_visits.filter(status='checked_out').count()
    
    # Get available cards
    available_cards = Card.objects.filter(is_available=True, is_active=True).count()
    total_cards = Card.objects.filter(is_active=True).count()
    
    # Get recent visits
    recent_visits = visits[:20]
    
    # Status counts
    status_counts = visits.values('status').annotate(count=Count('id'))
    
    context = {
        'secretary': secretary,
        'visits': recent_visits,
        'needs_card': needs_card,
        'needs_collection': needs_collection,
        'today_count': today_count,
        'today_checked_in': today_checked_in,
        'today_checked_out': today_checked_out,
        'available_cards': available_cards,
        'total_cards': total_cards,
        'status_filter': status_filter,
        'status_counts': {item['status']: item['count'] for item in status_counts},
    }
    
    return render(request, 'core/secretary_dashboard.html', context)


@login_required
@require_http_methods(["POST"])
def secretary_card_action_view(request, visit_id):
    """Handle secretary card actions (assign/collect) via AJAX."""
    if not hasattr(request.user, 'secretary_profile'):
        return JsonResponse({'error': 'Unauthorized'}, status=403)
    
    secretary = request.user.secretary_profile
    visit = get_object_or_404(Visit, id=visit_id)
    
    action = request.POST.get('action')
    
    if action == 'assign':
        card_id = request.POST.get('card_id')
        if card_id:
            try:
                card = Card.objects.get(id=card_id, is_available=True, is_active=True)
            except Card.DoesNotExist:
                return JsonResponse({'error': 'Card not found or not available'}, status=404)
        else:
            from .utils import assign_card_to_visit
            card, error = assign_card_to_visit(visit, secretary)
            if not card:
                return JsonResponse({'error': error}, status=400)
        
        visit.assign_card(card, secretary)
        from .tasks import send_host_notification
        send_host_notification.delay(visit.id)
        create_audit_log(
            'card_assigned',
            f'Card {card.card_number} assigned to visit {visit.id}',
            user=request.user,
            visit=visit,
            ip_address=get_client_ip(request),
            user_agent=get_user_agent(request)
        )
        return JsonResponse({
            'success': True,
            'message': f'Card {card.card_number} assigned successfully.',
            'card_number': card.card_number,
            'status': visit.status
        })
    
    elif action == 'collect':
        if visit.status != 'finished':
            return JsonResponse({'error': 'Visit must be finished by host before card collection.'}, status=400)
        
        card_number = request.POST.get('card_number', '').strip().upper()
        if not card_number:
            return JsonResponse({'error': 'Card number is required.'}, status=400)
        
        # Verify card number matches assigned card
        if not visit.card:
            return JsonResponse({'error': 'No card assigned to this visit.'}, status=400)
        
        if visit.card.card_number.upper() != card_number:
            return JsonResponse({
                'error': f'Card number does not match. Expected: {visit.card.card_number}, Got: {card_number}'
            }, status=400)
        
        visit.check_out(secretary)
        create_audit_log(
            'card_collected',
            f'Card {card_number} collected from visit {visit.id}',
            user=request.user,
            visit=visit,
            ip_address=get_client_ip(request),
            user_agent=get_user_agent(request),
            metadata={'card_number': card_number}
        )
        return JsonResponse({
            'success': True,
            'message': f'Card {card_number} collected and visit checked out successfully.',
            'status': visit.status
        })
    
    return JsonResponse({'error': 'Invalid action'}, status=400)


@login_required
def secretary_visits_api(request):
    """API endpoint for secretary to get all visits (AJAX)."""
    if not hasattr(request.user, 'secretary_profile'):
        return JsonResponse({'error': 'Unauthorized'}, status=403)
    
    visits = Visit.objects.select_related('visitor', 'host__user', 'card').order_by('-created_at')
    
    # Apply filters
    status_filter = request.GET.get('status')
    if status_filter:
        visits = visits.filter(status=status_filter)
    
    serializer = VisitListSerializer(visits[:100], many=True)
    return JsonResponse({'visits': serializer.data})


@login_required
def secretary_cards_api(request):
    """API endpoint to get available cards."""
    if not hasattr(request.user, 'secretary_profile'):
        return JsonResponse({'error': 'Unauthorized'}, status=403)
    
    cards = Card.objects.filter(is_available=True, is_active=True).order_by('card_number')
    cards_data = [{'id': card.id, 'card_number': card.card_number} for card in cards]
    return JsonResponse({'cards': cards_data})

