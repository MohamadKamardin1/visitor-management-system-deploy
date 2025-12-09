from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from core.models import Host


class Command(BaseCommand):
    help = 'Create a host user'

    def add_arguments(self, parser):
        parser.add_argument('username', type=str, help='Username')
        parser.add_argument('email', type=str, help='Email')
        parser.add_argument('phone', type=str, help='Phone number')
        parser.add_argument('--first-name', type=str, default='', help='First name')
        parser.add_argument('--last-name', type=str, default='', help='Last name')
        parser.add_argument('--department', type=str, default='', help='Department')
        parser.add_argument('--office', type=str, default='', help='Office location')

    def handle(self, *args, **options):
        username = options['username']
        email = options['email']
        phone = options['phone']
        
        # Create or get user
        user, created = User.objects.get_or_create(
            username=username,
            defaults={
                'email': email,
                'first_name': options['first_name'],
                'last_name': options['last_name'],
            }
        )
        
        if not created:
            self.stdout.write(self.style.WARNING(f'User {username} already exists'))
        
        # Create host profile
        host, created = Host.objects.get_or_create(
            user=user,
            defaults={
                'phone_number': phone,
                'department': options['department'],
                'office_location': options['office'],
            }
        )
        
        if created:
            self.stdout.write(
                self.style.SUCCESS(f'Successfully created host: {username}')
            )
        else:
            self.stdout.write(self.style.WARNING(f'Host for {username} already exists'))






