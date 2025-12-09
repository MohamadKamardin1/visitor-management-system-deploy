from django.core.management.base import BaseCommand
from core.models import Card


class Command(BaseCommand):
    help = 'Generate a specified number of cards'

    def add_arguments(self, parser):
        parser.add_argument(
            'count',
            type=int,
            help='Number of cards to generate',
        )

    def handle(self, *args, **options):
        count = options['count']
        created = 0
        
        for _ in range(count):
            card_number = Card.generate_card_number()
            card = Card.objects.create(card_number=card_number)
            created += 1
            self.stdout.write(
                self.style.SUCCESS(f'Created card: {card.card_number}')
            )
        
        self.stdout.write(
            self.style.SUCCESS(f'Successfully created {created} cards')
        )






