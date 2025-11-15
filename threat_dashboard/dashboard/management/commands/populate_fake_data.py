from django.core.management.base import BaseCommand
from dashboard.utils import generate_fake_threats, generate_fake_statistics

class Command(BaseCommand):
    help = 'Populate database with fake threat data for testing'

    def add_arguments(self, parser):
        parser.add_argument(
            '--threats',
            type=int,
            default=50,
            help='Number of fake threats to generate'
        )
        parser.add_argument(
            '--days',
            type=int,
            default=30,
            help='Number of days of statistics to generate'
        )

    def handle(self, *args, **options):
        threats_count = options['threats']
        days_count = options['days']
        
        self.stdout.write('Generating fake threat data...')
        
        # Generate threats
        threats_created = generate_fake_threats(threats_count)
        self.stdout.write(
            self.style.SUCCESS(f'Successfully created {threats_created} fake threats')
        )
        
        # Generate statistics
        stats_created = generate_fake_statistics(days_count)
        self.stdout.write(
            self.style.SUCCESS(f'Successfully created {stats_created} days of statistics')
        )
        
        self.stdout.write(
            self.style.SUCCESS('Fake data population complete!')
        )