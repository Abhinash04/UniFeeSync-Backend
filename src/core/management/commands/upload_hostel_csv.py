# core/management/commands/upload_hostel_csv.py

import csv
from django.core.management.base import BaseCommand
from core.models import User  # adjust if your model is elsewhere

class Command(BaseCommand):
    help = 'Upload hostel student data from a CSV file'

    def add_arguments(self, parser):
        parser.add_argument('csv_file', type=str)

    def handle(self, *args, **kwargs):
        csv_file = kwargs['csv_file']
        with open(csv_file, newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                email = row.get('email')
                name = row.get('name')

                if User.objects.filter(email=email).exists():
                    self.stdout.write(self.style.WARNING(f"User with email {email} already exists."))
                else:
                    user = User.objects.create_user(email=email, name=name)
                    user.must_reset_password = True
                    user.set_unusable_password()  # Makes sure they can't log in yet
                    user.save()
                    self.stdout.write(self.style.SUCCESS(f"Created user: {email}"))
