from django.core.management.base import BaseCommand

from django_keycloak.models import Realm


class Command(BaseCommand):

    def add_arguments(self, parser):
        parser.add_argument('realm_name', type=str)

    def handle(self, realm_name: str, **kwargs):
        server_url = input("Keycloak Server URL: ")
        realm = Realm.objects.create(server=server_url, name=realm_name)
        self.stdout.write(f"Created client for realm '{realm.name}'")
