import getpass

from django.core.management.base import BaseCommand

from django_keycloak.models import Realm, Client


class Command(BaseCommand):

    def add_arguments(self, parser):
        parser.add_argument('realm_name', type=str)

    def handle(self, realm_name: str, **kwargs):
        try:
            realm = Realm.objects.get(name=realm_name)
        except Realm.DoesNotExist:
            self.stderr.write(f"No realm called '{realm_name}'")
            return
        client_id = input("Client ID: ")
        client_secret = getpass.getpass("Client Secret [optional]: ") or None
        Client.objects.create(realm=realm,
                              client_id=client_id,
                              secret=client_secret)
        self.stdout.write(f"Created client for realm '{realm_name}'")
