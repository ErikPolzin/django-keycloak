import getpass

from django.core.management.base import BaseCommand

from django_keycloak.models import Realm, Client


class Command(BaseCommand):

    def add_arguments(self, parser):
        parser.add_argument('client_id', type=str)

    def handle(self, client_id: str, **kwargs):
        realm = Realm.objects.first()
        if realm is None:
            self.stderr.write("No realm found")
            return
        client_secret = getpass.getpass("Client Secret [optional]: ") or None
        Client.objects.create(realm=realm,
                              client_id=client_id,
                              secret=client_secret)
        self.stdout.write(f"Created client for realm '{client_id}'")
