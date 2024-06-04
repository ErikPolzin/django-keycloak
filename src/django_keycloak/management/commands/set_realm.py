import logging
import getpass

from django.core.management.base import BaseCommand

from django_keycloak.models import Realm, Client, Server

logger = logging.getLogger(__name__)


class Command(BaseCommand):

    def add_arguments(self, parser):
        parser.add_argument('realm_name', type=str)

    def handle(self, realm_name: str, **kwargs):
        server_url = input("Keycloak Server URL: ")
        server = Server.objects.create(url=server_url)
        realm = Realm.objects.create(server=server, name=realm_name)
        client_id = input("Client ID: ")
        client_secret = getpass.getpass("Client Secret: ")
        Client.objects.create(realm=realm, client_id=client_id, secret=client_secret)
        logger.info("Created client for realm '%s'", realm_name)
