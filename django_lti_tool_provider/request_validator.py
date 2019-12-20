from django.conf import settings
from oauthlib.oauth1 import RequestValidator as _RequestValidator


class RequestValidator(_RequestValidator):
    @property
    def enforce_ssl(self):
        return False

    def validate_timestamp_and_nonce(
        self,
        client_key,
        timestamp,
        nonce,
        request,
        request_token=None,
        access_token=None,
    ):
        return True

    def validate_client_key(self, client_key, request):
        return True

    def get_client_secret(self, client_key, request):
        return unicode(settings.LTI_CLIENT_SECRET)

    def check_client_key(self, client_key):
        return True
