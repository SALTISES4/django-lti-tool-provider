from oauthlib.oauth1 import RequestValidator as _RequestValidator


class RequestValidator(_RequestValidator):
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
        return "tmp"
