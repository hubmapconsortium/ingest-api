import requests


class Api(object):

    def __init__(self, user_token, api_url):
        self.headers = {
            'Authorization': f"Bearer {user_token}",
            # Won't need this header for calls to search-api - Zhou 
            'Content-Type': 'application/json',
            # Only need this X-Hubmap-Application header on updating the Dataset.status
            # via entity-api using a PUT call - Zhou
            'X-Hubmap-Application': 'ingest-api'
        }
        self.api_url = api_url
        self.verify_server_tls_certificate = False

    def request_get(self, url_path) -> object:
        return requests.get(
            url=f"{self.api_url}{url_path}",
            headers=self.headers,
            verify=self.verify_server_tls_certificate
        )

    def request_get_public(self, url_path) -> object:
        return requests.get(
            url=f"{self.api_url}{url_path}",
            verify=self.verify_server_tls_certificate
        )

    def request_put(self, url_path, json) -> object:
        return requests.get(
            url=f"{self.api_url}{url_path}",
            json=json,
            headers=self.headers,
            verify=self.verify_server_tls_certificate
        )
