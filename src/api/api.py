import requests


class Api(object):

    def __init__(self, user_token: str, api_url: str):
        self.headers = {
            'Authorization': f"Bearer {user_token}",
            'Content-Type': 'application/json'
        }
        self.headers_hubmap_application = {
            'Authorization': f"Bearer {user_token}",
            'Content-Type': 'application/json',
            'X-Hubmap-Application': 'ingest-api'
        }
        self.api_url = api_url
        self.verify_server_tls_certificate = False

    def request_get(self, url_path: str) -> object:
        return requests.get(
            url=f"{self.api_url}{url_path}",
            headers=self.headers,
            verify=self.verify_server_tls_certificate
        )

    def request_get_public(self, url_path: str) -> object:
        return requests.get(
            url=f"{self.api_url}{url_path}",
            verify=self.verify_server_tls_certificate
        )

    def request_put(self, url_path: str, json: object) -> object:
        return requests.get(
            url=f"{self.api_url}{url_path}",
            json=json,
            headers=self.headers_hubmap_application,
            verify=self.verify_server_tls_certificate
        )
