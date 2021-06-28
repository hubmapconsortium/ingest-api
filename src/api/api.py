import requests


class Api(object):

    def __init__(self, user_token, api_url):
        self.auth_header = {
            'Authorization': f"Bearer {user_token}"
        }
        self.api_url = api_url
        self.verify_server_tls_certificate = False

    def request_get(self, url_path) -> object:
        return requests.get(
            url=f"{self.api_url}{url_path}",
            headers=self.auth_header,
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
            headers=self.auth_header,
            verify=self.verify_server_tls_certificate
        )
