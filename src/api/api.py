import requests


class Api(object):

    def __init__(self, user_token: str, api_url: str):
        self.headers = {
            'Authorization': f"Bearer {user_token}"
        }
        self.api_url = api_url
        self.verify_server_tls_certificate = False

    def add_extra_headers(self, extra_headers: object) -> object:
        # Merge the new headers into the existing headers
        # A header with the same name will be overwritten by the ones from headers_to_add
        if extra_headers is None:
            return self.headers
        return {**self.headers, **extra_headers}

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

    def request_post(self, url_path: str, json: object, extra_headers=None) -> object:
        return requests.post(
            url=f"{self.api_url}{url_path}",
            json=json,
            headers=self.add_extra_headers(extra_headers),
            verify=self.verify_server_tls_certificate
        )

    def request_put(self, url_path: str, json: object, extra_headers=None) -> object:
        return requests.put(
            url=f"{self.api_url}{url_path}",
            json=json,
            headers=self.add_extra_headers(extra_headers),
            verify=self.verify_server_tls_certificate
        )
