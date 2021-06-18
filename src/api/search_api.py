from api.api import Api


# HuBMAP Search API
# https://smart-api.info/ui/7aaf02b838022d564da776b03f357158
# NOTE: Should be derived from an OpenAPI spec
class SearchApi(Api):

    def __init__(self, user_token, api_url):
        super().__init__(user_token, api_url)

    def get_assaytype(self, data_type) -> object:
        return super().request_get_public(f"/assaytype/{data_type}")
