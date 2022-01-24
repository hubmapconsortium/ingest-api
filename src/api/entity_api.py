from api.api import Api


# HuBMAP Entity API
# https://smart-api.info/ui/0065e419668f3336a40d1f5ab89c6ba3#/
# NOTE: Should be made from an OpenAPI spec
class EntityApi(Api):

    def __init__(self, user_token: str, api_url: str):
        super().__init__(user_token, api_url)

    def post_entities(self, dataset_uuid: str, json: object, extra_headers: dict = {}) -> object:
        return super().request_post(f"entities/{dataset_uuid}", json, extra_headers)

    def put_entities(self, dataset_uuid: str, json: object, extra_headers: dict = {}) -> object:
        return super().request_put(f"entities/{dataset_uuid}", json, extra_headers)

    def get_entities(self, dataset_uuid: str) -> object:
        return super().request_get(f"entities/{dataset_uuid}")

    def get_ancestors(self, dataset_uuid: str) -> object:
        return super().request_get(f"ancestors/{dataset_uuid}")
