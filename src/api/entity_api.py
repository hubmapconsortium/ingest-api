from api.api import Api


# HuBMAP Entity API
# https://smart-api.info/ui/0065e419668f3336a40d1f5ab89c6ba3#/
# NOTE: Should be made from an OpenAPI spec
class EntityApi(Api):

    def __init__(self, user_token: str, api_url: str):
        super().__init__(user_token, api_url)

    def get_entities(self, dataset_uuid: str) -> object:
        return super().request_get(f"/entities/{dataset_uuid}")

    def put_entities(self, dataset_uuid: str, json: object) -> object:
        return super().request_put(f"/entities/{dataset_uuid}", json)

    def get_entity_types(self, dataset_uuid: str) -> object:
        return super().request_get(f"/entity-types/{dataset_uuid}")

    def get_ancestors(self, dataset_uuid: str) -> object:
        return super().request_get(f"/ancestors/{dataset_uuid}")

    def get_descendants(self, dataset_uuid: str) -> object:
        return super().request_get(f"/descendants/{dataset_uuid}")

    def get_patients(self, dataset_uuid: str) -> object:
        return super().request_get(f"/patients/{dataset_uuid}")

    def get_children(self, dataset_uuid: str) -> object:
        return super().request_get(f"/children/{dataset_uuid}")

    def get_entities_provenance(self, dataset_uuid: str) -> object:
        return super().request_get(f"/entities/{dataset_uuid}/provenance")

    def get_entities_ancestor_organs(self, dataset_uuid: str) -> object:
        return super().request_get(f"/entities/{dataset_uuid}/ancestor-organs")

    def get_collections(self, dataset_uuid: str) -> object:
        return super().request_get(f"/collections/{dataset_uuid}")

    def put_collections_add_datasets(self, collections_uuid: str, json) -> object:
        return super().request_put(f"/collections{collections_uuid}/add-datasets", json)

    def get_doi_redirect(self, dataset_uuid: str) -> object:
        return super().request_get(f"/doi/redirect/{dataset_uuid}")

    def get_entities_globus_url(self, dataset_uuid: str) -> object:
        return super().request_get(f"/entities/{dataset_uuid}/globus-url")
