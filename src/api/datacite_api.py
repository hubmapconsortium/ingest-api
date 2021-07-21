import requests
from requests.auth import HTTPBasicAuth
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


# DataCite REST API Guide:
# https://support.datacite.org/reference/dois-2
class DataCiteApi:

    def __init__(self, datacite_repository_id: str, datacite_repository_password: str,
                 datacite_hubmap_prefix: str, datacite_api_url: str, entity_api_url: str):
        self.auth = HTTPBasicAuth(datacite_repository_id, datacite_repository_password)
        self.datacite_hubmap_prefix = datacite_hubmap_prefix
        self.datacite_api_url = datacite_api_url
        self.redirect_prefix = f"{entity_api_url}/doi/redirect"
        self.ssl_verification_enabed = False

    def registration_doi(self, dataset_hubmap_id: str):
        return f"{self.datacite_hubmap_prefix}/{dataset_hubmap_id}"

    # https://support.datacite.org/reference/dois-2#get_dois-id
    def return_doi(self, dataset_hubmap_id: str) -> object:
        response = requests.get(
            url=f"{self.datacite_api_url}/{dataset_hubmap_id}",
            auth=self.auth,
            headers={'Accept: application/vnd.api+json'},
            verify=self.ssl_verification_enabed
        )
        return response

    # https://support.datacite.org/reference/dois-2#post_dois
    # and https://docs.python.org/3/library/typing.html
    def add_new_doi(self,
                    dataset_hubmap_id: str, dataset_uuid: str, dataset_title: str,
                    contributors: list, creators: list) -> object:
        publisher = 'HuBMAP Consortium'
        publication_year = int(datetime.now().year)

        # Draft DOI doesn't specify the 'event' attribute
        json = {
            'data': {
                'id': dataset_hubmap_id,
                'type': 'dois',
                'attributes': {
                    'event': 'register',
                    # Below are all the "Manditory" properties. See:
                    # https://schema.datacite.org/meta/kernel-4.3/doc/DataCite-MetadataKernel_v4.3.pdf#%5B%7B%22num%22%3A19%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22XYZ%22%7D%2C68%2C549%2C0%5D

                    # The globally unique string that identifies the resource and can't be changed
                    'doi': self.registration_doi(dataset_hubmap_id),
                    # One or more names or titles by which the resource is known
                    'titles': [{
                        'title': dataset_title
                    }],
                    # The name of the entity that holds, archives, publishes prints, distributes,
                    # releases, issues, or produces the resource
                    'publisher': publisher,
                    # The year when the resource was or will be made publicly available
                    'publicationYear': publication_year,  # Integer
                    # The general type of the resource
                    'types': {
                        'resourceTypeGeneral': 'Dataset'
                    },
                    # The location of the landing page with more information about the resource
                    'url': f"{self.redirect_prefix}/{dataset_uuid}"
                }
            }
        }

        # <Orchid_ID, first, lastname, name, institution_affiliation> from Dataset.contributors is mapped here (see reference above)
        if contributors is not None:
            json['data']['attributes']['contributors'] = contributors

        if creators is not None:
            json['data']['attributes']['creators'] = creators

        logger.debug("======Draft DOI json_to_post======")
        logger.debug(json)

        response = requests.post(
            url=self.datacite_api_url,
            auth=self.auth,
            headers={'Content-Type': 'application/vnd.api+json'},
            json=json,
            verify=self.ssl_verification_enabed
        )
        return response

    # https://support.datacite.org/reference/dois-2#put_dois-id
    def update_doi_event_publish(self, dataset_hubmap_id: str) -> object:
        doi = self.registration_doi(dataset_hubmap_id)
        json = {
            'data': {
                'id': doi,
                'type': 'dois',
                'attributes': {
                    'event': 'publish'
                }
            }
        }

        logger.debug("====== DataCiteApi.update_doi_event_publish() json ======")
        logger.debug(json)

        response = requests.put(
            url=f"{self.datacite_api_url}/{doi}",
            auth=self.auth,
            headers={'Content-Type': 'application/vnd.api+json'},
            json=json,
            verify=self.ssl_verification_enabed
        )
        return response
