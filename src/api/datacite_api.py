import requests
from requests.auth import HTTPBasicAuth
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


# DataCite REST API Guide:
# https://support.datacite.org/docs/api
class DataCiteApi:

    def __init__(self, datacite_repository_id: str, datacite_repository_password: str,
                 datacite_hubmap_prefix: str, datacite_api_url: str, entity_api_url: str):
        self.auth = HTTPBasicAuth(datacite_repository_id, datacite_repository_password)
        self.headers = {'Content-Type': 'application/vnd.api+json'}
        self.datacite_hubmap_prefix = datacite_hubmap_prefix
        self.datacite_api_url = datacite_api_url
        self.redirect_prefix = f"{entity_api_url}/doi/redirect"
        self.ssl_verification_enabed = False

    def registration_doi(self, dataset_hubmap_id: str):
        return f"{self.datacite_hubmap_prefix}/{dataset_hubmap_id}"

    def post_create_draft_doi(self, dataset_hubmap_id: str, dataset_uuid: str, dataset_title: str) -> object:
        publisher = 'HuBMAP Consortium'
        publication_year = int(datetime.now().year)

        # Draft DOI doesn't specify the 'event' attribute
        json_to_post = {
            'data': {
                'id': dataset_hubmap_id,
                'type': 'dois',
                'attributes': {
                    # Below are all the "Manditory" properties. See:
                    # https://schema.datacite.org/meta/kernel-4.3/doc/DataCite-MetadataKernel_v4.3.pdf#%5B%7B%22num%22%3A19%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22XYZ%22%7D%2C68%2C549%2C0%5D

                    # The globally unique string that identifies the resource and can't be changed
                    'doi': self.registration_doi(dataset_hubmap_id),
                    # The main researchers or organizations involved in producing the resource, in priority order
                    # Will use Dataset.contributors as creators once available
                    'creators': [{
                        'name': "HuBMAP"
                    }],
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

        logger.debug("======Draft DOI json_to_post======")
        logger.debug(json_to_post)

        response = requests.post(
            url=self.datacite_api_url,
            auth=self.auth,
            headers=self.headers,
            json=json_to_post,
            verify=self.ssl_verification_enabed
        )
        return response

    def put_publish_doi(self, dataset_hubmap_id: str) -> object:
        doi = self.registration_doi(dataset_hubmap_id)
        json_to_post = {
            'data': {
                'id': doi,
                'type': 'dois',
                'attributes': {
                    # Trigger a state move from Draft to Findable
                    'event': 'publish'
                }
            }
        }

        logger.debug("======DOI [draft -> findable] json_to_post======")
        logger.debug(json_to_post)

        response = requests.put(
            url=f"{self.datacite_api_url}/{doi}",
            auth=self.auth,
            headers=self.headers,
            json=json_to_post,
            verify=self.ssl_verification_enabed
        )
        return response
