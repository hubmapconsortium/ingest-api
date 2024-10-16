import requests
from requests.auth import HTTPBasicAuth
import logging

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

    # https://support.datacite.org/docs/doi-basics
    def build_doi_name(self, entity_hubmap_id: str):
        # Format: prefix/suffix, no need for proxy part
        return f"{self.datacite_hubmap_prefix}/{entity_hubmap_id}"

    # DOI retrieval
    # https://support.datacite.org/reference/dois-2#get_dois-id
    def get_doi_by_id(self, doi_id: str) -> object:
        logger.debug(f"======Target DOI ID: {doi_id}======")

        response = requests.get(
            url=f"{self.datacite_api_url}/{doi_id}",
            auth=self.auth,
            headers={'Content-Type': 'application/vnd.api+json'},
            verify=self.ssl_verification_enabed
        )
        return response

    # https://support.datacite.org/reference/dois-2#post_dois
    # and https://docs.python.org/3/library/typing.html
    def create_new_draft_doi(self,
                    hubmap_id: str, 
                    uuid: str,
                    contributors: list, 
                    title: str,
                    publication_year: int,
                    creators: list,
                    entity_type='Dataset') -> object:
        publisher = 'HuBMAP Consortium'

        # Draft DOI doesn't specify the 'event' attribute
        json = {
            'data': {
                'id': hubmap_id,
                'type': 'dois',
                'attributes': {
                    # ==============ATTENTION==============
                    # Do NOT add 'event' field in order to create a "Draft" DOI
                    # Do NOT specify 'event': 'register', this creates a "Registered" DOI directly or
                    # triggers a state move from "Draft" to "Registered" and this DOI can not be deleted nor returned to the "Draft" state
                    # Do NOT specify 'event': 'publish', this creates a "Findable" DOI directly or
                    # triggers a state move from "Draft" or "Registered" to "Findable" and this DOI can not be deleted nor returned to a different state
                    # =====================================

                    # Below are all the "Manditory" properties. See:
                    # https://schema.datacite.org/meta/kernel-4.3/doc/DataCite-MetadataKernel_v4.3.pdf#%5B%7B%22num%22%3A19%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22XYZ%22%7D%2C68%2C549%2C0%5D

                    # The globally unique string that identifies the resource and can't be changed
                    'doi': self.build_doi_name(hubmap_id),
                    # One or more names or titles by which the resource is known
                    'titles': [{
                        'title': title
                    }],
                    # The name of the entity that holds, archives, publishes prints, distributes,
                    # releases, issues, or produces the resource
                    'publisher': publisher,
                    # The year when the resource was or will be made publicly available
                    'publicationYear': publication_year,  # Integer
                    # The general type of the resource
                    'types': {
                        'resourceTypeGeneral': entity_type
                    },
                    # The location of the landing page with more information about the resource
                    'url': f"{self.redirect_prefix}/{uuid}"
                }
            }
        }

        # <Orchid_ID, first, lastname, name, institution_affiliation> from Dataset.contributors is mapped here (see reference above)
        if contributors is not None:
            json['data']['attributes']['contributors'] = contributors

        if creators is not None:
            json['data']['attributes']['creators'] = creators

        logger.debug("======Draft DOI json_to_post======")
        #logger.debug(json)

        response = requests.post(
            url=self.datacite_api_url,
            auth=self.auth,
            headers={'Content-Type': 'application/vnd.api+json'},
            json=json,
            verify=self.ssl_verification_enabed
        )
        return response

    # https://support.datacite.org/reference/dois-2#put_dois-id
    def update_doi_event_publish(self, entity_hubmap_id: str) -> object:
        doi = self.build_doi_name(entity_hubmap_id)
        json = {
            'data': {
                'id': doi,
                'type': 'dois',
                'attributes': {
                    # Triggers a state move from "Draft" or "Registered" to "Findable"
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
