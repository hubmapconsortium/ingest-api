import requests
import logging

from requests.auth import HTTPBasicAuth

# Suppress InsecureRequestWarning warning when requesting status on https with ssl cert verify disabled
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(category = InsecureRequestWarning)

# Set logging fromat and level (default is warning)
# All the API logging is forwarded to the uWSGI server and gets written into the log file `uwsgo-entity-api.log`
# Log rotation is handled via logrotate on the host system with a configuration file
# Do NOT handle log file and rotation via the Python logging to avoid issues with multi-worker processes
logging.basicConfig(format='[%(asctime)s] %(levelname)s in %(module)s: %(message)s', level=logging.DEBUG, datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger(__name__)


# Configurations
DATACITE_API_URL = 'https://api.test.datacite.org/dois'
HUBMAP_PREFIX = '10.80478'
ENTITY_API_URL = 'https://entity-api.dev.hubmapconsortium.org/'

# Remove trailing slash / from URL base to avoid "//" 
ENTITY_API_URL = ENTITY_API_URL.strip('/')

"""
Register the given dataset with DataCite 

Parameters
----------
dataset: dict
    The dataset dict to be registered
user_token: str
    The user's globus nexus token

Returns
-------
list
    The list of new ids dicts, the number of dicts is based on the count
"""
def register_dataset(dataset, user_token, datacite_repository_id, datacite_repository_password):
    if ('entity_type' in dataset) and (dataset['entity_type'] == 'Dataset'):
        json_to_post = {
          'data': {
            'id': dataset['hubmap_id'],
            'type': 'dois',
            'attributes': {
              'event': 'publish',
              'doi': f"{HUBMAP_PREFIX}/{dataset['hubmap_id']}",
              # 'creators': dataset['creators'] if ('creators' in dataset) else [],
              # 'titles': [{
              #   'title': dataset['title'] if ('title' in dataset) else 'Default title placeholder'
              # }],
              'creators': [{
                'name': "DataCite Metadata Working Group"
              }],
              'titles': [{
                'title': "DataCite Metadata Schema Documentation for the Publication and Citation of Research Data v4.0"
              }],
              'publisher': 'HuBMAP Consortium',
              'publicationYear': 2021,
              'types': {
                'resourceTypeGeneral': 'Dataset'
              },
              'url': 'https://schema.datacite.org/meta/kernel-4.0/index.html',
              'schemaVersion': 'http://datacite.org/schema/kernel-4'
            }
          }
        }

        logger.debug(json_to_post)

        request_auth = HTTPBasicAuth(datacite_repository_id, datacite_repository_password)

        # Specify the MIME type type of request being sent from the client to the DataCite
        request_headers = {
            'Content-Type': 'application/vnd.api+json'
        }

        # Send the request using Basic Auth
        # Disable ssl certificate verification
        response = requests.post(url = DATACITE_API_URL, auth = request_auth, headers = request_headers, json = json_to_post, verify = False) 

        # Invoke .raise_for_status(), an HTTPError will be raised with certain status codes
        #response.raise_for_status()

        if response.status_code == 200:
            logger.info("======registered DOI via DataCite======")

            # Get the response json of resulting doi
            doi_data = response.json()

            dataset_uuid = dataset['uuid']

            try:
                # Update the doi properties via entity-api
                update_dataset_doi_info(dataset_uuid, doi_data, user_token)
            except requests.exceptions.RequestException as e:
                # Bubble up the error
                raise requests.exceptions.RequestException(e)
        else:
            msg = f"Unable to register DOIs via DataCite" 
            
            # Log the full stack trace, prepend a line with our message
            logger.exception(msg)

            logger.debug("======status code from DataCite======")
            logger.debug(response.status_code)

            logger.debug("======response text from DataCite======")
            logger.debug(response.text)

            # Also bubble up the error message from DataCite
            raise requests.exceptions.RequestException(response.text)
    else:
        raise KeyError('The entity_type of the given dataset is not Dataset')

"""
Update the dataset's doi properties

Parameters
----------
dataset_uuid: str
    The dataset uuid
doi_data: dict
    The DataCite generated doi information
user_token: str
    The user's globus nexus token
"""
def update_dataset_doi_info(dataset_uuid, doi_data, user_token):
    # Update the registered_doi, doi_url, and has_doi properties after DOI creatiion
    dataset_properties_to_update = {
        'registered_doi': doi_data['attributes']['doi'],
        'doi_url': doi_data['attributes']['url'],
        'has_doi': True
    }

    request_headers = {
        'Authorization': f"Bearer {user_token}",
        'X-Hubmap-Application': 'ingest-api'
    }

    response = requests.put(url = f"{ENTITY_API_URL}/entities/{dataset_uuid}", headers = request_headers, json = dataset_properties_to_update, verify = False) 
    
    if response.status_code == 200:
        logger.info("======The target entity has been updated with DOI info======")
    else:
        msg = f"Unable to update the DOI properties of dataset {dataset_uuid}" 
        
        # Log the full stack trace, prepend a line with our message
        logger.exception(msg)

        logger.debug("======status code from entity-api======")
        logger.debug(response.status_code)

        logger.debug("======response text from entity-api======")
        logger.debug(response.text)

        # Also bubble up the error message from entity-api
        raise requests.exceptions.RequestException(response.text)