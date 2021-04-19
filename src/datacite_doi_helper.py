import os
import sys
import requests
import logging
from flask import Flask
from datetime import datetime
from requests.auth import HTTPBasicAuth

# Suppress InsecureRequestWarning warning when requesting status on https with ssl cert verify disabled
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Local modules
import dataset_helper


requests.packages.urllib3.disable_warnings(category = InsecureRequestWarning)

# Set logging fromat and level (default is warning)
# All the API logging is forwarded to the uWSGI server and gets written into the log file `uwsgo-entity-api.log`
# Log rotation is handled via logrotate on the host system with a configuration file
# Do NOT handle log file and rotation via the Python logging to avoid issues with multi-worker processes
logging.basicConfig(format = '[%(asctime)s] %(levelname)s in %(module)s: %(message)s', level = logging.DEBUG, datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger(__name__)


# In Python, "privacy" depends on "consenting adults'" levels of agreement, we can't force it.
# A single leading underscore means you're not supposed to access it "from the outside"
_datacite_repository_id = None
_datacite_repository_password = None
_datacite_hubmap_prefix = None
_datacite_api_url = None
_entity_api_url = None
_search_api_url = None


####################################################################################################
## Initialization
####################################################################################################

"""
Initialize the datacite_helper module

Read in the Flask configuration items
"""
def initialize():
    # Specify as module-scope variables
    global _datacite_repository_id
    global _datacite_repository_password
    global _datacite_hubmap_prefix
    global _datacite_api_url
    global _entity_api_url
    global _search_api_url

    config = load_flask_instance_config()

    _datacite_repository_id = config['DATACITE_REPOSITORY_ID']
    _datacite_repository_password = config['DATACITE_REPOSITORY_PASSWORD']
    _datacite_hubmap_prefix = config['DATACITE_HUBMAP_PREFIX']
    _datacite_api_url = config['DATACITE_API_URL']
    _entity_api_url = config['ENTITY_WEBSERVICE_URL']
    _search_api_url = config['SEARCH_WEBSERVICE_URL']


"""
Load the Flask instance configuration

Returns
-------
dict
    The Flask instance config
"""
def load_flask_instance_config():
    # Specify the absolute path of the instance folder and use the config file relative to the instance path
    app = Flask(__name__, instance_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'instance'), instance_relative_config = True)
    app.config.from_pyfile('app.cfg')

    # Remove trailing slash / from URL base to avoid "//" caused by config with trailing slash
    app.config['DATACITE_API_URL'] = app.config['DATACITE_API_URL'].strip('/')
    app.config['ENTITY_WEBSERVICE_URL'] = app.config['ENTITY_WEBSERVICE_URL'].strip('/')
    app.config['SEARCH_WEBSERVICE_URL'] = app.config['SEARCH_WEBSERVICE_URL'].strip('/')

    return app.config

"""
Publish the given dataset with DataCite 

Parameters
----------
dataset: dict
    The dataset dict to be published
dataset_title: str
    The dataset title, either from dataset.title or an auto generated one
user_token: str
    The user's globus nexus token

Returns
-------
dict
    The datset entity dict with updated DOI properties
"""
def publish_dataset(dataset, dataset_title, user_token):
    global _datacite_repository_id
    global _datacite_repository_password
    global _datacite_hubmap_prefix
    global _datacite_api_url
    global _entity_api_url

    if ('entity_type' in dataset) and (dataset['entity_type'] == 'Dataset'):
        # First create the DOI via DataCite
        try:
            doi_data = create_doi(dataset, dataset_title, user_token)
        except requests.exceptions.RequestException as e:
            raise requests.exceptions.RequestException(e)

        # Then update the dataset DOI properties via entity-api
        try:
            updated_dataset = update_dataset_after_doi_created(dataset_uuid, doi_data, user_token)

            return updated_dataset
        except requests.exceptions.RequestException as e:
            raise requests.exceptions.RequestException(e)
    else:
        raise KeyError('Either the entity_type of the given Dataset is missing or the entity is not a Dataset')


"""
Create DOI via DataCite 

Parameters
----------
dataset: dict
    The dataset dict to be published
dataset_title: str
    The dataset title, either from dataset.title or an auto generated one
user_token: str
    The user's globus nexus token

Returns
-------
dict
    The generated DOI information
"""
def create_doi(dataset, dataset_title, user_token):
    global _datacite_repository_id
    global _datacite_repository_password
    global _datacite_hubmap_prefix
    global _datacite_api_url

    dataset_uuid = dataset['uuid']

    doi = f"{_datacite_hubmap_prefix}/{dataset['hubmap_id']}"
    publisher = 'HuBMAP Consortium'
    publication_year = int(datetime.now().year)

    # To create a DOI in Findable state with a URL and metadata you need to include 
    # all of the required DOI metadata fields 
    # (DOI, creators, title, publisher, publicationYear, resourceTypeGeneral)
    json_to_post = {
      'data': {
        'id': dataset['hubmap_id'],
        'type': 'dois',
        'attributes': {
            # Below are all the REQUIRED attributes

            # The event action determines the DOI state: Draft, Registered, Findable
            # Possible actions:
            # publish - Triggers a state move from Draft or Registered to Findable
            # register - Triggers a state move from Draft to Registered
            # hide - Triggers a state move from Findable to Registered
            'event': 'publish', 
            # The globally unique string that identifies the resource and can't be changed
            'doi': doi,
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
            'publicationYear': publication_year, # Integer
            # The general type of the resource
            'types': {
                'resourceTypeGeneral': 'Dataset'
            },
            # The location of the landing page with more information about the resource
            'url': f"{_entity_api_url}/dataset/redirect/{dataset_uuid}"
        }
      }
    }

    logger.debug("======DOI json_to_post======")
    logger.debug(json_to_post)

    request_auth = HTTPBasicAuth(_datacite_repository_id, _datacite_repository_password)

    # Specify the MIME type type of request being sent from the client to the DataCite
    request_headers = {
        'Content-Type': 'application/vnd.api+json'
    }

    # Send the request using Basic Auth
    # Disable ssl certificate verification
    response = requests.post(url = _datacite_api_url, auth = request_auth, headers = request_headers, json = json_to_post, verify = False) 

    # Invoke .raise_for_status(), an HTTPError will be raised with certain status codes
    #response.raise_for_status()

    # Don't forget 201
    if response.status_code in [200, 201]:
        logger.info(f"======Registered DOI for dataset {dataset_uuid} via DataCite======")

        # Get the response json of resulting doi
        doi_data = response.json()['data']

        logger.debug("======resulting json from DataCite======")
        logger.debug(doi_data)

        return doi_data
    else:
        msg = f"Unable to create DOI for dataset {dataset_uuid} via DataCite" 
        
        # Log the full stack trace, prepend a line with our message
        logger.exception(msg)

        logger.debug("======status code from DataCite======")
        logger.debug(response.status_code)

        logger.debug("======response text from DataCite======")
        logger.debug(response.text)

        # Also bubble up the error message from DataCite
        raise requests.exceptions.RequestException(response.text)

"""
Update the dataset's properties after doi is created

Parameters
----------
dataset_uuid: str
    The dataset uuid
doi_data: dict
    The DataCite generated doi information
user_token: str
    The user's globus nexus token

Returns
-------
dict
    The entity dict with updated DOI properties
"""
def update_dataset_after_doi_created(dataset_uuid, doi_data, user_token):
    global _entity_api_url

    # Update the registered_doi, and doi_url properties after DOI creatiion
    # Are we also supposed to update the Dataset.status to "Published"?
    dataset_properties_to_update = {
        'registered_doi': doi_data['attributes']['doi'],
        'doi_url': doi_data['attributes']['url']
    }

    request_headers = {
        'Authorization': f"Bearer {user_token}",
        'X-Hubmap-Application': 'ingest-api'
    }

    response = requests.put(url = f"{_entity_api_url}/entities/{dataset_uuid}", headers = request_headers, json = dataset_properties_to_update, verify = False) 
    
    if response.status_code == 200:
        logger.info("======The target entity has been updated with DOI info======")

        updated_entity = response.json()

        logger.debug("======updated_entity======")
        logger.debug(updated_entity)

        return updated_entity 
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


# Running this python file as a script
# python3 -m datacite_doi_helper <user_token> <dataset_uuid>
if __name__ == "__main__":
    try:
        user_token = sys.argv[1]

        try:
            dataset_uuid = sys.argv[2]
        except IndexError as e:
            msg = "Missing dataset uuid argument"
            # Log the full stack trace, prepend a line with our message
            logger.exception(msg)
            sys.exit(msg)  
    except IndexError as e:
        msg = "Missing user token argument"
        # Log the full stack trace, prepend a line with our message
        logger.exception(msg)
        sys.exit(msg)

    initialize()

    target_url = f"{_entity_api_url}/entities/{dataset_uuid}"

    auth_header = {
        'Authorization': f"Bearer {user_token}"
    }

    response = requests.get(url = target_url, headers = auth_header,  verify = False) 

    if response.status_code == 200:

        dataset = response.json()

        logger.debug(dataset)
        
        # Generate the dataset title
        dataset_helper.initialize()
        dataset_title = dataset_helper.generate_dataset_title(dataset, user_token)

        try:
            publish_dataset(dataset, dataset_title, user_token)
        except requests.exceptions.RequestException as e:
            logger.exception(e)
    else:
        msg = f"Unable to query the target dataset with uuid: {dataset_uuid}" 
        
        # Log the full stack trace, prepend a line with our message
        logger.exception(msg)

        logger.debug("======status code from entity-api======")
        logger.debug(response.status_code)

        logger.debug("======response text from entity-api======")
        logger.debug(response.text)