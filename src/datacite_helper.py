import os
import sys
import requests
import logging
from flask import Flask
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


# In Python, "privacy" depends on "consenting adults'" levels of agreement, we can't force it.
# A single leading underscore means you're not supposed to access it "from the outside"
_datacite_repository_id = None
_datacite_repository_password = None
_datacite_hubmap_prefix = None
_datacite_api_url = None
_entity_api_url = None
_search_api_url = None


####################################################################################################
## Provenance yaml schema initialization
####################################################################################################

"""
Initialize the datacite_manager module

Parameters
----------
valid_yaml_file : file
    A valid yaml file
neo4j_session_context : neo4j.Session object
    The neo4j database session
"""
def initialize():
    # Specify as module-scope variables
    global _datacite_repository_id
    global _datacite_repository_password
    global _datacite_hubmap_prefix
    global _datacite_api_url
    global _entity_api_url
    global _search_api_url

    # Specify the absolute path of the instance folder and use the config file relative to the instance path
    app = Flask(__name__, instance_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'instance'), instance_relative_config = True)
    app.config.from_pyfile('app.cfg')

    _datacite_repository_id = app.config['DATACITE_REPOSITORY_ID']
    _datacite_repository_password = app.config['DATACITE_REPOSITORY_PASSWORD']
    _datacite_hubmap_prefix = app.config['DATACITE_HUBMAP_PREFIX']
    _datacite_api_url = app.config['DATACITE_API_URL']
    _entity_api_url = app.config['ENTITY_WEBSERVICE_URL']
    _search_api_url = app.config['SEARCH_WEBSERVICE_URL']


"""
Publish the given dataset with DataCite 

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
def publish_dataset(dataset, user_token):
    global _datacite_repository_id
    global _datacite_repository_password
    global _datacite_hubmap_prefix
    global _datacite_api_url
    global _entity_api_url

    if ('entity_type' in dataset) and (dataset['entity_type'] == 'Dataset'):
        dataset_uuid = dataset['uuid']

        doi = f"{_datacite_hubmap_prefix}/{dataset['hubmap_id']}"
        publisher = 'HuBMAP Consortium'

        # To create a DOI in Findable state with a URL and metadata you need to include 
        # all of the required DOI metadata fields 
        # (DOI, creators, title, publisher, publicationYear, resourceTypeGeneral)
        json_to_post = {
          'data': {
            'id': dataset['hubmap_id'],
            'type': 'dois',
            'attributes': {
                'event': 'publish', # The DOI state will be 'findable'
                'doi': doi,
                'creators': [{
                    'name': "HuBMAP"
                }],
                'titles': [{
                    'title': generate_dataset_title(dataset, user_token)
                }],
                'publisher': publisher,
                'publicationYear': 2021,
                'types': {
                    'resourceTypeGeneral': 'Dataset'
                }
            }
          }
        }

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
            logger.info("======Published dataset via DataCite======")
   
            # Get the response json of resulting doi
            doi_data = response.json()['data']

            logger.debug("======resulting json from DataCite======")
            logger.debug(doi_data)

            try:
                # Update the dataset properties via entity-api
                update_dataset_after_doi_created(dataset_uuid, doi_data, user_token, _entity_api_url)
            except requests.exceptions.RequestException as e:
                # Bubble up the error
                raise requests.exceptions.RequestException(e)
        else:
            msg = f"Unable to publish dataset {dataset_uuid} via DataCite" 
            
            # Log the full stack trace, prepend a line with our message
            logger.exception(msg)

            logger.debug("======status code from DataCite======")
            logger.debug(response.status_code)

            logger.debug("======response text from DataCite======")
            logger.debug(response.text)
    else:
        raise KeyError('The entity_type of the given dataset is not Dataset')

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
"""
def update_dataset_after_doi_created(dataset_uuid, doi_data, user_token):
    global _entity_api_url

    # Update the registered_doi, doi_url, and has_doi properties after DOI creatiion
    # Are we also supposed to update the Dataset.status to "Published"?
    dataset_properties_to_update = {
        'registered_doi': doi_data['attributes']['doi'],
        'doi_url': doi_data['attributes']['url'],
        'has_doi': True
    }

    request_headers = {
        'Authorization': f"Bearer {user_token}",
        'X-Hubmap-Application': 'ingest-api'
    }

    response = requests.put(url = f"{_entity_api_url}/entities/{dataset_uuid}", headers = request_headers, json = dataset_properties_to_update, verify = False) 
    
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

"""
Create a dataset name, store it in the Dataset.title field. Based on this template:
"<Assay Type> data from the <organ name> of a <years old> year old <race> <sex>.

For Example: "Bulk ATAC-seq data from the liver of a 63 year old white male."

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
str
    The generated title string
"""
def generate_dataset_title(dataset, user_token):
    assay_type_desc = '<assay_type_desc>'
    organ_name = '<organ_name>'
    age = '<age>'
    race = '<race>'
    sex = '<sex>'

    ancestors = get_dataset_ancestors(dataset['uuid'], user_token)

    for ancestor in ancestors:
        if (ancestor['entity_type'] == 'Sample') and (ancestor['specimen_type'].lower() == 'organ'):
            organ_name = ancestor['organ']

        if (ancestor['entity_type'] == 'Donor' and ('metadata' in ancestor)):
            if 'organ_donor_data' in ancestor['metadata']:
                data_list = ancestor['metadata']['organ_donor_data']

                for data in data_list:
                    if 'grouping_concept_preferred_term' in data:
                        if data['grouping_concept_preferred_term'].lower() == 'age':
                            sex = data['preferred_term']

                        if data['grouping_concept_preferred_term'].lower() == 'race':
                            sex = data['preferred_term']

                        if data['grouping_concept_preferred_term'].lower() == 'sex':
                            sex = data['preferred_term']

    if ('ingest_metadata' in dataset) and ('metadata' in dataset['ingest_metadata']):
        metadata = dataset['ingest_metadata']['metadata']
        if 'assay_type' in dataset['ingest_metadata']['metadata']:
            assay_type = dataset['ingest_metadata']['metadata']['assay_type']

            try:
                assay_type_desc = get_assay_type_desc(assay_type)
            except requests.exceptions.RequestException as e:
                # Bubble up the error
                raise requests.exceptions.RequestException(e)

    title = f"{assay_type_desc} data from the {organ_name} of a {age} year old {race} {sex}"

    return title


"""
Get the description of a given assay type

Parameters
----------
assay_type: str
    The assay type name

Returns
-------
str
    The description of the target assay type
"""
def get_assay_type_desc(assay_type):
    global _search_api_url

    target_url = f"{_search_api_url}/assaytype/{assay_type}"
    
    # The assaytype endpoint in search-api is public accessible, no token needed
    response = requests.get(url = target_url, verify = False) 

    if response.status_code == 200:

        assay_type_info = response.json()

        logger.debug(assay_type_info)

        return assay_type_info['description']
    else:
        msg = f"Unable to query the assay type: {assay_type} via search-api" 
        
        # Log the full stack trace, prepend a line with our message
        logger.exception(msg)

        logger.debug("======status code from search-api======")
        logger.debug(response.status_code)

        logger.debug("======response text from search-api======")
        logger.debug(response.text)

def get_dataset_ancestors(dataset_uuid, user_token):
    global _entity_api_url

    target_url = f"{_entity_api_url}/ancestors/{dataset_uuid}"

    auth_header = {
        'Authorization': f"Bearer {user_token}"
    }

    response = requests.get(url = target_url, headers = auth_header,  verify = False) 

    if response.status_code == 200:

        ancestors = response.json()

        logger.debug(ancestors)

        return ancestors
    else:
        msg = f"Unable to get the ancestors of dataset with uuid: {dataset_uuid}" 
        
        # Log the full stack trace, prepend a line with our message
        logger.exception(msg)

        logger.debug("======status code from entity-api======")
        logger.debug(response.status_code)

        logger.debug("======response text from entity-api======")
        logger.debug(response.text)


# Running this python file as a script
# python3 datacite.py <user_token> <dataset_uuid>
if __name__ == "__main__":
    global _entity_api_url

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

        try:
            publish_dataset(dataset, user_token)
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