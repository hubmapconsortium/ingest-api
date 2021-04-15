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
def register_dataset(dataset, user_token, datacite_repository_id, datacite_repository_password, datacite_api_url, datacite_hubmap_prefix, entity_api_url):
    if ('entity_type' in dataset) and (dataset['entity_type'] == 'Dataset'):
        json_to_post = {
          'data': {
            'id': dataset['hubmap_id'],
            'type': 'dois',
            'attributes': {
              'event': 'publish',
              'doi': f"{datacite_hubmap_prefix}/{dataset['hubmap_id']}",
              # 'creators': dataset['creators'] if ('creators' in dataset) else [],
              'creators': [{
                'name': "DataCite Metadata Working Group"
              }],
              'titles': [{
                'title': dataset['title'] if ('title' in dataset) else 'Default title placeholder'
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
        response = requests.post(url = datacite_api_url, auth = request_auth, headers = request_headers, json = json_to_post, verify = False) 

        # Invoke .raise_for_status(), an HTTPError will be raised with certain status codes
        #response.raise_for_status()

        # Don't forget 201
        if response.status_code in [200, 201]:
            logger.info("======registered DOI via DataCite======")
   
            # Get the response json of resulting doi
            doi_data = response.json()['data']

            logger.debug("======resulting json from DataCite======")
            logger.debug(doi_data)

            dataset_uuid = dataset['uuid']

            try:
                # Update the dataset properties via entity-api
                update_dataset_after_doi_created(dataset_uuid, doi_data, user_token, entity_api_url)
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
def update_dataset_after_doi_created(dataset_uuid, doi_data, user_token, entity_api_url):
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

    response = requests.put(url = f"{entity_api_url}/entities/{dataset_uuid}", headers = request_headers, json = dataset_properties_to_update, verify = False) 
    
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


# Running this python file as a script
# python3 datacite.py <user_token> <dataset_uuid>
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

    # Specify the absolute path of the instance folder and use the config file relative to the instance path
    app = Flask(__name__, instance_path=os.path.join(os.path.abspath(os.path.dirname(__file__)), 'instance'), instance_relative_config=True)
    app.config.from_pyfile('app.cfg')

    datacite_repository_id = app.config['DATACITE_REPOSITORY_ID']
    datacite_repository_password = app.config['DATACITE_REPOSITORY_PASSWORD']
    datacite_api_url = app.config['DATACITE_API_URL']
    datacite_hubmap_prefix = app.config['DATACITE_HUBMAP_PREFIX']
    entity_api_url = app.config['ENTITY_WEBSERVICE_URL']

    target_url = f"{entity_api_url}/entities/{dataset_uuid}"

    auth_header = {
        'Authorization': f"Bearer {user_token}"
    }

    response = requests.get(url = target_url, headers = auth_header,  verify = False) 

    if response.status_code == 200:

        dataset = response.json()

        logger.debug(dataset)

        try:
            register_dataset(dataset, user_token, datacite_repository_id, datacite_repository_password, datacite_api_url, datacite_hubmap_prefix, entity_api_url)
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