import os
import sys
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import logging
from flask import Flask
from api.datacite_api import DataCiteApi
from api.entity_api import EntityApi
from dataset_helper_object import DatasetHelper

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# Set logging fromat and level (default is warning)
# All the API logging is forwarded to the uWSGI server and gets written into the log file `uwsgo-entity-api.log`
# Log rotation is handled via logrotate on the host system with a configuration file
# Do NOT handle log file and rotation via the Python logging to avoid issues with multi-worker processes
logging.basicConfig(format='[%(asctime)s] %(levelname)s in %(module)s: %(message)s', level=logging.DEBUG,
                    datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger(__name__)


def load_flask_instance_config():
    # Specify the absolute path of the instance folder and use the config file relative to the instance path
    app = Flask(__name__, instance_path=os.path.join(os.path.abspath(os.path.dirname(__file__)), 'instance'),
                instance_relative_config=True)
    app.config.from_pyfile('app.cfg')

    # Remove trailing slash / from URL base to avoid "//" caused by config with trailing slash
    app.config['DATACITE_API_URL'] = app.config['DATACITE_API_URL'].strip('/')
    app.config['ENTITY_WEBSERVICE_URL'] = app.config['ENTITY_WEBSERVICE_URL'].strip('/')

    return app.config


class DataCiteDoiHelper:

    def __init__(self):
        config = load_flask_instance_config()

        # Login "Account ID" and "Password" for doi.test.datacite.org
        self.datacite_repository_id = config['DATACITE_REPOSITORY_ID']
        self.datacite_repository_password = config['DATACITE_REPOSITORY_PASSWORD']
        # Prefix, e.g., 10.80478 for test...
        self.datacite_hubmap_prefix = config['DATACITE_HUBMAP_PREFIX']
        # DataCite TEST API: https://api.test.datacite.org/
        self.datacite_api_url = config['DATACITE_API_URL']
        self.entity_api_url = config['ENTITY_WEBSERVICE_URL']

    """
    Register a draft DOI with DataCite

    Draft DOIs may be updated to either Registered or Findable DOIs. 
    Registered and Findable DOIs may not be returned to the Draft state, 
    which means that changing the state of a Draft DOI is final. 
    Draft DOIs remain until the DOI owner either deletes them or converts them to another state.

    Parameters
    ----------
    dataset: dict
        The dataset dict to be published
    dataset_title: str
        The dataset title, either from dataset.title or an auto generated one

    Returns
    -------
    dict
        The registered DOI details
    """
    def create_dataset_draft_doi(self, dataset: object, dataset_title: str) -> object:
        if ('entity_type' in dataset) and (dataset['entity_type'] == 'Dataset'):
            datacite_api = DataCiteApi(self.datacite_repository_id, self.datacite_repository_password,
                                       self.datacite_hubmap_prefix, self.datacite_api_url, self.entity_api_url)
            response = datacite_api.post_create_draft_doi(dataset['hubmap_id'], dataset['uuid'], dataset_title)

            if response.status_code == 201:
                logger.info(f"======Created draft DOI for dataset {dataset['uuid']} via DataCite======")
                doi_data = response.json()
                logger.debug("======resulting json from DataCite======")
                logger.debug(doi_data)
                return doi_data
            else:
                # Log the full stack trace, prepend a line with our message
                logger.exception(f"Unable to create draft DOI for dataset {dataset['uuid']} via DataCite")
                logger.debug("======status code from DataCite======")
                logger.debug(response.status_code)
                logger.debug("======response text from DataCite======")
                logger.debug(response.text)

                # Also bubble up the error message from DataCite
                raise requests.exceptions.RequestException(response.text)
        else:
            raise KeyError('Either the entity_type of the given Dataset is missing or the entity is not a Dataset')

    """
    Move the DOI state from draft to findable, meaning publish this dataset 
    
    Parameters
    ----------
    dataset: dict
        The dataset dict to be published
    user_token: str
        The user's globus nexus token
    
    Returns
    -------
    dict
        The published datset entity dict with updated DOI properties
    """
    def move_doi_state_from_draft_to_findable(self, dataset: object, user_token: str) -> object:
        if ('entity_type' in dataset) and (dataset['entity_type'] == 'Dataset'):
            datacite_api = DataCiteApi(self.datacite_repository_id, self.datacite_repository_password,
                                       self.datacite_hubmap_prefix, self.datacite_api_url, self.entity_api_url)
            response = datacite_api.put_publish_doi(dataset['hubmap_id'])
            entity_api = EntityApi(user_token, self.entity_api_url)

            if response.status_code == 200:
                logger.info(f"======Published DOI for dataset {dataset['uuid']} via DataCite======")

                doi_data = response.json()
                logger.debug("======resulting json from DataCite======")
                logger.debug(doi_data)

                # Then update the dataset DOI properties via entity-api after the DOI gets published
                try:
                    doi_url = doi_data['data']['attributes']['url']
                    registration_doi = datacite_api.registration_doi(dataset['hubmap_id'])
                    updated_dataset = self.update_dataset_after_doi_published(dataset['uuid'], registration_doi, doi_url, entity_api)

                    return updated_dataset
                except requests.exceptions.RequestException as e:
                    raise requests.exceptions.RequestException(e)
            else:
                # Log the full stack trace, prepend a line with our message
                logger.exception(f"Unable to publish DOI for dataset {dataset['uuid']} via DataCite")
                logger.debug("======status code from DataCite======")
                logger.debug(response.status_code)
                logger.debug("======response text from DataCite======")
                logger.debug(response.text)

                # Also bubble up the error message from DataCite
                raise requests.exceptions.RequestException(response.text)
        else:
            raise KeyError('Either the entity_type of the given Dataset is missing or the entity is not a Dataset')

    """
    Update the dataset's properties after DOI is published (Draft -> Findable) 
    
    Parameters
    ----------
    dataset_uuid: str
        The dataset uuid
    registration_doi: str
        The registered doi
    doi_url: str
        The registered doi_url
    entity_api
        The EntityApi object instance
    
    Returns
    -------
    dict
        The entity dict with updated DOI properties
    """
    def update_dataset_after_doi_published(self, dataset_uuid: str, registration_doi: str, doi_url: str, entity_api: EntityApi) -> object:

        # Update the registered_doi, and doi_url properties after DOI made findable
        # Changing Dataset.status to "Published" and setting the published_* properties
        # are handled by another script
        dataset_properties_to_update = {
            'registered_doi': registration_doi,
            'doi_url': doi_url
        }
        response = entity_api.put_entities(dataset_uuid, dataset_properties_to_update)

        if response.status_code == 200:
            logger.info("======The target entity has been updated with DOI info======")
            updated_entity = response.json()
            logger.debug("======updated_entity======")
            logger.debug(updated_entity)

            return updated_entity
        else:
            # Log the full stack trace, prepend a line with our message
            logger.exception(f"Unable to update the DOI properties of dataset {dataset_uuid}")
            logger.debug("======status code from entity-api======")
            logger.debug(response.status_code)
            logger.debug("======response text from entity-api======")
            logger.debug(response.text)

            # Also bubble up the error message from entity-api
            raise requests.exceptions.RequestException(response.text)


# Running this python file as a script
# python3 -m datacite_doi_helper_object <user_token> <dataset_uuid>

# Verify information in...
# URL: https://doi.test.datacite.org/sign-in
# Username: PSC.HUBMAP  (all caps)
# Password: doi4HuBMAP2020
# HuBMAP Prefix: 10.80478
# Click "DOIs" in the GUI and see what is registered, and find the one that you just created
# from the {'data': {'id':'10.80478/hbm836.lnmm.773' ...
# the url should look like "https://handle.stage.datacite.org/10.80478/hbm836.lnmm.773
# click on it and it should send you to the registered redirect page registered in creating
# the draft doi, e.g., https://portal.test.hubmapconsortium.org/browse/dataset/2d4d2f368c6f74cc3aa17177924003b8
if __name__ == "__main__":
    try:
        user_token = sys.argv[1]
        try:
            dataset_uuid = sys.argv[2]
        except IndexError as e:
            msg = "Missing dataset uuid argument"
            logger.exception(msg)
            sys.exit(msg)
    except IndexError as e:
        msg = "Missing user token argument"
        # Log the full stack trace, prepend a line with our message
        logger.exception(msg)
        sys.exit(msg)

    # Make sure that 'app.cfg' is pointed to DEV everything!!!
    config = load_flask_instance_config()
    entity_api = EntityApi(user_token, config['ENTITY_WEBSERVICE_URL'])
    response = entity_api.get_entities(dataset_uuid)
    if response.status_code == 200:
        dataset = response.json()

        logger.debug(dataset)

        dataset_helper = DatasetHelper()
        dataset_title = dataset_helper.generate_dataset_title(dataset, user_token)

        data_cite_doi_helper = DataCiteDoiHelper()
        try:
            data_cite_doi_helper.create_dataset_draft_doi(dataset, dataset_title)
        except requests.exceptions.RequestException as e:
            pass
        try:
            # To publish an existing draft DOI (change the state from draft to findable)
            data_cite_doi_helper.move_doi_state_from_draft_to_findable(dataset, user_token)
        except requests.exceptions.RequestException as e:
            logger.exception(e)
    else:
        # Log the full stack trace, prepend a line with our message
        logger.exception(f"Unable to query the target dataset with uuid: {dataset_uuid}")

        logger.debug("======status code from entity-api======")
        logger.debug(response.status_code)

        logger.debug("======response text from entity-api======")
        logger.debug(response.text)
