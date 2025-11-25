import os
import sys
import time
import requests
from datetime import datetime
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import logging
from flask import Flask
from api.datacite_api import DataCiteApi, DataciteApiException
from hubmap_sdk import EntitySdk
from dataset_helper_object import DatasetHelper
from hubmap_commons.exceptions import HTTPException
from hubmap_commons import string_helper
import ast

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# Set logging fromat and level (default is warning)
# All the API logging is forwarded to the uWSGI server and gets written into the log file `uwsgo-entity-api.log`
# Log rotation is handled via logrotate on the host system with a configuration file
# Do NOT handle log file and rotation via the Python logging to avoid issues with multi-worker processes
logging.basicConfig(format='[%(asctime)s] %(levelname)s in %(module)s: %(message)s', level=logging.INFO,
                    datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger(__name__)


def load_flask_instance_config():
    # Specify the absolute path of the instance folder and use the config file relative to the instance path
    app = Flask(__name__, instance_path=os.path.join(os.path.abspath(os.path.dirname(__file__)), 'instance'),
                instance_relative_config=True)
    app.config.from_pyfile('app.cfg')

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

    def safely_convert_string(self, to_convert: object) -> list:
        # from entity-api this will be a json array, from Neo4j it will be a string...
        if not isinstance(to_convert, str):
            return to_convert
        try:
            return ast.literal_eval(to_convert)
        except (SyntaxError, ValueError, TypeError) as e:
            msg = f"Failed to convert the source string with ast.literal_eval(); msg: {repr(e)}"
            logger.exception(msg)
            raise ValueError(msg)

    # See: https://support.datacite.org/docs/schema-40#table-3-expanded-datacite-mandatory-properties
    def build_common_dataset_contributor(self, dataset_contributor: dict) -> dict:
        contributor = {}

        # This automatically sets the name based on familyName, givenname without using the 'name' value stored in Neo4j
        # E.g., "Smith, Joe"
        contributor['nameType'] = 'Personal'

        if 'first_name' in dataset_contributor:
            # See: https://support.datacite.org/docs/schema-optional-properties-v43#72-givenname
            contributor['givenName'] = dataset_contributor['first_name']

        if 'last_name' in dataset_contributor:
            # See: https://support.datacite.org/docs/schema-optional-properties-v43#73-familyname
            contributor['familyName'] = dataset_contributor['last_name']

        if 'affiliation' in dataset_contributor:
            # See: https://support.datacite.org/docs/schema-optional-properties-v43#75-affiliation
            contributor['affiliation'] = [
                {
                    'name': dataset_contributor['affiliation']
                }
            ]

        # NOTE: ORCID provides a persistent digital identifier (an ORCID iD) that you own and control, and that distinguishes you from every other researcher.
        if 'orcid_id' in dataset_contributor:
            # See: https://support.datacite.org/docs/schema-optional-properties-v43#74-nameidentifier
            contributor['nameIdentifiers'] = [
                {
                    'nameIdentifierScheme': 'ORCID',
                    'nameIdentifier': dataset_contributor['orcid_id'],
                    'schemeUri': 'https://orcid.org/'
                }
            ]

        return contributor

    #helper function to check existence of a non-blank string property in a dict
    def __contains_string_field(self, field_name, entity: dict):
        if not field_name in entity or string_helper.isBlank(entity[field_name]):
            return False
        return True
    
    #helper function to check existence of a non-empty list property in a dict
    def __contains_list_field(self, field_name, entity: dict):
        if not field_name in entity or not isinstance(entity[field_name], list) or len(entity[field_name]) == 0:
            return False
        return True

    # See: https://support.datacite.org/docs/schema-optional-properties-v43#7-contributor
    def build_doi_contributors(self, dataset: dict) -> list:
        dataset_contributors = self.safely_convert_string(dataset['contacts'])
        contributors = []

        for dataset_contributor in dataset_contributors:
            contributor = self.build_common_dataset_contributor(dataset_contributor)
            # See: https://support.datacite.org/docs/schema-optional-properties-v43#7a-contributortype
            contributor['contributorType'] = 'ContactPerson'

            if len(contributor) != 0:
                contributors.append(contributor)

        if len(contributors) == 0:
            return None

        return contributors

    def build_doi_creators(self, dataset: object) -> list:
        dataset_creators = self.safely_convert_string(dataset['contributors'])
        creators = []

        for dataset_creator in dataset_creators:
            creator = self.build_common_dataset_contributor(dataset_creator)

            if len(creator) != 0:
                creators.append(creator)

        if len(creators) == 0:
            return None

        return creators
    

    def check_doi_existence_and_state(self, entity: dict):
        datacite_api = DataCiteApi(self.datacite_repository_id, self.datacite_repository_password, 
                                   self.datacite_hubmap_prefix, self.datacite_api_url, self.entity_api_url)
        doi_name = datacite_api.build_doi_name(entity['hubmap_id'])
        try:
            doi_response = datacite_api.get_doi_by_id(doi_name)
        except requests.exceptions.RequestException as e:
            raise DataciteApiException(error_code=500, message="Failed to connect to DataCite")
        if doi_response.status_code == 200:
            logger.debug("==========DOI already exists. Skipping create-draft=========")
            response_data = doi_response.json()
            state = response_data.get("data", {}).get("attributes", {}).get("state")
            if state == "findable":
                return True
            else:
                return False
        return None

    """
    Register a draft DOI with DataCite

    Draft DOIs may be updated to either Registered or Findable DOIs. 
    Registered and Findable DOIs may not be returned to the Draft state, 
    which means that changing the state of a Draft DOI is final. 
    Draft DOIs remain until the DOI owner either deletes them or converts them to another state.

    Parameters
    ----------
    entity: dict
        The dict of an entity to be published, works for Datasets, Collections or Epicollections

    Returns
    -------
    dict
        The registered DOI details
    """
    def create_draft_doi(self, entity: dict, ignore_publication_status = False) -> object:
        missing_fields = []
        if not self.__contains_string_field('uuid', entity) or not self.__contains_string_field('hubmap_id', entity):
            raise Exception(f"Cannot create a draft DOI for an unknown entity.  Entity uuid and/or hubmap_id are missing.")
        required_string_fields = ['title', 'description', 'entity_type']
        required_list_fields = ['contacts', 'contributors']
        for field in required_string_fields:
            if not self.__contains_string_field(field, entity):
                missing_fields.append(field)
        for field in required_list_fields:
            if not self.__contains_list_field(field, entity):
                missing_fields.append(field)
        n_missing_fields = len(missing_fields)           
        if n_missing_fields > 0:
            if n_missing_fields == 1:
                field_desc = "field"
                field_verb = "is"
            else:
                field_desc = "fields"
                field_verb = "are"
            raise HTTPException(f"Error cannot create a DOI for {entity['entity_type']} {entity['uuid']} because the {field_desc} \"{''.join(missing_fields)}\" {field_verb} blank.", 400)
        
        if not entity['entity_type'] in ['Dataset', 'Collection', 'Epicollection']:
            raise HTTPException(f"Error: cannot create a DOI for entity type {entity['entity_type']} {entity['uuid']} because it is not of required type Dataset, Collection or Epicollection", 400)

        if not ignore_publication_status and entity['entity_type'] == 'Dataset' and (not self.__contains_string_field('status', entity) or not entity['status'] == 'Published'):
            raise HTTPException(f"Error: cannot crate a DOI for Dataset {entity['uuid']} because it does not have a status of Published", 400)

        datacite_api = DataCiteApi(self.datacite_repository_id, self.datacite_repository_password, self.datacite_hubmap_prefix, self.datacite_api_url, self.entity_api_url)

        # Get publication_year, default to the current year
        publication_year = int(datetime.now().year)
        ent_type = entity['entity_type']
        if ent_type == 'Epicollection':
            ent_type = 'Collection'
        if 'published_timestamp' in entity:
            # The timestamp stored with using neo4j's TIMESTAMP() function contains milliseconds
            publication_year = int(datetime.fromtimestamp(entity['published_timestamp']/1000).year)

        try:
            response = datacite_api.create_new_draft_doi(entity['hubmap_id'], 
                                                entity['uuid'],
                                                self.build_doi_contributors(entity), 
                                                entity['title'],
                                                publication_year,
                                                self.build_doi_creators(entity),
                                                entity_type = ent_type)
        except requests.exceptions.RequestException as e:
            raise DataciteApiException(error_code=500, message="Failed to connect to DataCite")

        if response.status_code == 201:
            logger.info(f"======Created draft DOI for entity {entity['uuid']} via DataCite======")
            doi_data = response.json()
            logger.debug("======resulting json from DataCite======")
            logger.debug(doi_data)
            return doi_data
        else:
            # Log the full stack trace, prepend a line with our message
            logger.exception(f"Unable to create draft DOI for entity {entity['uuid']} via DataCite")
            logger.debug(f'======Status code from DataCite {response.status_code} ======')
            logger.debug("======response text from DataCite======")
            logger.debug(response.text)

            # Also bubble up the error message from DataCite
            #raise requests.exceptions.RequestException(response.text)
            raise DataciteApiException(response.text, error_code=response.status_code)


    def build_doi_name(self, entity):
        datacite_api = DataCiteApi(self.datacite_repository_id, self.datacite_repository_password, self.datacite_hubmap_prefix, self.datacite_api_url, self.entity_api_url)
        doi_name = datacite_api.build_doi_name(entity['hubmap_id'])
        return doi_name
    
    """
    Move the DOI state from draft to findable, meaning publish this dataset. 
    No PUT call made against entity-api to update the two DOI fields here. 
    Will need to call `update_dataset_after_doi_published()` separately if needed
    
    Parameters
    ----------
    entity: dict
        The entity dict to be published
    user_token: str
        The user's globus nexus token
    
    Returns
    -------
    dict
        The updated DOI properties
    """
    def move_doi_state_from_draft_to_findable(self, entity: dict) -> object:
        entity_types = ['Dataset', 'Collection', 'Epicollection']
        if ('entity_type' in entity) and (entity['entity_type'] in entity_types):
            datacite_api = DataCiteApi(self.datacite_repository_id, self.datacite_repository_password,
                                       self.datacite_hubmap_prefix, self.datacite_api_url, self.entity_api_url)
            response = datacite_api.update_doi_event_publish(entity['hubmap_id'])

            if response.status_code == 200:
                logger.info(f"======Published DOI for entity {entity['uuid']} via DataCite======")
                doi_data = response.json()
                logger.debug("======resulting json from DataCite======")
                logger.debug(doi_data)

                doi_name = datacite_api.build_doi_name(entity['hubmap_id'])
                doi_info = {
                    'registered_doi': doi_name,
                    'doi_url': f'https://doi.org/{doi_name}'
                }
                return doi_info
            else:
                # Log the full stack trace, prepend a line with our message
                logger.exception(f"Unable to publish DOI for dataset {entity['uuid']} via DataCite")
                logger.debug(f'======Status code from DataCite {response.status_code} ======')
                logger.debug("======response text from DataCite======")
                logger.debug(response.text)

                # Also bubble up the error message from DataCite
                raise HTTPException(f"Unable to make doi findable for {entity['entity_type']} {entity['uuid']}: " + response.text, 400)
        else:
            entity_uuid = "UNKNOWN"
            if 'uuid' in entity:
                entity_uuid = entity['uuid']
            raise HTTPException(f"Either the entity_type of the given entity with uuid:{entity_uuid} is missing or the entity is not one of the following types: {', '.join(entity_types)}", 400)

    """
    Update the dataset's properties after DOI is published (Draft -> Findable) 
    
    Parameters
    ----------
    dataset_uuid: str
        The dataset uuid
    doi_info: dict
        The `doi_info` returned from `move_doi_state_from_draft_to_findable()` method
    entity_api
        The EntitySdk object instance
    
    Returns
    -------
    dict
        A json message in the format: {'message': f"{normalized_entity_type} of {id} has been updated"}
    """
    def update_dataset_after_doi_published(self, dataset_uuid: dict, doi_info: str, entity_api: EntitySdk) -> object:
        # Update the registered_doi, and doi_url properties after DOI made findable
        # Changing Dataset.status to "Published" and setting the published_* properties
        # are handled by another script
        # See https://github.com/hubmapconsortium/ingest-ui/issues/354
        try:
            # Entity update via PUT call only returns a json message, no entity details
            result = entity_api.update_entity(dataset_uuid, doi_info)
            logger.info("======The dataset {dataset['uuid']}  has been updated with DOI info======")
            logger.info(doi_info)

            return result
        except HTTPException as e:
            # Log the full stack trace, prepend a line with our message
            logger.exception(f"Unable to update the DOI properties of dataset {dataset_uuid}")
            logger.debug(f'======Status code from DataCite {e.status_code} ======')
            logger.debug("======response text from entity-api======")
            logger.debug(e.description)

            # Also bubble up the error message from entity-api
            raise requests.exceptions.RequestException(e.description)


    # Do the full DOI registration and make it findable for an entity of type Dataset, Collection or Epicollection
    # If the DOI already exists at DataCite, just make it findable
    def register_doi_and_make_findable(self, entity, ignore_publication_status=False):
            # Checks both whether a doi already exists, as well as if it is already findable. If True, DOI exists and is findable
            # If false, DOI exists but is not yet in findable. If None, doi does not yet exist. 
            doi_info = None
            
            try:
                doi_exists = self.check_doi_existence_and_state(entity)
            except DataciteApiException as e:
                    logger.exception(f"Exception while fetching doi for {entity['entity_type']} {entity['uuid']}")
                    raise HTTPException(f"Error occurred while trying to confirm existence of doi for {dataset_uuid}. {e}", 500)
            # Doi does not exist, create draft then make it findable
            if doi_exists is None:
                try:
                    self.create_draft_doi(entity, ignore_publication_status)
                except DataciteApiException as e:
                    logger.exception(f"Exception while creating draft doi for {entity['entity_type']} {entity['uuid']}")
                    raise HTTPException(f"Error occurred while trying to create draft doi for {dataset_uuid}. {e}", 500)                
                doi_info = self.move_doi_state_from_draft_to_findable(entity)
            # Doi exists, but is not yet findable. Just make it findable
            elif doi_exists is False:
                doi_info = self.move_doi_state_from_draft_to_findable(entity)
            # The doi exists and it is already findable, skip both steps
            elif doi_exists is True:
                logger.debug(f"DOI for {entity['uuid']} is already findable. Skipping creation and state change.")
                doi_name = datacite_doi_helper.build_doi_name(entity)
                doi_info = {
                    'registered_doi': doi_name,
                    'doi_url': f'https://doi.org/{doi_name}'
                }

            #this should never or rarely happen, but could if there is an unforeseen problem returning info from existing or new DOI
            if doi_info is None or not 'registered_doi' in doi_info or not 'doi_url' in doi_info or string_helper.isBlank(doi_info['registered_doi'] or stringHelper.isBlank(doi_info['doi_url'])):
                raise HTTPException(f"Unexpected result while registering DOI for entity {entity['uuid']}.  DOI information not found",500)
            
            return doi_info

# Running this python file as a script
# cd src; python3 -m datacite_doi_helper_object <user_token>
if __name__ == "__main__":
    # Add the uuids to this list
    datasets = []

    try:
        user_token = sys.argv[1]
    except IndexError as e:
        msg = "Missing user token argument"
        # Log the full stack trace, prepend a line with our message
        logger.exception(msg)
        sys.exit(msg)

    # Make sure that 'app.cfg' is pointed to DEV everything!!!
    config = load_flask_instance_config()
    entity_api = EntitySdk(user_token, config['ENTITY_WEBSERVICE_URL'])

    count = 1
    for dataset_uuid in datasets:
        logger.debug(f"Begin {count}: ========================= {dataset_uuid} =========================")
        try:
            entity = entity_api.get_entity_by_id(dataset_uuid)
            dataset = vars(entity)

            #logger.debug(dataset)

            dataset_helper = DatasetHelper()

            data_cite_doi_helper = DataCiteDoiHelper()

            try:
                logger.debug("Create Draft DOI")

                ### DISABLED, need to enable when use

                # data_cite_doi_helper.create_draft_doi(dataset)
            except Exception as e:
                logger.exception(e)
                sys.exit(e)

            try:
                logger.debug("Move Draft DOI -> Findable DOI")

                ### DISABLED, need to enable when use

                # doi_info = data_cite_doi_helper.move_doi_state_from_draft_to_findable(dataset, user_token)
                # result = data_cite_doi_helper.update_dataset_after_doi_published(dataset['uuid'], doi_info, entity_api)
                # logger.info("======The dataset {dataset['uuid']}  has been updated with DOI info======")
            except Exception as e:
                logger.exception(e)
                sys.exit(e)
        except HTTPException as e:
            # Log the full stack trace, prepend a line with our message
            logger.exception(f"Unable to query the target dataset with uuid: {dataset_uuid}")

            logger.debug("======status code from entity-api======")
            logger.debug(e.status_code)

            logger.debug("======response text from entity-api======")
            logger.debug(e.description)

        logger.debug(f"End {count}: ========================= {dataset_uuid} =========================")

        time.sleep(1)

        count = count + 1
