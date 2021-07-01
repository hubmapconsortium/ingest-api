import os
import sys
from array import array

import yaml
import requests
import logging
from flask import Flask
import urllib.request
from api.entity_api import EntityApi
from api.search_api import SearchApi

# Suppress InsecureRequestWarning warning when requesting status on https with ssl cert verify disabled
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# Set logging fromat and level (default is warning)
# All the API logging is forwarded to the uWSGI server and gets written into the log file `uwsgo-entity-api.log`
# Log rotation is handled via logrotate on the host system with a configuration file
# Do NOT handle log file and rotation via the Python logging to avoid issues with multi-worker processes
logging.basicConfig(format='[%(asctime)s] %(levelname)s in %(module)s: %(message)s', level=logging.DEBUG,
                    datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger(__name__)

# In Python, "privacy" depends on "consenting adults'" levels of agreement, we can't force it.
# A single leading underscore means you're not supposed to access it "from the outside"
_entity_api_url = None
_search_api_url = None


def load_flask_instance_config():
    # Specify the absolute path of the instance folder and use the config file relative to the instance path
    app = Flask(__name__,
                instance_path=os.path.join(os.path.abspath(os.path.dirname(__file__)), 'instance'),
                instance_relative_config=True)
    app.config.from_pyfile('app.cfg')

    # Remove trailing slash / from URL base to avoid "//" caused by config with trailing slash
    app.config['ENTITY_WEBSERVICE_URL'] = app.config['ENTITY_WEBSERVICE_URL'].strip('/')
    app.config['SEARCH_WEBSERVICE_URL'] = app.config['SEARCH_WEBSERVICE_URL'].strip('/')

    return app.config


class DatasetHelper:

    def __init__(self):
        # Specify as module-scope variables
        global _entity_api_url
        global _search_api_url

        if _entity_api_url is None:
            config = load_flask_instance_config()
            _entity_api_url = config['ENTITY_WEBSERVICE_URL']
            _search_api_url = config['SEARCH_WEBSERVICE_URL']

        print(f"__init__ _entity_api_url: {_entity_api_url}")
        print(f"__init__ _search_api_url: {_search_api_url}")

    def get_organ_types_dict(self) -> object:
        yaml_file_url = 'https://raw.githubusercontent.com/hubmapconsortium/search-api/master/src/search-schema/data/definitions/enums/organ_types.yaml'
        with urllib.request.urlopen(yaml_file_url) as response:
            yaml_file = response.read()
            try:
                return yaml.safe_load(yaml_file)
            except yaml.YAMLError as e:
                raise yaml.YAMLError(e)

    # This is the business logic for an endpoint that is used by the ingress-validation-tests package to validate
    # the data needed to produce a title from data found in a dataset using generate_dataset_title below.
    def verify_dataset_title_info(self, dataset_uuid: str, user_token: str) -> array:
        entity_api = EntityApi(user_token, _entity_api_url)
        search_api = SearchApi(user_token, _search_api_url)

        data_found = {'age': False, 'race': False, 'sex': False}
        rslt = []

        response = entity_api.get_entities(dataset_uuid)
        if response.status_code != 200:
            rslt.append(f'Unable to get the target dataset with uuid: {dataset_uuid}')
            return rslt
        dataset = response.json()

        for data_type in dataset['data_types']:
            response = search_api.get_assaytype(data_type)
            if response.status_code != 200:
                rslt.append(f"Unable to query the assay type details of: {data_type} via search-api")

        response = entity_api.get_ancestors(dataset['uuid'])
        if response.status_code != 200:
            rslt.append(f"Unable to get the ancestors of dataset with uuid: {dataset_uuid}")

        for ancestor in response.json():
            if 'entity_type' in ancestor:

                if ancestor['entity_type'] == 'Sample':
                    if 'specimen_type' in ancestor and ancestor['specimen_type'].lower() == 'organ':
                        if 'organ' in ancestor:
                            organ_code = ancestor['organ']
                            organ_types_dict = self.get_organ_types_dict()
                            if organ_code in organ_types_dict:
                                organ_entry = organ_types_dict[organ_code]
                                if 'description' not in organ_entry:
                                    rslt.append(f"Description for Organ code '{organ_code}' not found in organ types file")
                            else:
                                rslt.append(f"Organ code '{organ_code}' not found in organ types file")
                        else:
                            rslt.append('Organ key not found in specimen_type organ')

                elif ancestor['entity_type'] == 'Donor':
                    try:
                        for data in ancestor['metadata']['organ_donor_data']:
                            if data['grouping_concept_preferred_term'].lower() == 'age':
                                data_found['age'] = True

                            if data['grouping_concept_preferred_term'].lower() == 'race':
                                data_found['race'] = True

                            if data['grouping_concept_preferred_term'].lower() == 'sex':
                                data_found['sex'] = True
                    except KeyError:
                        pass

        for k, v in data_found.items():
            if not v:
                rslt.append(f'Donor metadata.organ_donor_data grouping_concept_preferred_term {k} not found')

        return rslt

    # Note: verify_dataset_title_info checks information used here and so if this is changed that should be updated.
    def generate_dataset_title(self, dataset: object, user_token: str) -> str:
        entity_api = EntityApi(user_token, _entity_api_url)
        search_api = SearchApi(user_token, _search_api_url)

        organ_desc = '<organ_desc>'
        age = '<age>'
        race = '<race>'
        sex = '<sex>'

        # Parse assay_type from the Dataset
        try:
            assay_type_desc = self.get_assay_type_description(search_api, dataset['data_types'])
        except requests.exceptions.RequestException as e:
            raise requests.exceptions.RequestException(e)

        # Parse organ_name, age, race, and sex from ancestor Sample and Donor
        try:
            ancestors = self.get_dataset_ancestors(entity_api, dataset['uuid'])
        except requests.exceptions.RequestException as e:
            raise requests.exceptions.RequestException(e)

        # https://github.com/hubmapconsortium/entity-api/blob/73d880fbeefb0ec5a9527cbea8b83ddd3d7f4e50/entity-api-spec.yaml
        for ancestor in ancestors:
            if 'entity_type' in ancestor:
                # 'specimen_type' is a key in search-api/src/search-schema/data/definitions/enums/tissue_sample_types.yaml

                if ancestor['entity_type'] == 'Sample':
                    if 'specimen_type' in ancestor and ancestor['specimen_type'].lower() == 'organ' and \
                            'organ' in ancestor:
                        try:
                            # ancestor['organ'] is the two-letter code only set if sample_type == organ.
                            # Convert the two-letter code to a description
                            # https://github.com/hubmapconsortium/search-api/blob/test-release/src/search-schema/data/definitions/enums/organ_types.yaml
                            organ_desc = self.get_organ_description(ancestor['organ'])
                        except yaml.YAMLError as e:
                            raise yaml.YAMLError(e)

                if ancestor['entity_type'] == 'Donor':
                    # Easier to ask for forgiveness than permission (EAFP)
                    # Rather than checking key existence at every level
                    try:
                        data_list = ancestor['metadata']['organ_donor_data']

                        for data in data_list:
                            if 'grouping_concept_preferred_term' in data:
                                if data['grouping_concept_preferred_term'].lower() == 'age':
                                    # The actual value of age stored in 'data_value' instead of 'preferred_term'
                                    age = data['data_value']

                                if data['grouping_concept_preferred_term'].lower() == 'race':
                                    race = data['preferred_term'].lower()

                                if data['grouping_concept_preferred_term'].lower() == 'sex':
                                    sex = data['preferred_term'].lower()
                    except KeyError:
                        pass

        generated_title = f"{assay_type_desc} data from the {organ_desc} of a {age}-year-old {race} {sex}"

        logger.debug("===========Auto generated Title===========")
        logger.debug(generated_title)

        return generated_title

    def get_assay_type_description(self, search_api: object, data_types: array) -> str:
        assay_types = []
        assay_type_desc = ''

        for data_type in data_types:
            # The assaytype endpoint in search-api is public accessible, no token needed
            response = search_api.get_assaytype(data_types)
            if response.status_code == 200:
                assay_type_info = response.json()
                # Add to the list
                assay_types.append(assay_type_info['description'])
            else:
                msg = f"Unable to query the assay type details of: {data_type} via search-api"

                # Log the full stack trace, prepend a line with our message
                logger.exception(msg)

                logger.debug("======status code from search-api======")
                logger.debug(response.status_code)

                logger.debug("======response text from search-api======")
                logger.debug(response.text)

                raise requests.exceptions.RequestException(response.text)

        # Formatting based on the number of items in the list
        if assay_types:
            if len(assay_types) == 1:
                assay_type_desc = assay_types[0]
            elif len(assay_types) == 2:
                # <assay_type1> and <assay_type2>
                assay_type_desc = ' and '.join(assay_types)
            else:
                # <assay_type1>, <assay_type2>, and <assay_type3>
                assay_type_desc = f"{', '.join(assay_types[:-1])}, and {assay_types[-1]}"
        else:
            msg = "Empty list of assay_types"

            logger.error(msg)

            raise ValueError(msg)

        return assay_type_desc

    def get_organ_description(self, organ_code: str) -> str:
        organ_types_dict = self.get_organ_types_dict()
        return organ_types_dict[organ_code]['description'].lower()

    def get_dataset_ancestors(self, entity_api: object, dataset_uuid: str) -> object:
        response = entity_api.get_ancestors(dataset_uuid)
        if response.status_code == 200:
            return response.json()
        else:
            msg = f"Unable to get the ancestors of dataset with uuid: {dataset_uuid}"

            # Log the full stack trace, prepend a line with our message
            logger.exception(msg)

            logger.debug("======status code from entity-api======")
            logger.debug(response.status_code)

            logger.debug("======response text from entity-api======")
            logger.debug(response.text)

            raise requests.exceptions.RequestException(response.text)


# Running this python file as a script
# python3 -m dataset_helper <user_token> <dataset_uuid>
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

    dataset_helper = DatasetHelper()

    entity_api = EntityApi(user_token, _entity_api_url)
    response = entity_api.get_entities(dataset_uuid)
    if response.status_code == 200:
        dataset = response.json()

        try:
            title = dataset_helper.generate_dataset_title(dataset, user_token)
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
