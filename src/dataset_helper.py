import os
import sys
import requests
import logging
from flask import Flask

# Suppress InsecureRequestWarning warning when requesting status on https with ssl cert verify disabled
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(category = InsecureRequestWarning)

# Set logging fromat and level (default is warning)
# All the API logging is forwarded to the uWSGI server and gets written into the log file `uwsgo-entity-api.log`
# Log rotation is handled via logrotate on the host system with a configuration file
# Do NOT handle log file and rotation via the Python logging to avoid issues with multi-worker processes
logging.basicConfig(format = '[%(asctime)s] %(levelname)s in %(module)s: %(message)s', level = logging.DEBUG, datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger(__name__)


# In Python, "privacy" depends on "consenting adults'" levels of agreement, we can't force it.
# A single leading underscore means you're not supposed to access it "from the outside"
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
    global _entity_api_url
    global _search_api_url

    config = load_flask_instance_config()

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
Create a dataset name, store it in the Dataset.title field. Based on this template:
<Assay type> data from the <organ name> of a <age>-year-old <race> <sex>.

For Example: "Bulk ATAC-seq data from the liver of a 63 year old white male."

Parameters
----------
dataset_uuid: str
    The dataset uuid
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

    # Parse assay_type from the Dataset
    try:
        assay_type_desc = get_assay_type_description(dataset['data_types'])
    except requests.exceptions.RequestException as e:
        raise requests.exceptions.RequestException(e)

    # Parse organ_name, age, race, and sex from ancestor Sample and Donor         
    try:
        ancestors = get_dataset_ancestors(dataset['uuid'], user_token)
    except requests.exceptions.RequestException as e:
        raise requests.exceptions.RequestException(e)

    for ancestor in ancestors:
        if (ancestor['entity_type'] == 'Sample') and (ancestor['specimen_type'].lower() == 'organ'):
            # ancestor['organ'] is the two-letter code
            # Do we need to convert to the description?
            # https://github.com/hubmapconsortium/search-api/blob/test-release/src/search-schema/data/definitions/enums/organ_types.yaml
            organ_name = ancestor['organ']

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

    generated_title = f"{assay_type_desc} data from the {organ_name} of a {age}-year-old {race} {sex}"

    logger.debug("===========Auto generated Title===========")
    logger.debug(generated_title)

    return generated_title


"""
Get the description of a given assay type name

Parameters
----------
data_types: list
    The data types of the given dataset

Returns
-------
str
    The description of the target assay type, single or combined
"""
def get_assay_type_description(data_types):
    global _search_api_url

    assay_types = []
    assay_type_desc = ''

    for data_type in data_types:
        target_url = f"{_search_api_url}/assaytype/{data_type}"
    
        # The assaytype endpoint in search-api is public accessible, no token needed
        response = requests.get(url = target_url, verify = False) 

        if response.status_code == 200:

            assay_type_info = response.json()

            logger.debug(assay_type_info)

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


"""
Get the ancestors list of the target dataset

Parameters
----------
dataset_uuid: str
    The UUID of target dataset
user_token: str
    The user's globus nexus token

Returns
-------
list
    A list of ancestors entity dicts
"""
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

        raise requests.exceptions.RequestException(response.text)


# Running this python file as a script
# python3 -m datacite_helper <user_token> <dataset_uuid>
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

        try:
            title = generate_dataset_title(dataset, user_token)

            logger.debug("========generated dataset title========")
            logger.debug(title)
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