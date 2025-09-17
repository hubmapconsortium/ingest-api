import datetime
import redis
import glob
import os
import sys
import logging
import urllib.request
import requests
import re
import json
import pandas
import shutil
from uuid import UUID
import csv
import time
from operator import xor
from threading import Thread

import werkzeug.exceptions
from hubmap_sdk import EntitySdk, sdk_helper
from apscheduler.schedulers.background import BackgroundScheduler
from neo4j.exceptions import TransactionError
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.triggers.date import DateTrigger
# Don't confuse urllib (Python native library) with urllib3 (3rd-party library, requests also uses urllib3)
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import argparse
from pathlib import Path
from flask import Flask, g, jsonify, abort, request, json, Response
from flask_cors import CORS
from flask_mail import Mail, Message

from dataset_helper_object import DatasetHelper
from worker.utils import ResponseException

# HuBMAP commons
from hubmap_commons import neo4j_driver
from hubmap_commons.hm_auth import AuthHelper, secured
from hubmap_commons.autherror import AuthError
from hubmap_commons.exceptions import HTTPException
from hubmap_commons import string_helper
from hubmap_commons.string_helper import isBlank
from hubmap_commons import net_helper
from hubmap_commons import file_helper as commons_file_helper

# Should be deprecated/refactored but still in use
from hubmap_commons.hubmap_const import HubmapConst

# Local modules
from sample_helper import SampleHelper
from ingest_file_helper import IngestFileHelper
from file_upload_helper import UploadFileHelper
from prov_schema_helper import ProvenanceSchemaHelper
import app_manager
from dataset import Dataset
from datacite_doi_helper_object import DataCiteDoiHelper
from api.datacite_api import DataciteApiException
from app_utils.request_validation import require_json
from app_utils.error import unauthorized_error, not_found_error, internal_server_error, bad_request_error, forbidden_error
from app_utils.misc import __get_dict_prop
from app_utils.entity import __get_entity, get_entity_type_instanceof
from app_utils.task_queue import TaskQueue
from werkzeug import utils

from routes.auth import auth_blueprint
from routes.datasets import datasets_blueprint
from routes.file import file_blueprint
from routes.assayclassifier import bp as assayclassifier_blueprint
from routes.validation import validation_blueprint
from routes.datasets_bulk_submit import datasets_bulk_submit_blueprint, DatasetHelper as ds_helper
from routes.privs import privs_blueprint
from ingest_validation_tools import schema_loader, table_validator 
from ingest_validation_tools import validation_utils as iv_utils

# Set logging format and level (default is warning)
# All the API logging is forwarded to the uWSGI server and gets written into the log file `uwsgi-ingest-api.log`
# Log rotation is handled via logrotate on the host system with a configuration file
# Do NOT handle log file and rotation via the Python logging to avoid issues with multi-worker processes
logging.basicConfig(format='[%(asctime)s] %(levelname)s in %(module)s: %(message)s',
                    level=logging.INFO,
                    datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger(__name__)

# Specify the absolute path of the instance folder and use the config file relative to the instance path
app = Flask(__name__,
            instance_path=os.path.join(os.path.abspath(os.path.dirname(__file__)), 'instance'),
            instance_relative_config=True)
app.config.from_pyfile('app.cfg')

app.register_blueprint(auth_blueprint)
app.register_blueprint(datasets_blueprint)
app.register_blueprint(file_blueprint)
app.register_blueprint(assayclassifier_blueprint)
app.register_blueprint(validation_blueprint)
app.register_blueprint(datasets_bulk_submit_blueprint)
app.register_blueprint(privs_blueprint)

# Suppress InsecureRequestWarning warning when requesting status on https with ssl cert verify disabled
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# Enable/disable CORS from configuration based on docker or non-docker deployment
if app.config['ENABLE_CORS']:
    CORS(app)

# Instantiate the Flask Mail instance
try:
    if  'MAIL_SERVER' not in app.config or not app.config['MAIL_SERVER'] or \
        'MAIL_PORT' not in app.config or not isinstance(app.config['MAIL_PORT'], int) or \
        'MAIL_USE_TLS' not in app.config or not isinstance(app.config['MAIL_USE_TLS'], bool) or \
        'MAIL_USERNAME' not in app.config or not app.config['MAIL_USERNAME'] or \
        'MAIL_PASSWORD' not in app.config or not app.config['MAIL_PASSWORD'] or \
        'MAIL_DEBUG' not in app.config or not isinstance(app.config['MAIL_DEBUG'], bool) or \
        'MAIL_DEFAULT_SENDER' not in app.config or not isinstance(app.config['MAIL_DEFAULT_SENDER'], tuple) or \
        len(app.config['MAIL_DEFAULT_SENDER']) != 2 or \
        not app.config['MAIL_DEFAULT_SENDER'][0] or not app.config['MAIL_DEFAULT_SENDER'][1]:
            logger.fatal(f"Flask Mail settings are not correct.")
    if 'MAIL_ADMIN_LIST' not in app.config or not isinstance(app.config['MAIL_ADMIN_LIST'], list) or \
        len(app.config['MAIL_ADMIN_LIST']) < 1 or \
        not app.config['MAIL_ADMIN_LIST'][0]:
            # Admin emails, not part of Flask-Mail configuration
            logger.fatal(f"ingest-api custom email setting for MAIL_ADMIN_LIST are not correct.")

    flask_mail = Mail(app)
except Exception as e:
    logger.fatal(f"An error occurred configuring the app to email. {str(e)}")

####################################################################################################
## Register error handlers
####################################################################################################

# Error handler for 400 Bad Request with custom error message
@app.errorhandler(400)
def http_bad_request(e):
    return jsonify(error=str(e)), 400

# Error handler for 401 Unauthorized with custom error message
@app.errorhandler(401)
def http_unauthorized(e):
    return jsonify(error=str(e)), 401

# Error handler for 404 Not Found with custom error message
@app.errorhandler(404)
def http_not_found(e):
    return jsonify(error=str(e)), 404

# Error handler for 500 Internal Server Error with custom error message
@app.errorhandler(500)
def http_internal_server_error(e):
    return jsonify(error=str(e)), 500


####################################################################################################
## AuthHelper initialization
####################################################################################################

# Initialize AuthHelper class and ensure singleton
try:
    if AuthHelper.isInitialized() == False:
        auth_helper_instance = AuthHelper.create(app.config['APP_CLIENT_ID'],
                                                 app.config['APP_CLIENT_SECRET'])

        logger.info("Initialized AuthHelper class successfully :)")
    else:
        auth_helper_instance = AuthHelper.instance()
except Exception:
    msg = "Failed to initialize the AuthHelper class"
    # Log the full stack trace, prepend a line with our message
    logger.exception(msg)


####################################################################################################
## Neo4j connection initialization
####################################################################################################

# The neo4j_driver (from commons package) is a singleton module
# This neo4j_driver_instance will be used for application-specific neo4j queries
# as well as being passed to the schema_manager
try:
    neo4j_driver_instance = neo4j_driver.instance(app.config['NEO4J_SERVER'],
                                                  app.config['NEO4J_USERNAME'],
                                                  app.config['NEO4J_PASSWORD'])

    logger.info("Initialized neo4j_driver module successfully :)")
except Exception:
    msg = "Failed to initialize the neo4j_driver module"
    # Log the full stack trace, prepend a line with our message
    logger.exception(msg)

if not 'METADATA_TSV_BACKUP_DIR' in app.config:
    logger.exception("ERROR: METADATA_TSV_BACKUP_DIR property not found in configuration file")
    tsv_backup_dir = None
else:
    tsv_backup_dir = app.config['METADATA_TSV_BACKUP_DIR']


####################################################################################################
## File upload initialization
####################################################################################################

try:
    # Initialize the UploadFileHelper class and ensure singleton
    if UploadFileHelper.is_initialized() == False:
        file_upload_helper_instance = UploadFileHelper.create(app.config['FILE_UPLOAD_TEMP_DIR'],
                                                              app.config['FILE_UPLOAD_DIR'],
                                                              app.config['UUID_WEBSERVICE_URL'])

        logger.info("Initialized UploadFileHelper class successfully :)")

        # This will delete all the temp dirs on restart
        #file_upload_helper_instance.clean_temp_dir()
    else:
        file_upload_helper_instance = UploadFileHelper.instance()
# Use a broad catch-all here
except Exception:
    msg = "Failed to initialize the UploadFileHelper class"
    # Log the full stack trace, prepend a line with our message
    logger.exception(msg)

# Admin group UUID
data_admin_group_uuid = app.config['HUBMAP_DATA_ADMIN_GROUP_UUID']
data_curator_group_uuid = app.config['HUBMAP_DATA_CURATOR_GROUP_UUID']

prov_schema_helper = ProvenanceSchemaHelper(app.config)

####################################################################################################
## Task Queue initialization
####################################################################################################
try:
    redis_url = app.config['REDIS_URL']
    logger.info(f'Initializing TaskQueue class successfully :) REDIS_URL={redis_url}')
    TaskQueue.create(redis_url, 'Cell Type Count Processing')
except Exception:
    logger.exception("Failed to Initializing class TaskQueue")

####################################################################################################
## Default and Status Routes
####################################################################################################

@app.route('/', methods=['GET'])
def index():
    return "Hello! This is HuBMAP Ingest API service :)"

# Show status of neo4j connection and optionally of the dependent web services
# to show the status of the other hubmap services that ingest-api is dependent on
# use the url parameter "?check-ws-dependencies=true
# returns a json body with the status of the neo4j service and optionally the
# status/time that it took for the dependent web services to respond
# e.g.:
#     {
#        "build": "adfadsfasf",
#        "entity_ws": 130,
#        "neo4j_connection": true,
#        "search_ws_check": 127,
#        "uuid_ws": 105,
#        "version": "1.15.4"
#     }
@app.route('/status', methods=['GET'])
def status():
    response_code = 200
    try:
        file_build_content = (Path(__file__).absolute().parent.parent / 'BUILD').read_text().strip()
    except Exception as e:
        file_build_content = str(e)

    try:
        redis_conn = redis.from_url(redis_url)
        redis_ping_status = redis_conn.ping()
    except Exception as e:
        redis_ping_status = str(e)

    response_data = {
        # Use strip() to remove leading and trailing spaces, newlines, and tabs
        'version': (Path(__file__).absolute().parent.parent / 'VERSION').read_text().strip(),
        'redis': redis_ping_status,
        'build': file_build_content
    }

    try:
        #if ?check-ws-dependencies=true is present in the url request params
        #set a flag to check these other web services
        check_ws_calls = string_helper.isYes(request.args.get('check-ws-dependencies'))

        #check the neo4j connection
        try:
            with neo4j_driver_instance.session() as session:
                recds = session.run("Match () Return 1 Limit 1")
                for recd in recds:
                    if recd[0] == 1:
                        is_connected = True
                    else:
                        is_connected = False

                is_connected = True
        #the neo4j connection will often fail via exception so
        #catch it here, flag as failure and track the returned error message
        except Exception as e:
            response_code = 500
            response_data['neo4j_error'] = str(e)
            is_connected = False

        if is_connected:
            response_data['neo4j_connection'] = True
        else:
            response_code = 500
            response_data['neo4j_connection'] = False

        #if the flag was set to check ws dependencies do it now
        #for each dependency try to connect via helper which calls the
        #service's /status method
        #The helper method will return False if the connection fails or
        #an integer with the number of milliseconds that it took to get
        #the services status
        if check_ws_calls:
            uuid_ws_url = app.config['UUID_WEBSERVICE_URL'].strip()
            if uuid_ws_url.endswith('hmuuid'): uuid_ws_url = uuid_ws_url[:len(uuid_ws_url) - 6]
            uuid_ws_check = net_helper.check_hm_ws(uuid_ws_url)
            entity_ws_check = net_helper.check_hm_ws(app.config['ENTITY_WEBSERVICE_URL'])
            search_ws_check = net_helper.check_hm_ws(app.config['SEARCH_WEBSERVICE_URL'])
            if not uuid_ws_check or not entity_ws_check or not search_ws_check: response_code = 500
            response_data['uuid_ws'] = uuid_ws_check
            response_data['entity_ws'] = entity_ws_check
            response_data['search_ws_check'] = search_ws_check

    #catch any unhandled exceptions
    except Exception as e:
        response_code = 500
        response_data['exception_message'] = str(e)
    finally:
        return Response(json.dumps(response_data), response_code, mimetype='application/json')


####################################################################################################
## Slack Notification
####################################################################################################

# Send an email with the specified text in the body and the specified subject line to
# the  data curation/ingest staff email addresses specified in the app.cfg MAIL_ADMIN_LIST entry.
def email_admin_list(message_text, subject):
    msg = Message(  body=message_text
                    ,recipients=app.config['MAIL_ADMIN_LIST']
                    ,subject=subject)
    flask_mail.send(msg)

"""
Notify data curation/ingest staff of events during the data ingest process by sending a message to the 
target Slack channel, with an option to email the same message to addresses in the MAIL_ADMIN_LIST value
of app.cfg. HuBMAP-Read access is required in the "old gateway" used by ingest-api, running on a PSC VM.

Input
--------
POST request body data is a JSON object containing the following fields:
    message : str
        The message to be sent to the channel. Required.
    channel : str
        The target Slack channel. Optional, with default from configuration used if not specified.
    send_to_email : bool
        Indication if the message should also be sent via email to addresses configured in MAIL_ADMIN_LIST.
        Optional, defaulting to False when not in the JSON.
Returns
--------
dict
    Dictionary with separate dictionary entries for 'Slack' and 'Email', each containing a summary of the notification.
"""
@app.route('/notify', methods=['POST'])
def notify():
    channel = app.config['SLACK_DEFAULT_CHANNEL']
    user_name = ''
    user_email = ''

    # Get user info based on token
    # At this point we should have a valid token since the gateway already checked the auth
    user_info = auth_helper_instance.getUserInfo(AuthHelper.parseAuthorizationTokens(request.headers))
    if user_info is None:
        unauthorized_error("Unable to obtain user information for groups token")
    elif isinstance(user_info, Response) and user_info.status_code in [400, 401, 403]:
        unauthorized_error(f"Unable to dispatch notifications with the groups token presented.")
    else:
        try:
            user_name = user_info['name']
            user_email = user_info['email']
        except Exception as e:
            logger.error(f"An exception occurred authorizing the user for notification dispatching. {str(e)}")
            unauthorized_error(f"An error occurred authorizing the notification.  See logs.")

    require_json(request)
    json_data = request.json

    logger.debug(f"======notify() Request json:======")
    logger.debug(json_data)

    if 'channel' in json_data:
        if not isinstance(json_data['channel'], str):
            bad_request_error("The value of 'channel' must be a string")
        # Use the user provided channel rather than the configured default value
        channel = json_data['channel']

    if 'message' not in json_data:
        bad_request_error("The 'message' field is required.")

    if not isinstance(json_data['message'], str):
        bad_request_error("The value of 'message' must be a string")

    # Send message to Slack
    target_url = 'https://slack.com/api/chat.postMessage'
    request_header = {
        "Authorization": f"Bearer {app.config['SLACK_CHANNEL_TOKEN']}"
    }
    json_to_post = {
        "channel": channel,
        "text": f"From {user_name} ({user_email}):\n{json_data['message']}"
    }

    logger.debug("======notify() json_to_post======")
    logger.debug(json_to_post)

    response = requests.post(url = target_url, headers = request_header, json = json_to_post, verify = False)

    notification_results = {'Slack': None, 'Email': None}
    # Note: Slack API wraps the error response in the 200 response instead of using non-200 status code
    # Callers should always check the value of the 'ok' params in the response
    if response.status_code == 200:
        result = response.json()
        # 'ok' filed is boolean value
        if 'ok' in result:
            if result['ok']:
                output = {
                    "channel": channel,
                    "message": json_data['message'],
                    "user_name": user_name,
                    "user_email": user_email
                }

                logger.debug("======notify() Sent Notification Summary======")
                logger.info(output)

                notification_results['Slack'] = output
            else:
                logger.error(f"Unable to notify Slack channel: {channel} with the message: {json_data['message']}")
                logger.debug("======notify() response json from Slack API======")
                logger.debug(result)

                # https://api.slack.com/methods/chat.postMessage#errors
                if 'error' in result:
                    bad_request_error(result['error'])
                else:
                    internal_server_error("Slack API unable to process the request, 'error' param/field missing from Slack API response json")
        else:
            internal_server_error("The 'ok' param/field missing from Slack API response json")
    else:
        internal_server_error("Failed to send a request to Slack API")

    if 'send_to_email' in json_data and json_data['send_to_email']:
        logger.debug(json_data['send_to_email'])
        try:
            subject_line = app.config['MAIL_SUBJECT_LINE'].format(  user_name=user_name
                                                                    ,user_email=user_email)
            email_admin_list(   message_text=json_data['message']
                                ,subject=subject_line)
            output = {
                "email_recipient_list": str(app.config['MAIL_ADMIN_LIST']),
                "message": json_data['message'],
                "user_name": user_name,
                "user_email": user_email
            }

            logger.debug("======notify() Sent Email Summary======")
            logger.info(output)

            notification_results['Email'] = output
        except Exception as e:
            logger.error(f"Failed to send email message. {str(e)}", exc_info=True)
            return jsonify( f"Failed to send email message, after Slack notification resulted in"
                            f" {notification_results['Slack']}"), 400

    return jsonify(notification_results)

####################################################################################################
## Internal Functions
####################################################################################################

"""
Validate the provided token when Authorization header presents
Parameters
----------
request : flask.request object
    The Flask http request object
"""
def _validate_token_if_auth_header_exists(request):
    # No matter if token is required or not, when an invalid token provided,
    # we need to tell the client with a 401 error
    # HTTP header names are case-insensitive
    # request.headers.get('Authorization') returns None if the header doesn't exist
    if request.headers.get('Authorization') is not None:
        user_token = auth_helper_instance.getAuthorizationTokens(request.headers)

        # When the Authorization header provided but the user_token is a flask.Response instance,
        # it MUST be a 401 error with message.
        # That's how commons.auth_helper.getAuthorizationTokens() was designed
        if isinstance(user_token, Response):
            # We wrap the message in a json and send back to requester as 401 too
            # The Response.data returns binary string, need to decode
            unauthorized_error(user_token.get_data().decode())

        # Also check if the parsed token is invalid or expired
        # Set the second parameter as False to skip group check
        user_info = auth_helper_instance.getUserInfo(user_token, False)

        if isinstance(user_info, Response):
            unauthorized_error(user_info.get_data().decode())


# Use the Flask request.args MultiDict to see if 'reindex' is a URL parameter passed in with the
# request and if it indicates reindexing should be supressed. Default to reindexing in all other cases.
def _suppress_reindex() -> bool:
    if 'reindex' not in request.args:
        return False
    reindex_str = request.args.get('reindex').lower()
    if reindex_str == 'false':
        return True
    elif reindex_str == 'true':
        return False
    raise Exception(f"The value of the 'reindex' parameter must be True or False (case-insensitive)."
                    f" '{request.args.get('reindex')}' is not recognized.")

####################################################################################################
## Ingest API Endpoints
####################################################################################################

"""
For each element in a list of identifiers, return accessibility information appropriate
for the user authorization of the Request.

An HTTP 400 Response is returned for reasons described in the error message, such as
not providing the list of identifiers.

An HTTP 401 Response is returned when a token is presented that is not valid.

An HTTP 500 is returned for unexpected errors

Parameters
----------
request : flask.request
    The flask http request object that containing the Authorization header
    with a valid Globus groups token for checking group information. The
    Request will have the Content-type header set to application/json. The
    JSON body of the request will contain a JSON Array of strings with
    UUID or HuBMAP-ID strings.

Returns
-------
json
    Valid JSON for a single JSON Object containing only JSON Objects, one per
    entity evaluated.  This enclosing Object will have keys for each identifier
    submitted with the request, whose value is a JSON Object containing
    accessibility information for the entity. Each entity JSON Object will contain
    "valid_id": true/false,  --true if the id resolves to a HuBMAP Dataset or Upload
    ----------  below here only returned if valid_id == true
    "access_allowed": true/false --true if the user is allowed to access the data for this entity
    ----------  below here only returned if access_allowed == true
    "hubmap_id": "<corresponding HuBMAP ID of the requested id>",
    "uuid": "<uuid of Dataset or Upload>",
    "entity_type": "<Dataset or Upload>",
    "file_system_path": "<full absolute file system path to the Dataset or upload>"
"""
@app.route('/entities/accessible-data-directories', methods=['POST'])
def get_accessible_data_directories():
    dataset_helper = DatasetHelper()

    # If not token is provided or an invalid token is provided, return a 401 error.
    if request.headers.get('Authorization') is None:
        unauthorized_error('A valid token must be provided.')

    # If an invalid token provided, we need to tell the client with a 401 error, rather
    # than a 500 error later if the token is not good.
    _validate_token_if_auth_header_exists(request)

    # Get user token from Authorization header
    # Get the user token from Authorization header
    user_token = auth_helper_instance.getAuthorizationTokens(request.headers)

    # Get user group information which will be used to determine accessibility on
    # a per-entity basis.
    user_data_access_level = auth_helper_instance.getUserDataAccessLevel(request)

    if not request.is_json:
        bad_request_error("A json body and appropriate Content-Type header are required.")
    json_payload = request.get_json()
    if not isinstance(json_payload, list) or not json_payload:
        bad_request_error('The Request payload must be a non-empty JSON Array of strings.')
    for identifier in json_payload:
        if not isinstance(identifier, str):
            bad_request_error('The Request payload JSON Array must contain only identifier strings.')

    payload_accessibility_dict = {}
    for identifier in json_payload:
        try:
            identifier_accessibility_dict = dataset_helper.get_entity_accessibility(identifier
                                                                                    , user_token
                                                                                    , user_data_access_level=user_data_access_level)
            payload_accessibility_dict[identifier] = identifier_accessibility_dict
        except (HTTPException, sdk_helper.HTTPException) as he:
            return jsonify({'error': he.get_description()}), he.get_status_code()
        except ValueError as ve:
            logger.error(str(ve))
            return jsonify({'error': str(ve)}), 400
        except Exception as e:
            logger.error(e, exc_info=True)
            return Response("Unexpected error: " + str(e), 500)
    return jsonify(payload_accessibility_dict), 200

"""
Retrieve the path of Datasets or Uploads relative to the Globus endpoint mount point give from a list of entity uuids
This is a public endpoint, not authorization token is required.
Input
--------
Input is via POST request body data as a Json array of Upload or Dataset HuBMAP IDs or UUIDs.
Traditionally this would be a GET method as it isn't posting/creating anything, but we need to
use the ability to send request body data with this method, even though GET can support a 
request body with data we've found that our Gateway service (AWS API Gateway) doesn't support
GET with data.
ds_uuid_list : list
    ds_uuid : str
        The HuBMAP ID (e.g. HBM123.ABCD.456) or UUID of target dataset or upload
Example: ["HBM123.ABCD.456", "HBM939.ZYES.733", "a9382ce928b32839dbe83746f383ea8"]
Returns
--------
out_list : json array of json objects with information about the individual
           entities where the json objects have the following properties:
                                 id: the id of the dataset as sent in the input
                        entity_type: The type of entity ("Upload" or "Dataset")
                           rel_path: the path on the file system where the data for the entity sits relative to the mount point of the Globus endpoint
               globus_endpoint_uuid: The Globus id of the endpoint where the data can be downloaded
Example:
   [{
       "id":"HBM123.ABCD.4564",
       "entity_type":"Dataset",
       "hubmap_id":"HBM123.ABCD.4564",
       "rel_path":"/consortium/IEC Testing/db382ce928b32839dbe83746f384e354"
       "globus_endpoint_uuid":"a935-ce928b328-39dbe83746f3-84bdae",
       "uuid", "db382ce928b32839dbe83746f384e354"
    },
    {
       "id":"HBM478.BYRE.7748",
       "entity_type":"Dataset",
       "rel_path":"/consortium/IEC Testing/db382ce928b32839dbe83746f384e354"
       "globus_endpoint_uuid":"a935-ce928b328-39dbe83746f3-84bdae"
    }]
"""
@app.route('/entities/file-system-rel-path', methods=['POST'])
def get_file_system_relative_path():
    ds_uuid_list = request.json
    out_list = []
    error_id_list = []
    for ds_uuid in ds_uuid_list:
        try:
            ent_recd = {}
            ent_recd['id'] = ds_uuid
            dset = __get_entity(ds_uuid, auth_header="Bearer " + auth_helper_instance.getProcessSecret())
            ent_type_m = __get_dict_prop(dset, 'entity_type')
            ent_recd['entity_type'] = ent_type_m
            group_uuid = __get_dict_prop(dset, 'group_uuid')
            if ent_type_m is None or ent_type_m.strip() == '':
                error_id = {'id': ds_uuid, 'message': 'id not for Dataset, Publication or Upload', 'status_code': 400}
                error_id_list.append(error_id)
            ent_type = ent_type_m.lower().strip()
            ingest_helper = IngestFileHelper(app.config)
            if ent_type == 'upload':
                path = ingest_helper.get_upload_directory_relative_path(group_uuid=group_uuid, upload_uuid=dset['uuid'])
            elif get_entity_type_instanceof(ent_type, 'Dataset', auth_header="Bearer " + auth_helper_instance.getProcessSecret()):
                is_phi = __get_dict_prop(dset, 'contains_human_genetic_sequences')
                if group_uuid is None:
                    error_id = {'id': ds_uuid, 'message': 'Unable to find group uuid on dataset', 'status_code': 400}
                    error_id_list.append(error_id)
                if is_phi is None:
                    error_id = {'id': ds_uuid,
                                'message': f"contains_human_genetic_sequences is not set on {ent_type} dataset",
                                'status_code': 400}
                    error_id_list.append(error_id)
                path = ingest_helper.get_dataset_directory_relative_path(dset, group_uuid, dset['uuid'])
            else:
                error_id = {'id': ds_uuid, 'message': f'Unhandled entity type, must be Upload, Publication or Dataset, '
                                                      f'found {ent_type_m}', 'status_code': 400}
                error_id_list.append(error_id)
            ent_recd['rel_path'] = path['rel_path']
            ent_recd['globus_endpoint_uuid'] = path['globus_endpoint_uuid']
            ent_recd['uuid'] = (__get_dict_prop(dset, 'uuid'))
            ent_recd['hubmap_id'] = (__get_dict_prop(dset, 'hubmap_id'))
            out_list.append(ent_recd)
        except HTTPException as hte:
            error_id = {'id': ds_uuid, 'message': hte.get_description(), 'status_code': hte.get_status_code()}
            error_id_list.append(error_id)
        except Exception as e:
            logger.error(e, exc_info=True)
            error_id = {'id': ds_uuid, 'message': str(e), 'status_code': 500}
            error_id_list.append(error_id)
    if len(error_id_list) > 0:
        status_code = 400
        for each in error_id_list:
            if each['status_code'] == 500:
                status_code = 500
        return jsonify(error_id_list), status_code
    return jsonify(out_list), 200


@app.route('/uploads/<ds_uuid>/file-system-abs-path', methods=['GET'])
@app.route('/datasets/<ds_uuid>/file-system-abs-path', methods=['GET'])
def get_file_system_absolute_path(ds_uuid: str):
    try:
        r = requests.get(app.config['UUID_WEBSERVICE_URL'] + "/" + ds_uuid)
        r.raise_for_status()
    except Exception as e:
        status_code = r.status_code
        response_text = r.text
        if status_code == 404:
            not_found_error(response_text)
        elif status_code == 500:
            internal_server_error(response_text)
        else:
            return Response(response_text, status_code)
    ds_uuid = r.json().get("uuid")
    try:
        path = get_dataset_abs_path(ds_uuid)
        return jsonify({'path': path}), 200
    except ResponseException as re:
        return re.response
    except HTTPException as hte:
        return Response(f"Error while getting file-system-abs-path for {ds_uuid}: " +
                        hte.get_description(), hte.get_status_code())
    except Exception as e:
        logger.error(e, exc_info=True)
        return Response(f"Unexpected error while retrieving entity {ds_uuid}: " + str(e), 500)


@app.route('/uploads/file-system-abs-path', methods=['POST'])
@app.route('/datasets/file-system-abs-path', methods=['POST'])
def get_mulltiple_file_system_absolute_paths():
    out_list = []
    if not request.is_json:
        return Response("json request required", 400)
    uuids_list = request.json
    is_valid = validate_json_list(uuids_list)
    if not is_valid:
        bad_request_error("json must be a list of uuids")
    try:
        ingest_helper = IngestFileHelper(app.config)
        with neo4j_driver_instance.session() as neo_session:
            q = (f"MATCH (entity) "
                 f"WHERE entity.uuid in {uuids_list} OR entity.hubmap_id in {uuids_list} "
                 f"RETURN entity.entity_type AS entity_type, "
                 f"entity.group_uuid AS group_uuid, entity.contains_human_genetic_sequences as contains_human_genetic_sequences, " 
                 f"entity.data_access_level AS data_access_level, entity.status AS status, entity.uuid AS uuid, entity.hubmap_id AS hubmap_id")
            result = neo_session.run(q).data()
            returned_uuids = []
            for entity in result:
                returned_uuids.append(entity['uuid'])
                if entity.get('hubmap_id'):
                    returned_uuids.append(entity['hubmap_id'])
            for uuid in uuids_list:
                if uuid not in returned_uuids:
                    out_list.append({'uuid': uuid, 'error': 'No results for given uuid'})
            if len(result) < 1:
                raise ResponseException("No result found for uuids in list", 400)
        for entity in result:
            ent_type = entity['entity_type']
            group_uuid = entity['group_uuid']
            is_phi = entity['contains_human_genetic_sequences']
            ds_uuid = entity['uuid']
            if ent_type is None or ent_type.strip() == '':
                raise ResponseException(f"Entity with uuid:{ds_uuid} needs to be a Dataset or Upload.", 400)
            if ent_type.lower().strip() == 'upload':
                out_list.append({'path': ingest_helper.get_upload_directory_absolute_path(group_uuid=group_uuid, upload_uuid=ds_uuid), 'uuid': ds_uuid})
                continue
            if not get_entity_type_instanceof(ent_type, 'Dataset', auth_header=request.headers.get("AUTHORIZATION")):
                raise ResponseException(f"Entity with uuid: {ds_uuid} is not a Dataset, Publication or upload", 400)
            if group_uuid is None:
                raise ResponseException(f"Unable to find group uuid on dataset {ds_uuid}", 400)
            if is_phi is None:
                raise ResponseException(f"Contains_human_genetic_sequences is not set on dataset {ds_uuid}", 400)
            path = ingest_helper.get_dataset_directory_absolute_path(entity, group_uuid, ds_uuid)
            out_list.append({'uuid': ds_uuid, 'path': path})
        return jsonify(out_list), 200
    except ResponseException as re:
        return re.response
    except HTTPException as hte:
        return Response(f"Error while getting file-system-abs-path for entities: " + hte.get_description(), hte.get_status_code())
    except Exception as e:
        logger.error(e, exc_info=True)
        return Response(f"Unexpected error while retrieving entities: " + str(e), 500)

#passthrough method to call mirror method on entity-api
#this is need by ingest-pipeline that can only call
#methods via http (running on the same machine for security reasons)
#and ingest-api will for the foreseeable future run on the same
#machine
@app.route('/entities/<entity_uuid>', methods = ['GET'])
#@secured(groups="HuBMAP-read")
def get_entity(entity_uuid):
    try:
        entity = __get_entity(entity_uuid, auth_header = request.headers.get("AUTHORIZATION"))
        return jsonify (entity), 200
    except HTTPException as hte:
        return Response(hte.get_description(), hte.get_status_code())
    except Exception as e:
        logger.error(e, exc_info=True)
        return Response(f"Unexpected error while retrieving entity {entity_uuid}: " + str(e), 500)


# Create derived dataset
"""
Input JSON example with "source_dataset_uuid" being an array of uuids:
{
"source_dataset_uuid":["6e24ba7b41725e4b06630192476f8364", "hyt0tse652d3c4f22ace7f21fd64208ac"],
"derived_dataset_name":"Test derived dataset 1",
"derived_dataset_types":["QX11", "xxx"]
}

OR with "source_dataset_uuid" being a single uuid string to support past cases:

{
"source_dataset_uuid": "6e24ba7b41725e4b06630192476f8364",
"derived_dataset_name":"Test derived dataset 1",
"derived_dataset_types":["QX11", "xxx"]
}

Output JSON example:
{
    "derived_dataset_uuid": "78462470866bdda77deaaebe21ae7151",
    "full_path": "/hive/hubmap-dev/data/consortium/IEC Testing Group/78462470866bdda77deaaebe21ae7151",
    "group_display_name": "IEC Testing Group",
    "group_uuid": "5bd084c8-edc2-11e8-802f-0e368f3075e8"
}
"""
@app.route('/datasets/derived', methods=['POST'])
#@secured(groups="HuBMAP-read")
def create_derived_dataset():
    # Token is required
    nexus_token = None
    try:
        nexus_token = AuthHelper.parseAuthorizationTokens(request.headers)
    except Exception:
        internal_server_error("Unable to parse globus token from request header")

    require_json(request)

    json_data = request.json

    logger.info("++++++++++Calling /datasets/derived")
    logger.info("++++++++++Request:" + json.dumps(json_data))

    if 'source_dataset_uuids' not in json_data:
        bad_request_error("The 'source_dataset_uuids' property is required.")

    if 'derived_dataset_name' not in json_data:
        bad_request_error("The 'derived_dataset_name' property is required.")

    if 'derived_dataset_types' not in json_data:
        bad_request_error("The 'derived_dataset_types' property is required.")

    # source_dataset_uuids can either be a single uuid string OR a json array
    if not isinstance(json_data['source_dataset_uuids'], (str, list)):
        bad_request_error("The 'source_dataset_uuids' must either be a json string or an array")

    # Ensure the derived_dataset_types is json array
    if not isinstance(json_data['derived_dataset_types'], list):
        bad_request_error("The 'derived_dataset_types' must be a json array")

    # Ensure the arrays are not empty
    if isinstance(json_data['source_dataset_uuids'], list) and len(json_data['source_dataset_uuids']) == 0:
        bad_request_error("The 'source_dataset_uuids' can not be an empty array")

    if len(json_data['derived_dataset_types']) == 0:
        bad_request_error("The 'derived_dataset_types' can not be an empty array")

    try:
        dataset = Dataset(app.config)
        new_record = dataset.create_derived_datastage(nexus_token, json_data)

        return jsonify( new_record ), 201
    except HTTPException as hte:
        status_code = hte.get_status_code()
        response_text = hte.get_description()

        if status_code == 400:
            bad_request_error(response_text)
        elif status_code == 401:
            unauthorized_error(response_text)
        elif status_code == 404:
            not_found_error(response_text)
        elif status_code == 500:
            internal_server_error(response_text)
        else:
            return Response(response_text, status_code)
    except Exception as e:
        logger.error(e, exc_info=True)
        internal_server_error("Unexpected error while creating derived dataset: " + str(e))


@app.route('/datasets', methods=['POST'])
@app.route('/publications', methods=['POST'])
def create_datastage():
    if not request.is_json:
        return Response("json request required", 400)
    if request.path.lower() == '/datasets':
        entity_type = "dataset"
    elif request.path.lower() == '/publications':
        entity_type = "publication"
    try:
        dataset_request = request.json
        auth_helper = AuthHelper.configured_instance(app.config['APP_CLIENT_ID'], app.config['APP_CLIENT_SECRET'])
        auth_tokens = auth_helper.getAuthorizationTokens(request.headers)
        if isinstance(auth_tokens, Response):
            return(auth_tokens)
        elif isinstance(auth_tokens, str):
            token = auth_tokens
        elif 'nexus_token' in auth_tokens:
            token = auth_tokens['nexus_token']
        else:
            return(Response("Valid nexus auth token required", 401))

        requested_group_uuid = None
        if 'group_uuid' in dataset_request:
            requested_group_uuid = dataset_request['group_uuid']

        ingest_helper = IngestFileHelper(app.config)
        requested_group_uuid = auth_helper.get_write_group_uuid(token, requested_group_uuid)
        dataset_request['group_uuid'] = requested_group_uuid

        # Check URL parameters before proceeding to any CRUD operations, halting on validation failures.
        #
        # Check if re-indexing is to be suppressed after entity creation.
        try:
            suppress_reindex = _suppress_reindex()
        except Exception as e:
            bad_request_error(str(e))

        post_url = f"{commons_file_helper.ensureTrailingSlashURL(app.config['ENTITY_WEBSERVICE_URL'])}" \
                   f"entities/{entity_type}" \
                   f"{'?reindex=False' if suppress_reindex else ''}"
        response = requests.post(post_url
                                 , json = dataset_request
                                 , headers = {'Authorization': 'Bearer ' + token, 'X-Hubmap-Application':'ingest-api' }
                                 , verify = False)

        if response.status_code != 200:
            return Response(response.text, response.status_code)
        new_dataset = response.json()

        ingest_helper.create_dataset_directory(new_dataset, requested_group_uuid, new_dataset['uuid'])

        return jsonify(new_dataset)
    except werkzeug.exceptions.HTTPException as hte:
        return Response(hte.description, hte.code)
    except HTTPException as hte:
        return Response(hte.get_description(), hte.get_status_code())
    except Exception as e:
        logger.error(e, exc_info=True)
        return Response("Unexpected error while creating a dataset: " + str(e) + "  Check the logs", 500)

@app.route('/datasets/components', methods=['POST'])
def multiple_components():
    if not request.is_json:
        return Response("json request required", 400)
    try:
        component_request = request.json
        auth_helper = AuthHelper.configured_instance(app.config['APP_CLIENT_ID'], app.config['APP_CLIENT_SECRET'])
        auth_tokens = auth_helper.getAuthorizationTokens(request.headers)
        if isinstance(auth_tokens, Response):
            return(auth_tokens)
        elif isinstance(auth_tokens, str):
            token = auth_tokens
        else:
            return(Response("Valid globus groups token required", 401))

        # Check that `dataset_link_abs_dir` exists for both datasets and that it is a valid directory
        json_data_dict = request.get_json()
        for dataset in json_data_dict.get('datasets'):
            if 'dataset_link_abs_dir' in dataset:
                if not os.path.exists(dataset['dataset_link_abs_dir']):
                    return Response(f"The filepath specified with 'dataset_link_abs_dir' does not exist: {dataset['dataset_link_abs_dir']}", 400)
                if not os.path.isdir(dataset.get('dataset_link_abs_dir')):
                    return Response(f"{dataset.get('dataset_link_abs_dir')} is not a directory", 400)
            else:
                return Response("Required field 'dataset_link_abs_dir' is missing from dataset", 400)

            if not 'contains_human_genetic_sequences' in dataset:
                return Response("Missing required keys in request json: datasets.contains_human_genetic_sequences", 400)

        requested_group_uuid = None
        if 'group_uuid' in component_request:
            requested_group_uuid = component_request['group_uuid']

        ingest_helper = IngestFileHelper(app.config)
        requested_group_uuid = auth_helper.get_write_group_uuid(token, requested_group_uuid)
        component_request['group_uuid'] = requested_group_uuid

        # Check URL parameters before proceeding to any CRUD operations, halting on validation failures.
        #
        # Check if re-indexing is to be suppressed after entity creation.
        try:
            suppress_reindex = _suppress_reindex()
        except Exception as e:
            bad_request_error(e)

        post_url = f"{commons_file_helper.ensureTrailingSlashURL(app.config['ENTITY_WEBSERVICE_URL'])}" \
                   f"datasets/components" \
                   f"{'?reindex=False' if suppress_reindex else ''}"
        response = requests.post(post_url, json = component_request, headers = {'Authorization': 'Bearer ' + token, 'X-Hubmap-Application':'ingest-api' }, verify = False)

        if response.status_code != 200:
            return Response(response.text, response.status_code)
        new_datasets_list = response.json()
        for dataset in new_datasets_list:
            if dataset.get('dataset_link_abs_dir'):
                new_directory_path = ingest_helper.get_dataset_directory_absolute_path(dataset, requested_group_uuid, dataset['uuid'])
                logger.info(f"Creating a directory as: {new_directory_path} with a symbolic link to: {dataset['dataset_link_abs_dir']}")
                os.symlink(dataset['dataset_link_abs_dir'], new_directory_path, True)
            else:
                return Response("Required field 'dataset_link_abs_dir' is missing from dataset", 400)

        return jsonify(new_datasets_list)
    except HTTPException as hte:
        return Response(hte.get_description(), hte.get_status_code())
    except Exception as e:
        logger.error(e, exc_info=True)
        return Response("Unexpected error while creating a dataset: " + str(e) + " Check the logs", 500)


def obj_to_dict(obj) -> dict:
    """
    Convert the obj[ect] into a dict, but deeply.

    Note: The Python builtin 'vars()' does not work here because of the way that some of the classes
    are defined.
    """
    return json.loads(
        json.dumps(obj, default=lambda o: getattr(o, '__dict__', str(o)))
    )

def metadata_json_based_on_creation_action(creation_action: str) -> bool:
    """
    https://github.com/hubmapconsortium/ingest-api/issues/575
    Currently metadata.json files are generated for primary datasets only, change this so metadata.json file
    are additionally generated for processed datasets where creation_action == 'Central Process' or
    'Lab Process' or 'External Process' but not for multi-assay component datasets (component datasets match
    creation_action == 'Multi-Assay Split)
    """
    if creation_action is None:
        return False
    return creation_action.lower() in [x.lower() for x in ['Central Process', 'Lab Process', 'External Process']]

# Needs to be triggered in the workflow or manually?!
@app.route('/datasets/<identifier>/publish', methods=['PUT'])
@secured(groups="HuBMAP-read")
def publish_datastage(identifier):
    """
    Needs a dataset in 'Q/A' status and needs to be primary.

    http://18.205.215.12:7474/browser/ (see app.cfg for username and password)
    Use the data from this query...
    match (dn:Donor)-[*]->(s:Sample)-[:ACTIVITY_INPUT]->(:Activity)-[:ACTIVITY_OUTPUT]->(ds:Dataset {status:'QA'})
    where not ds.ingest_metadata is null and not ds.contacts is null and not ds.contributors is null
    and ds.data_access_level in ['consortium', 'protected'] and not dn.metadata is null
    return ds.uuid, ds.data_access_level, ds.group_name;

    From this query 'ds.data_access_level' tells you whether you need to use the directory in
    GLOBUS_PUBLIC_ENDPOINT_FILEPATH (public), GLOBUS_CONSORTIUM_ENDPOINT_FILEPATH (consortium),
    or GLOBUS_PROTECTED_ENDPOINT_FILEPATH (protected).
    In that directory create the directories with the values of `ds.group_name/ds.uuid`.
    In Globus Groups (https://app.globus.org/groups) you will also need to be associated with
    the group for `ds.group_name`.
    Use 'https://ingest.dev.hubmapconsortium.org/' to get the 'Local Storage/info/groups_token' for the $TOKEN

    Then use this call replacing ds.uuid with the value of ds.uuid...
    curl -v --location --request PUT 'http://localhost:8484/datasets/ds.uuid/publish?suspend-indexing-and-acls=true' --header "Authorization: Bearer $TOKEN"

    Test using both protected and consortium identifiers.
    """
    try:
        auth_helper = AuthHelper.configured_instance(app.config['APP_CLIENT_ID'], app.config['APP_CLIENT_SECRET'])
        user_info = auth_helper.getUserInfoUsingRequest(request, getGroups=True)
        if user_info is None:
            return Response("Unable to obtain user information for auth token", 401)
        if isinstance(user_info, Response):
            return user_info

        if 'hmgroupids' not in user_info:
            return Response("User has no valid group information to authorize publication.", 403)
        if data_admin_group_uuid not in user_info['hmgroupids']:
            return Response("User must be a member of the HuBMAP Data Admin group to publish data.", 403)

        if identifier is None or len(identifier) == 0:
            abort(400, jsonify( { 'error': 'identifier parameter is required to publish a dataset' } ))
        r = requests.get(app.config['UUID_WEBSERVICE_URL'] + "/" + identifier, headers={'Authorization': request.headers["AUTHORIZATION"]})
        if r.ok is False:
            raise ValueError("Cannot find specimen with identifier: " + identifier)
        dataset_uuid = json.loads(r.text)['hm_uuid']
        is_primary = dataset_is_primary(dataset_uuid)
        is_component = dataset_is_multi_assay_component(dataset_uuid)
        suspend_indexing_and_acls = string_helper.isYes(request.args.get('suspend-indexing-and-acls'))
        no_indexing_and_acls = False
        if suspend_indexing_and_acls:
            no_indexing_and_acls = True

        donors_to_reindex = []
        with neo4j_driver_instance.session() as neo_session:
            #recds = session.run("Match () Return 1 Limit 1")
            #for recd in recds:
            #    if recd[0] == 1:
            #        is_connected = True
            #    else:
            #        is_connected = False

            #look at all of the ancestors
            #gather uuids of ancestors that need to be switched to public access_level
            #grab the id of the donor ancestor to use for reindexing
            q = f"MATCH (dataset:Dataset {{uuid: '{dataset_uuid}'}})<-[:ACTIVITY_OUTPUT]-(e1)<-[:ACTIVITY_INPUT|ACTIVITY_OUTPUT*]-(all_ancestors:Entity) RETURN distinct all_ancestors.uuid as uuid, all_ancestors.entity_type as entity_type, all_ancestors.data_access_level as data_access_level, all_ancestors.status as status, all_ancestors.metadata as metadata"
            rval = neo_session.run(q).data()
            uuids_for_public = []
            has_donor = False
            for node in rval:
                uuid = node['uuid']
                entity_type = node['entity_type']
                data_access_level = node['data_access_level']
                status = node['status']
                metadata = node.get("metadata")
                if entity_type == 'Sample':
                    if data_access_level != 'public':
                        uuids_for_public.append(uuid)
                elif entity_type == 'Donor':
                    has_donor = True
                    if is_primary:
                        if metadata is None or metadata.strip() == '':
                            return jsonify({"error": f"donor.metadata is missing for {dataset_uuid}"}), 400
                        metadata = metadata.replace("'", '"')
                        metadata_dict = json.loads(metadata)
                        has_organ_donor_data = metadata_dict.get('organ_donor_data') is not None
                        has_living_donor_data = metadata_dict.get('living_donor_data') is not None
                        # Use the bit-wise xor operator with bool values to determine if
                        # exactly one of required Donor characteristics is indicated in the metadata.
                        if not xor(has_organ_donor_data, has_living_donor_data):
                            return jsonify({"error": f"donor.metadata.organ_donor_data or "
                                                     f"donor.metadata.living_donor_data required. "
                                                     f"Both cannot be None. Both cannot be present. Only one."}), 400
                    donors_to_reindex.append(uuid)
                    if data_access_level != 'public':
                        uuids_for_public.append(uuid)
                elif entity_type == 'Dataset':
                    if status != 'Published':
                        return Response(f"{dataset_uuid} has an ancestor dataset that has not been Published. "
                                        f"Will not Publish. Ancestor dataset is: {uuid}", 400)

            if has_donor is False:
                return Response(    response=f"{dataset_uuid}: no donor found for dataset, will not Publish"
                                    , status=400)

            #get info for the dataset to be published
            q = f"MATCH (e:Dataset {{uuid: '{dataset_uuid}'}}) RETURN " \
                "e.uuid as uuid, e.entity_type as entitytype, e.status as status, " \
                "e.data_access_level as data_access_level, e.group_uuid as group_uuid, " \
                "e.contacts as contacts, e.contributors as contributors, e.status_history as status_history"
            if is_primary:
                q += ", e.ingest_metadata as ingest_metadata"
            rval = neo_session.run(q).data()
            dataset_entitytype = rval[0]['entitytype']
            dataset_status = rval[0]['status']
            dataset_data_access_level = rval[0]['data_access_level']
            dataset_group_uuid = rval[0]['group_uuid']
            dataset_contacts = rval[0]['contacts']
            dataset_contributors = rval[0]['contributors']
            dataset_ingest_matadata_dict = None
            if is_primary:
                dataset_ingest_metadata = rval[0].get('ingest_metadata')
                if dataset_ingest_metadata is not None:
                    dataset_ingest_matadata_dict: dict =\
                        string_helper.convert_str_literal(dataset_ingest_metadata)
                logger.info(f"publish_datastage; ingest_matadata: {dataset_ingest_matadata_dict}")
            if not get_entity_type_instanceof(dataset_entitytype, 'Dataset', auth_header="Bearer " + auth_helper_instance.getProcessSecret()):
                return Response(f"{dataset_uuid} is not a dataset will not Publish, entity type is {dataset_entitytype}", 400)
            if not dataset_status == 'QA':
                return Response(f"{dataset_uuid} is not in QA state will not Publish, status is {dataset_status}", 400)

            auth_tokens = auth_helper.getAuthorizationTokens(request.headers)
            entity_instance = EntitySdk(token=auth_tokens, service_url=app.config['ENTITY_WEBSERVICE_URL'])
            has_entity_lab_processed_data_type = dataset_has_entity_lab_processed_data_type(dataset_uuid)

            ingest_helper: IngestFileHelper = IngestFileHelper(app.config)
            
            #find any *metadata.tsv files in this dataset and check to make sure they are writable
            dset_directory_to_check = ingest_helper.dataset_directory_absolute_path(dataset_data_access_level, dataset_group_uuid, dataset_uuid, False) 
            #make sure directory exists and is writable
            if not os.path.isdir(dset_directory_to_check) or not os.access(dset_directory_to_check, os.W_OK):
                return jsonify({"error":f"ERROR: Dataset directory {dset_directory_to_check} is not writable or doesn't exist"}), 500
            
            tsv_files = glob.glob(os.path.join(dset_directory_to_check,"*metadata.tsv"))
            for tsv_file in tsv_files:
                if not os.access(tsv_file, os.W_OK):
                    return jsonify({"error": f"ERROR: metadata.tsv file {tsv_file} is not writable"}), 500

            #if we need to strip tsv files make sure the directory where we will put backups exists and is writable
            if len(tsv_files) > 0:
                if tsv_backup_dir is None:
                    return jsonify({"error": "tsv backup directory is not set in configuration"}), 500
                if not os.path.isdir(tsv_backup_dir):
                    return jsonify({"error": f"ERROR: backup directory {tsv_backup_dir} is not a directory or does not exist"}), 500
                if not os.access(tsv_backup_dir, os.W_OK):
                    return jsonify({"error": f"ERROR: backup directory {tsv_backup_dir} is not writable"}), 500

            #grab the columns that will be blanked from the tsvs now.  In case there is an issue, we'll fail 
            #now before publishing the dataset
            tsv_columns_to_blank = prov_schema_helper.get_metadata_properties_to_exclude()
            
            #set up a status_history list to add a "Published" entry to below
            if 'status_history' in rval[0]:
                status_history_str = rval[0]['status_history']
                if status_history_str is None:
                    status_history_list = []
                else:
                    status_history_list = string_helper.convert_str_literal(status_history_str)
            else:
                status_history_list = []
            
            logger.info(f'is_primary: {is_primary}; has_entity_lab_processed_data_type: {has_entity_lab_processed_data_type}')

            if is_primary or has_entity_lab_processed_data_type or is_component:
                if dataset_contacts is None or dataset_contributors is None:
                    return jsonify({"error": f"{dataset_uuid} missing contacts or contributors. Must have at least one of each"}), 400
                #dataset_contacts = dataset_contacts.replace("'", '"')
                #dataset_contributors = dataset_contributors.replace("'", '"')
                if len(dataset_contacts) < 1 or len(dataset_contributors) < 1:
                    return jsonify({"error": f"{dataset_uuid} missing contacts or contributors. Must have at least one of each"}), 400
                dataset_contacts = string_helper.convert_str_literal(dataset_contacts)
                dataset_contributors = string_helper.convert_str_literal(dataset_contributors)

            data_access_level = dataset_data_access_level
            #if consortium access level convert to public dataset, if protected access leave it protected
            relink_cmd = ""
            if dataset_data_access_level == 'consortium':
                #before moving check to see if there is currently a link for the dataset in the assets directory
                asset_dir = ingest_helper.dataset_asset_directory_absolute_path(dataset_uuid)
                asset_dir_exists = os.path.exists(asset_dir)
                components_primary_path = None
                if is_component:
                    components_primary_path = get_components_primary_path(dataset_uuid)
                    relink_cmd = ingest_helper.move_dataset_files_for_publishing(dataset_uuid, dataset_group_uuid, 'consortium', False, is_component, components_primary_path)
                
                uuids_for_public.append(dataset_uuid)
                data_access_level = 'public'
                if asset_dir_exists or is_component:
                    asset_link_cmd = ingest_helper.relink_to_public(dataset_uuid, is_component, components_primary_path)
                    if not asset_link_cmd is None:
                        relink_cmd = relink_cmd + " " + asset_link_cmd
                        

            auth_tokens = auth_helper.getAuthorizationTokens(request.headers)
            entity_instance = EntitySdk(token=auth_tokens, service_url=app.config['ENTITY_WEBSERVICE_URL'])
            doi_info = None

            entity = entity_instance.get_entity_by_id(dataset_uuid)
            entity_dict = vars(entity)

            # Generating DOI's for lab processed/derived data as well as IEC/pipeline/airflow processed/derived data).
            if is_primary or has_entity_lab_processed_data_type or is_component:
                # DOI gets generated here
                # Note: moved dataset title auto generation to entity-api - Zhou 9/29/2021
                datacite_doi_helper = DataCiteDoiHelper()

                # Checks both whether a doi already exists, as well as if it is already findable. If True, DOI exists and is findable
                # If false, DOI exists but is not yet in findable. If None, doi does not yet exist. 
                try:
                    doi_exists = datacite_doi_helper.check_doi_existence_and_state(entity_dict)
                except DataciteApiException as e:
                    logger.exception(f"Exception while fetching doi for {dataset_uuid}")
                    return jsonify({"error": f"Error occurred while trying to confirm existence of doi for {dataset_uuid}. {e}"}), 500
                # Doi does not exist, create draft then make it findable
                if doi_exists is None:
                    try:
                        datacite_doi_helper.create_dataset_draft_doi(entity_dict, check_publication_status=False)
                    except DataciteApiException as e:
                        logger.exception(f"Exception while creating a draft doi for {dataset_uuid}")
                        return jsonify({"error": f"Error occurred while trying to create a draft doi for {dataset_uuid}. {e}"}), 500
                    # This will make the draft DOI created above 'findable'....
                    try:
                        doi_info = datacite_doi_helper.move_doi_state_from_draft_to_findable(entity_dict, auth_tokens)
                    except Exception as e:
                        logger.exception(f"Exception while creating making doi findable and saving to entity for {dataset_uuid}")
                        return jsonify({"error": f"Error occurred while making doi findable and saving to entity for {dataset_uuid}. Check logs."}), 500
                # Doi exists, but is not yet findable. Just make it findable 
                elif doi_exists is False:
                    try:
                        doi_info = datacite_doi_helper.move_doi_state_from_draft_to_findable(entity_dict, auth_tokens)
                    except Exception as e:
                        logger.exception(f"Exception while creating making doi findable and saving to entity for {dataset_uuid}")
                        return jsonify({"error": f"Error occurred while making doi findable and saving to entity for {dataset_uuid}. Check logs."}), 500
                # The doi exists and it is already findable, skip both steps
                elif doi_exists is True:
                    logger.debug(f"DOI for {dataset_uuid} is already findable. Skipping creation and state change.")
                    doi_name = datacite_doi_helper.build_doi_name(entity_dict)
                    doi_info = {
                        'registered_doi': doi_name,
                        'doi_url': f'https://doi.org/{doi_name}'
                    }
            doi_update_clause = ""
            if not doi_info is None:
                doi_update_clause = f", e.registered_doi = '{doi_info['registered_doi']}', e.doi_url = '{doi_info['doi_url']}'"

            #add Published status change to status history
            status_update = {
               "status": "Published",
               "changed_by_email":user_info['email'],
               "change_timestamp": "@#TIMESTAMP#@"
            }            
            status_history_list.append(status_update)
            #convert from list to string that is used for storage in database
            new_status_history_str = string_helper.convert_py_obj_to_string(status_history_list)
            #substitute the TIMESTAMP function to let Neo4j set the change_timestamp value of this status change record
            status_history_with_timestamp = new_status_history_str.replace("'@#TIMESTAMP#@'", '" + TIMESTAMP() + "')
            status_history_update_clause = f', e.status_history = "{status_history_with_timestamp}"'
            
            # set dataset status to published and set the last modified user info and user who published
            update_q = "match (e:Entity {uuid:'" + dataset_uuid + "'}) set e.status = 'Published', e.last_modified_user_sub = '" + \
                       user_info['sub'] + "', e.last_modified_user_email = '" + user_info[
                           'email'] + "', e.last_modified_user_displayname = '" + user_info[
                           'name'] + "', e.last_modified_timestamp = TIMESTAMP(), e.published_timestamp = TIMESTAMP(), e.published_user_email = '" + \
                       user_info['email'] + "', e.published_user_sub = '" + user_info[
                           'sub'] + "', e.published_user_displayname = '" + user_info['name'] + "'" + doi_update_clause + status_history_update_clause

            logger.info(dataset_uuid + "\t" + dataset_uuid + "\tNEO4J-update-base-dataset\t" + update_q)
            neo_session.run(update_q)
            entity_instance.clear_cache(dataset_uuid)

            # if all else worked set the list of ids to public that need to be public
            if len(uuids_for_public) > 0:
                id_list = string_helper.listToCommaSeparated(uuids_for_public, quoteChar="'")
                update_q = "match (e:Entity) where e.uuid in [" + id_list + "] set e.data_access_level = 'public'"
                logger.info(identifier + "\t" + dataset_uuid + "\tNEO4J-update-ancestors\t" + update_q)
                neo_session.run(update_q)
                for e_id in uuids_for_public:
                    entity_instance.clear_cache(e_id)

            #path to the Dataset on the file system, used for both creating metadata.json and for striping lab ids from any *metadata.tsv files
            ds_path = ingest_helper.dataset_directory_absolute_path_published(data_access_level, dataset_group_uuid, dataset_uuid)
            if is_primary or metadata_json_based_on_creation_action(entity_dict.get('creation_action')):
                # Write out the metadata.json file after all processing has been done for publication...
                # NOTE: The metadata.json file must be written before set_dataset_permissions published=True is executed
                # because (on examining the code) you can see that it causes the director to be not writable.

                md_file = os.path.join(ds_path, "metadata.json")
                try:
                    entity_base_url = commons_file_helper.removeTrailingSlashURL(app.config['ENTITY_WEBSERVICE_URL'])
                    prov_metadata_url = f"{entity_base_url}/datasets/{dataset_uuid}/prov-metadata"
                    rspn = requests.get(    url=prov_metadata_url
                                            ,headers = {'Authorization': request.headers["AUTHORIZATION"]})
                    if rspn.status_code not in [200]:
                        raise Exception(f"Retrieving provenance metadata for {dataset_uuid}"
                                        f" from Entity API resulted in: {rspn.json()['error']}")
                    json_object = f"{json.dumps(obj=rspn.json(), indent=4)}\n"
                except Exception as e:
                    logger.exception(   f"An exception occurred retrieving prov-metadata for"
                                        f" dataset_uuid={dataset_uuid} while"
                                        f" publishing identifier={identifier}")
                    raise e

                logger.info(f"publish_datastage; writing metadata.json file: '{md_file}'; "
                            f"containing: '{json_object}'")
                try:
                    with open(md_file, "w") as outfile:
                        outfile.write(json_object)
                except Exception as e:
                    logger.exception(f"Fatal error while writing md_file {md_file}; {str(e)}")
                    return jsonify({"error": f"Dataset UUID {dataset_uuid}; Problem writing metadata.json file to path: '{md_file}'; error text: {str(e)}."}), 500

            # This must be done after ALL files are written because calling it with published=True causes the
            # directory to be made READ/EXECUTE only and any attempt to write a file will cause a server 500 error.
            acls_cmd = ingest_helper.set_dataset_permissions(dataset_uuid, dataset_group_uuid, data_access_level,
                                                             True, no_indexing_and_acls)


        #find all of the files that match *metadata.tsv under the dataset's directory
        #strip the columns that can hold lab identifiers of any data
        tsv_files = glob.glob(os.path.join(ds_path,"*metadata.tsv"))
        for tsv_file in tsv_files:
            tsv_data = pandas.read_csv(tsv_file, sep='\t')
            columns = tsv_data.columns.tolist()
            changes = False
            for col_name in tsv_columns_to_blank:
                if col_name in columns:
                    changes = True
                    tsv_data[col_name] = None
            if changes:
                meta_filename = os.path.basename(os.path.normpath(tsv_file))
                dtnow = datetime.datetime.now().strftime('%Y-%m-%d-%H:%M:%S')
                backup_filename = f"({dataset_uuid}.{dtnow}) {meta_filename}"
                backup_file_path = os.path.join(tsv_backup_dir,backup_filename)
                shutil.copy(tsv_file, f"{backup_file_path}")
                tsv_data.to_csv(tsv_file, sep='\t', index=False)

        if no_indexing_and_acls:
            r_val = {'acl_cmd': acls_cmd, 'donors_for_indexing': donors_to_reindex, 'relink_cmd': relink_cmd}
        else:
            r_val = {'acl_cmd': '', 'donors_for_indexing': [], 'relink_cmd': relink_cmd}

        if not no_indexing_and_acls:
            for donor_uuid in donors_to_reindex:
                try:
                    rspn = requests.put(app.config['SEARCH_WEBSERVICE_URL'] + "/reindex/" + donor_uuid, headers={'Authorization': request.headers["AUTHORIZATION"]})
                    logger.info(f"Publishing {identifier} indexed donor {donor_uuid} with status {rspn.status_code}")
                except:
                    logger.exception(f"While publishing {identifier} Error happened when calling reindex web service for donor {donor_uuid}")

        return Response(json.dumps(r_val), 200, mimetype='application/json')                    

    except HTTPException as hte:
        return Response(hte.get_description(), hte.get_status_code())
    except Exception as e:
        logger.error(e, exc_info=True)
        return Response(f"Unexpected error while creating a dataset: {identifier} " + str(e) + "  Check the logs", 500)


@app.route('/datasets/<identifier>/metadata-json', methods=['PUT'])
@secured(groups="HuBMAP-read")
def datasets_metadata_json(identifier):
    """
    See publish_datastage() for additional information.

    Use the Neo4J query (above) to get dataset and file system information.
    File system mapping is explained above.
    Replacing ds.uuid in the URL with the value of ds.uuid, e.g.:
    curl --verbose --request PUT \
     --url ${INGESTAPI_URL}/datasets/ds.uuid/metadata-json \
     --header "Authorization: Bearer ${TOKEN}"
    """
    try:
        if identifier is None or len(identifier) == 0:
            return Response("Missing or improper dataset identifier", 400)

        auth_helper = AuthHelper.configured_instance(app.config['APP_CLIENT_ID'],
                                                     app.config['APP_CLIENT_SECRET'])
        user_info = auth_helper.getUserInfoUsingRequest(request, getGroups=True)
        if user_info is None:
            return Response("Unable to obtain user information for auth token", 401)
        if 'hmgroupids' not in user_info:
            return Response("User has no valid group information", 403)
        if data_admin_group_uuid not in user_info['hmgroupids']:
            return Response("User must be a member of the HuBMAP Data Admin group", 403)

        auth_tokens = auth_helper.getAuthorizationTokens(request.headers)
        entity_instance = EntitySdk(token=auth_tokens, service_url=app.config['ENTITY_WEBSERVICE_URL'])
        entity = entity_instance.get_entity_by_id(identifier)
        entity_dict: dict = vars(entity)
        dataset_group_uuid = entity_dict.get('group_uuid')
        dataset_data_access_level = entity_dict.get('data_access_level')
        dataset_ingest_metadata = entity_dict.get('ingest_metadata')
        dataset_published = entity_dict.get('status') == 'Published'

        if dataset_ingest_metadata is None:
            return Response(f"Could not find ingest_metadata for {identifier}", 500)

        logger.info(f"ingest_matadata: {dataset_ingest_metadata}")
        ingest_helper = IngestFileHelper(app.config)
        # Save a .json file with the metadata information at the top level directory...
        ds_path = ingest_helper.dataset_directory_absolute_path(dataset_data_access_level,
                                                                dataset_group_uuid,
                                                                identifier,
                                                                dataset_published)
        md_file = os.path.join(ds_path, "metadata.json")
        try:
            entity_base_url = commons_file_helper.removeTrailingSlashURL(app.config['ENTITY_WEBSERVICE_URL'])
            prov_metadata_url = f"{entity_base_url}/datasets/{identifier}/prov-metadata"
            rspn = requests.get(url=prov_metadata_url
                                , headers={'Authorization': request.headers["AUTHORIZATION"]})
            if rspn.status_code not in [200]:
                raise Exception(f"Retrieving provenance metadata for {identifier}"
                                f" from Entity API resulted in: {rspn.json()['error']}")
            json_object = f"{json.dumps(obj=rspn.json(), indent=4)}\n"
        except Exception as e:
            logger.exception(f"An exception occurred retrieving prov-metadata while"
                             f" updating metadata for identifier={identifier}")
            raise e

        logger.info(f"publish_datastage; writing md_file: '{md_file}'; "
                    f"containing: '{json_object}'")
        try:
            with open(md_file, "w") as outfile:
                outfile.write(json_object)
        except Exception as e:
            logger.exception(f"Fatal error while writing md_file {md_file}; {str(e)}")
            return Response(f"Fatal error while writing md_file for {identifier}", 500)

        return Response("Success", 201)

    except HTTPException as hte:
        return Response(hte.get_description(), hte.get_status_code())
    except Exception as e:
        logger.error(e, exc_info=True)
        return Response("Unexpected error: " + str(e) + "  Check the logs", 500)

@app.route('/datasets/<uuid>/status/<new_status>', methods = ['PUT'])
#@secured(groups="HuBMAP-read")
def update_dataset_status(uuid, new_status):
    if uuid == None or len(uuid) == 0:
        abort(400, jsonify( { 'error': 'uuid parameter is required to change a dataset status' } ))
    if str(new_status) not in HubmapConst.DATASET_STATUS_OPTIONS:
        abort(400, jsonify( { 'error': 'dataset status: ' + str(new_status) + ' is not a valid status.' } ))
    conn = None
    try:
        logger.info(f"++++++++++Called /datasets/{uuid}/{new_status}")

        dataset = Dataset(app.config)
        status_obj = dataset.set_status(neo4j_driver_instance, uuid, new_status)
        conn.close()

        print('Before reindex call in update_dataset_status')
        try:
            auth_headers = {'Authorization': request.headers["AUTHORIZATION"]}
            #reindex this node in elasticsearch
            rspn = requests.put(app.config['SEARCH_WEBSERVICE_URL'] + "/reindex/" + uuid, headers=auth_headers)
        except:
            print('Error occurred when call the reindex web service')

        return jsonify( { 'result' : status_obj } ), 200

    except ValueError as ve:
        print('ERROR: ' + str(ve))
        abort(404, jsonify( { 'error': str(ve) } ))

    except:
        msg = 'An error occurred: '
        for x in sys.exc_info():
            msg += str(x)
        print (msg)
        abort(400, msg)
    # finally:
    #     if conn != None:
    #         if conn.get_driver().closed() == False:
    #             conn.close()


@app.route('/datasets/<uuid>/verifytitleinfo', methods=['GET'])
# @secured(groups="HuBMAP-read")
def verify_dataset_title_info(uuid: str) -> object:
    try:
        UUID(uuid)
    except ValueError:
        abort(400, jsonify({'error': 'parameter uuid of dataset is required'}))
    try:
        result_array = app_manager.verify_dataset_title_info(uuid, request.headers)
        return jsonify({'verification_errors': result_array}), 200

    except HTTPException as hte:
        return Response(hte.get_description(), hte.get_status_code())

    except ValueError as ve:
        logger.error(str(ve))
        return jsonify({'error': str(ve)}), 400

    except Exception as e:
        logger.error(e, exc_info=True)
        return Response("Unexpected error: " + str(e), 500)

@app.route('/datasets/<uuid>/submit', methods = ['PUT'])
def submit_dataset(uuid):
    if not request.is_json:
        return Response("json request required", 400)
    try:
        dataset_request = request.json
        auth_helper = AuthHelper.configured_instance(app.config['APP_CLIENT_ID'], app.config['APP_CLIENT_SECRET'])
        ingest_helper = IngestFileHelper(app.config)
        auth_tokens = auth_helper.getAuthorizationTokens(request.headers)
        if isinstance(auth_tokens, Response):
            return(auth_tokens)
        elif isinstance(auth_tokens, str):
            token = auth_tokens
        elif 'nexus_token' in auth_tokens:
            token = auth_tokens['nexus_token']
        else:
            return(Response("Valid nexus auth token required", 401))
 
        if 'group_uuid' in dataset_request:
            return Response("Cannot specify group_uuid.  The group ownership cannot be changed after an entity has been created.", 400)
      
        with neo4j_driver_instance.session() as session:
            #query Neo4j db to get the group_uuid
            stmt = "match (d:Dataset {uuid:'" + uuid.strip() + "'}) return d.group_uuid as group_uuid"
            recds = session.run(stmt)
            #this assumes there is only one result returned, but we use the for loop
            #here because standard list (len, [idx]) operators don't work with
            #the neo4j record list object
            count = 0
            group_uuid = None
            for record in recds:
                count = count + 1
                group_uuid = record.get('group_uuid', None) 
                if group_uuid == None:
                    return Response(f"Unable to process submit.  group_uuid not found on entity:{uuid}", 400)
            if count == 0: return Response(f"Dataset with uuid:{uuid} not found.", 404) 
 
        user_info = auth_helper.getUserInfo(token, getGroups=True)
        if isinstance(user_info, Response): return user_info
        if not 'hmgroupids' in user_info:
            return Response("user not authorized to submit data, unable to retrieve any group information", 403)
        if not data_admin_group_uuid in user_info['hmgroupids']:
            return Response("user not authorized to submit data, must be a member of the HuBMAP-Data-Admin group", 403)

        # TODO: Temp fix till we can get this in the "Validation Pipeline"... add the validation code here... If it returns any errors fail out of this. Return 412 Precondition Failed with the errors in the description.
        pipeline_url = commons_file_helper.ensureTrailingSlashURL(app.config['INGEST_PIPELINE_URL']) + 'request_ingest'
    except Exception as e:
        logger.error(e, exc_info=True)
        return Response("Unexpected error while creating a dataset: " + str(e) + "  Check the logs", 500)

    # Check URL parameters before proceeding to any CRUD operations, halting on validation failures.
    #
    # Check if re-indexing is to be suppressed after entity creation.
    try:
        suppress_reindex = _suppress_reindex()
    except Exception as e:
        bad_request_error(e)

    try:
        put_url = f"{commons_file_helper.ensureTrailingSlashURL(app.config['ENTITY_WEBSERVICE_URL'])}" \
                   f"entities/{uuid}" \
                   f"{'?reindex=False' if suppress_reindex else ''}"
        dataset_request['status'] = 'Processing'
        response = requests.put(put_url, json=dataset_request,
                                headers={'Authorization': 'Bearer ' + token, 'X-Hubmap-Application': 'ingest-api'},
                                verify=False)

        if not response.status_code == 200:
            error_msg = f"call to {put_url} failed with code:{response.status_code} message:" + response.text
            logger.error(error_msg)
            return Response(error_msg, response.status_code)
    except HTTPException as hte:
        logger.error(hte)
        return Response("Unexpected error while updating dataset: " + str(hte) + "  Check the logs", 500)
    def call_airflow():
        try:
            r = requests.post(pipeline_url, json={"submission_id" : "{uuid}".format(uuid=uuid), "process" : app.config['INGEST_PIPELINE_DEFAULT_PROCESS'],"full_path": ingest_helper.get_dataset_directory_absolute_path(dataset_request, group_uuid, uuid),"provider": "{group_name}".format(group_name=AuthHelper.getGroupDisplayName(group_uuid))}, headers={'Content-Type':'application/json', 'Authorization': 'Bearer {token}'.format(token=AuthHelper.instance().getProcessSecret() )}, verify=False)
            if r.ok == True:
                """expect data like this:
                {"ingest_id": "abc123", "run_id": "run_657-xyz", "overall_file_count": "99", "top_folder_contents": "["IMS", "processed_microscopy","raw_microscopy","VAN0001-RK-1-spatial_meta.txt"]"}
                """
                data = json.loads(r.content.decode())
                submission_data = data['response']
                dataset_request['ingest_id'] = submission_data['ingest_id']
                dataset_request['run_id'] = submission_data['run_id']
            else:
                error_message = 'Failed call to AirFlow HTTP Response: ' + str(r.status_code) + ' msg: ' + str(r.text)
                logger.error(error_message)
                dataset_request['status'] = 'Error'
                dataset_request['pipeline_message'] = error_message
            response = requests.put(put_url, json=dataset_request,
                                    headers={'Authorization': 'Bearer ' + token, 'X-Hubmap-Application': 'ingest-api'},
                                    verify=False)
            if not response.status_code == 200:
                error_msg = f"call to {put_url} failed with code:{response.status_code} message:" + response.text
                logger.error(error_msg)
        except HTTPException as hte:
            logger.error(hte)
        except Exception as e:
            logger.error(e, exc_info=True)
    thread = Thread(target=call_airflow)
    thread.start()
    return Response("Request of Dataset Submisssion Accepted", 202)

####################################################################################################
## Uploads API Endpoints
####################################################################################################

# This creates a new protected Uploads folder once a user creates a new Uploads datagroup
#
#
# example url:  https://my.endpoint.server/uploads
# inputs:
#      - The title of the new folder
#      - The UUID
#      - A valid nexus token in a authorization bearer header
#
# returns
#      200 json with Details about the new folder (@TODO: paste in once authed again)
#      400 if invalid json sent
#      401 if user does not have hubmap read access or the token is invalid
#
# Example json response:
#                  {{
#                         "created_by_user_displayname": "Eris Pink",
#                         "created_by_user_email": "mycoolemail@aolonline.co",
#                         "created_by_user_sub": "12345678-abba-2468-wdwa-6484IDKSGGFF",
#                         "created_timestamp": 1587414020,
#                         "entity_type": "Upload",
#                         "group_name": "IEC Testing Group",
#                         "group_uuid": "UUID-OF-GROUP-HERE-0e006b0001e9",
#                         "hubmap_id": "HBM420.LTRS.999",
#                         "last_modified_timestamp": 1587414020,
#                         "last_modified_user_displayname": "E Pink",
#                         "last_modified_user_email": "Jmycoolemail@aolonline.co",
#                         "last_modified_user_sub": "76f777all-abba-6971-hehe-125ea519865",
#                         "status": "New",
#                         "title": "TestTitle",
#                         "uuid": "4a583209bfe9ad6cda851d913ac44833915"
#                    }

@app.route('/uploads', methods=['POST'])
def create_uploadstage():
    if not request.is_json:
        return Response("json request required", 400)    
    try:
        upload_request = request.json
        auth_helper = AuthHelper.configured_instance(app.config['APP_CLIENT_ID'], app.config['APP_CLIENT_SECRET'])
        auth_tokens = auth_helper.getAuthorizationTokens(request.headers)
        if isinstance(auth_tokens, Response):
            return(auth_tokens)
        elif isinstance(auth_tokens, str):
            token = auth_tokens
        elif 'groups_token' in auth_tokens:
            token = auth_tokens['groups_token']
        else:
            return(Response("Valid nexus auth token required", 401))
        
        requested_group_uuid = None
        if 'group_uuid' in upload_request:
            requested_group_uuid = upload_request['group_uuid']
        
        ingest_helper = IngestFileHelper(app.config)
        requested_group_uuid = auth_helper.get_write_group_uuid(token, requested_group_uuid)
        upload_request['group_uuid'] = requested_group_uuid            
        post_url = commons_file_helper.ensureTrailingSlashURL(app.config['ENTITY_WEBSERVICE_URL']) + 'entities/upload'
        response = requests.post(post_url, json = upload_request, headers = {'Authorization': 'Bearer ' + token, 'X-Hubmap-Application':'ingest-api' }, verify = False)
        if response.status_code != 200:
            return Response(response.text, response.status_code)
        new_upload = response.json()
        ingest_helper.create_upload_directory(requested_group_uuid, new_upload['uuid'])
        return jsonify(new_upload)
    except HTTPException as hte:
        return Response(hte.get_description(), hte.get_status_code())
    except Exception as e:
        logger.error(e, exc_info=True)
        return Response("Unexpected error while creating a upload: " + str(e) + "  Check the logs", 500)        


#method to change the status of an Upload to "submitted"
#will also save any changes to title or description that are passed in
@app.route('/uploads/<upload_uuid>/submit', methods=['PUT'])
def submit_upload(upload_uuid):
    if not request.is_json:
        return Response("json request required", 400)

    upload_changes = request.json
    upload_changes['status'] = 'Submitted'

    if 'priority_project_list' not in request.json:
        return Response("Missing required property 'priority_project_list'. Field is required even if the value is an empty array.", 400)
    
    #get auth info to use in other calls
    #add the app specific header info
    http_headers = {
        'Authorization': request.headers["AUTHORIZATION"], 
        'Content-Type': 'application/json',
        'X-Hubmap-Application':'ingest-api'
    } 

    update_url = commons_file_helper.ensureTrailingSlashURL(app.config['ENTITY_WEBSERVICE_URL']) + 'entities/' + upload_uuid
    # Disable ssl certificate verification
    resp = requests.put(update_url, headers=http_headers, json=upload_changes, verify = False)
    if resp.status_code >= 300:
        return Response(resp.text, resp.status_code)
    
    #disable validations stuff for now...
    ##call the AirFlow validation workflow
    #validate_url = commons_file_helper.ensureTrailingSlashURL(app.config['INGEST_PIPELINE_URL']) + 'uploads/' + upload_uuid + "/validate"
    ## Disable ssl certificate verification
    #resp = requests.put(validate_url, headers=http_headers, json=upload_changes, verify = False)
    #if resp.status_code >= 300:
    #    return Response(resp.text, resp.status_code)

    return(Response("Upload updated successfully", 200))

#method to validate an Upload
#saves the upload then calls the validate workflow via
#AirFlow interface 
@app.route('/uploads/<upload_uuid>/validate', methods=['PUT'])
def validate_upload(upload_uuid):
    if not request.is_json:
        return Response("json request required", 400)

    upload_changes = request.json
    
    #get auth info to use in other calls
    #add the app specific header info
    http_headers = {
        'Authorization': request.headers["AUTHORIZATION"], 
        'Content-Type': 'application/json',
        'X-Hubmap-Application':'ingest-api'
    } 

    #update the Upload with any changes from the request
    #and change the status to "Processing", the validate
    #pipeline will update the status when finished

    #run the pipeline validation
    upload_changes['status'] = 'Processing'
    update_url = commons_file_helper.ensureTrailingSlashURL(app.config['ENTITY_WEBSERVICE_URL']) + 'entities/' + upload_uuid
    
    # Disable ssl certificate verification
    resp = requests.put(update_url, headers=http_headers, json=upload_changes, verify = False)
    if resp.status_code >= 300:
        return Response(resp.text, resp.status_code)
    
    #disable validations stuff for now...
    ##call the AirFlow validation workflow
    validate_url = commons_file_helper.ensureTrailingSlashURL(app.config['INGEST_PIPELINE_URL']) + 'uploads/' + upload_uuid + "/validate"
    ## Disable ssl certificate verification
    resp = requests.put(validate_url, headers=http_headers, json=upload_changes, verify = False)
    if resp.status_code >= 300:
        return Response(resp.text, resp.status_code)

    return(Response("Upload updated successfully", 200))
    
#method to reorganize an Upload
#saves the upload then calls the reorganize workflow via
#AirFlow interface 
@app.route('/uploads/<upload_uuid>/reorganize', methods=['PUT'])
def reorganize_upload(upload_uuid):
    
    #get auth info to use in other calls
    #add the app specific header info
    http_headers = {
        'Authorization': request.headers["AUTHORIZATION"], 
        'Content-Type': 'application/json',
        'X-Hubmap-Application':'ingest-api'
    } 

    #update the Upload with any changes from the request
    #and change the status to "Processing", the validate
    #pipeline will update the status when finished
    upload_changes = {}
    upload_changes['status'] = 'Processing'
    update_url = commons_file_helper.ensureTrailingSlashURL(app.config['ENTITY_WEBSERVICE_URL']) + 'entities/' + upload_uuid
    
    # Disable ssl certificate verification
    resp = requests.put(update_url, headers=http_headers, json=upload_changes, verify = False)
    if resp.status_code >= 300:
        return Response(resp.text, resp.status_code)
    
    #disable validations stuff for now...
    ##call the AirFlow validation workflow
    validate_url = commons_file_helper.ensureTrailingSlashURL(app.config['INGEST_PIPELINE_URL']) + 'uploads/' + upload_uuid + "/reorganize"
    ## Disable ssl certificate verification
    resp = requests.put(validate_url, headers=http_headers, json=upload_changes, verify = False)
    if resp.status_code >= 300:
        return Response(resp.text, resp.status_code)

    return(Response("Upload reorganize started successfully", 200))

# method to fetch all Data Provider groups through Hubmap Commons
# Returns an Array of nested objects containing all groups
@app.route('/metadata/data-provider-groups', methods=['GET'])
@secured(groups="HuBMAP-read")
def all_group_list():
    try:
        auth_helper = AuthHelper.configured_instance(
            app.config['APP_CLIENT_ID'], app.config['APP_CLIENT_SECRET'])
        group_list = auth_helper.getHuBMAPGroupInfo()
        return_list = []
        for group_info in group_list.keys():
            if group_list[group_info]['data_provider'] == True:
                return_list.append(group_list[group_info])
        return jsonify({'groups': return_list}), 200
    except HTTPException as hte:
        return Response(hte.get_description(), hte.get_status_code())
    except Exception as e:
        logger.error(e, exc_info=True)
        return Response("Unexpected error while fetching group list: " + str(e) + "  Check the logs", 500)

@app.route('/metadata/usergroups', methods = ['GET'])
@secured(groups="HuBMAP-read")
def user_group_list():
    token = str(request.headers["AUTHORIZATION"])[7:]
    try:
        auth_helper = AuthHelper.configured_instance(app.config['APP_CLIENT_ID'], app.config['APP_CLIENT_SECRET'])        
        group_list = auth_helper.get_user_groups_deprecated(token)
        return jsonify( {'groups' : group_list}), 200
    except HTTPException as hte:
        return Response(hte.get_description(), hte.get_status_code())
    except Exception as e:
        logger.error(e, exc_info=True)
        return Response("Unexpected error while creating a dataset: " + str(e) + "  Check the logs", 500)        

@app.route('/metadata/userroles', methods = ['GET'])
@secured(groups="HuBMAP-read")
def user_role_list():
    token = str(request.headers["AUTHORIZATION"])[7:]
    try:
        auth_helper = AuthHelper.configured_instance(app.config['APP_CLIENT_ID'], app.config['APP_CLIENT_SECRET'])                
        role_list = auth_helper.get_user_roles_deprecated(token)
        
        #temp code!!
        #role_list = []
        
        return jsonify( {'roles' : role_list}), 200
    except HTTPException as hte:
        return Response(hte.get_description(), hte.get_status_code())
    except Exception as e:
        logger.error(e, exc_info=True)
        return Response("Unexpected error while creating a dataset: " + str(e) + "  Check the logs", 500)        


@app.route('/specimens/<identifier>/ingest-group-ids', methods=['GET'])
@secured(groups="HuBMAP-read")
def get_specimen_ingest_group_ids(identifier):
    if identifier == None:
        abort(400)
    if len(identifier) == 0:
        abort(400)

    conn = None
    try:
        token = str(request.headers["AUTHORIZATION"])[7:]
        r = requests.get(app.config['UUID_WEBSERVICE_URL'] + "/" + identifier, headers={'Authorization': 'Bearer ' + token })
        if r.ok == False:
            raise ValueError("Cannot find specimen with identifier: " + identifier)
        uuid = json.loads(r.text)['hm_uuid']

        sibling_id_list = SampleHelper.get_ingest_group_list(   driver=neo4j_driver_instance
                                                                , uuid=uuid)
        return jsonify({'ingest_group_ids': sibling_id_list}), 200

    except AuthError as e:
        print(e)
        return Response('token is invalid', 401)
    except:
        msg = 'An error occurred: '
        for x in sys.exc_info():
            msg += str(x)
        abort(400, msg)

@app.route('/ubkg-download-file-list', methods = ['GET'])
def ubkg_download_file_list():
    if not request.args or request.args.get('umls-key') is None:
        bad_request_error("Must include parameter 'umls-key'")
    umls_key = request.args.get('umls-key')
    if umls_key is None or not umls_key.strip():
        bad_request_error("The value of umls-key can not be empty")
    validator_key = app.config['UMLS_KEY']
    base_url = app.config['UMLS_VALIDATE_URL']
    url = base_url + '?validatorApiKey=' + validator_key + '&apiKey=' + umls_key
    result = requests.get(url=url)
    if result.json() == True:
        ubkg_dir = app.config['UBKG_DIRECTORY_FILEPATH']
        file_info_json = app.config['UBKG_FILES_LIST_JSON']
        files_list = []
        """We may eventually want to look through subdirectories, in which case we can use this recursive function"""
        # def get_files_in_dir(directory):
        #     files = os.listdir(directory)
        #     for file in files:
        #         full_path = os.path.join(directory, file)
        #         if os.path.isdir(full_path):
        #             get_files_in_dir(full_path)
        #         else:
        #             files_list.append(full_path)
        # get_files_in_dir(ubkg_dir)
        files = os.listdir(ubkg_dir)
        for file in files:
            full_path = os.path.join(ubkg_dir, file)
            if not os.path.isdir(full_path):
                files_list.append(full_path)
        file_paths_dict = {os.path.basename(file_path): file_path for file_path in files_list}
        if file_info_json not in file_paths_dict:
            return bad_request_error(f"UBKG Download Directory {file_info_json} not found")
        with open(file_paths_dict[file_info_json], 'r') as f:
            json_data = json.load(f)
        json_out = []
        for file_name in file_paths_dict:
            if file_name != file_info_json:
                out_dict = {}
                path = file_paths_dict[file_name]
                size = os.path.getsize(path)
                last_modified_timestamp = os.path.getmtime(path)
                last_modified_date = datetime.datetime.fromtimestamp(last_modified_timestamp)
                out_dict['name'] = file_name
                out_dict['last_modified'] = last_modified_date
                out_dict['size'] = size
                if file_name in json_data:
                    description = json_data.get(file_name)
                    out_dict['description'] = description
                json_out.append(out_dict)
        return jsonify(json_out)
    else:
        return jsonify(False), 403


"""
Takes a valid id for a collection entity, validates that it contains required fields and has datasets in the published state, 
then registers a DOI, updates the collection via entity-api, and returns the new registered_doi
"""
@app.route('/collections/<collection_id>/register-doi', methods = ['PUT'])
def register_collections_doi(collection_id):
    try:
        auth_helper = AuthHelper.configured_instance(app.config['APP_CLIENT_ID'], app.config['APP_CLIENT_SECRET'])
        user_info = auth_helper.getUserInfoUsingRequest(request, getGroups=True)
        if user_info is None:
            return jsonify({"error": "Unable to obtain user information for auth token"}), 401
        if isinstance(user_info, Response):
            return user_info
        if 'hmgroupids' not in user_info:
            return jsonify({"error": "User has no valid group information to authorize publication."}), 403
        if data_admin_group_uuid not in user_info['hmgroupids']:
            return jsonify({"error": "User must be a member of the HuBMAP Data Admin group to publish data."}), 403
        if collection_id is None or len(collection_id) == 0:
            return jsonify({"error": "identifier parameter is required to publish a collection."}), 400
        r = requests.get(app.config['UUID_WEBSERVICE_URL'] + "/" + collection_id, headers={'Authorization': request.headers["AUTHORIZATION"]})
        if r.ok is False:
            return jsonify({"error": f"{r.text}"}), r.status_code
        collection_uuid = json.loads(r.text)['hm_uuid']
        if json.loads(r.text).get('type').lower() not in ['collection', 'epicollection']:
            return jsonify({"error": f"{collection_uuid} is not a collection"}), 400
        with neo4j_driver_instance.session() as neo_session:
            q = f"MATCH (collection:Collection {{uuid: '{collection_uuid}'}})<-[:IN_COLLECTION]-(dataset:Dataset) RETURN distinct dataset.uuid AS uuid, dataset.status AS status"
            rval = neo_session.run(q).data()
            unpublished_datasets = []
            for node in rval:
                uuid = node['uuid']
                status = node['status']
                if status != 'Published':
                    unpublished_datasets.append(uuid)
            if len(unpublished_datasets) > 0:
                return jsonify({"error": f"Collection with uuid {collection_uuid} has one more associated datasets that have not been Published.", "dataset_uuids": ', '.join(unpublished_datasets)}), 422
            #get info for the collection to be published
            q = f"MATCH (e:Collection {{uuid: '{collection_uuid}'}}) RETURN e.uuid as uuid, e.contacts as contacts, e.contributors as contributors "
            rval = neo_session.run(q).data()
            collection_contacts = rval[0]['contacts']
            collection_contributors = rval[0]['contributors']
            if collection_contributors is None or collection_contacts is None:
                return jsonify({"error": "Collection missing contacts or contributors field. Must have at least one of each"}), 400
            if len(collection_contributors) < 1 or len(collection_contacts) < 1:
                return jsonify({"error": "Collection missing contacts or contributors. Must have at least one of each"}), 400

            auth_tokens = auth_helper.getAuthorizationTokens(request.headers)
            entity_instance = EntitySdk(token=auth_tokens, service_url=app.config['ENTITY_WEBSERVICE_URL'])

            doi_info = None

            entity = entity_instance.get_entity_by_id(collection_uuid)
            entity_dict = vars(entity)
            datacite_doi_helper = DataCiteDoiHelper()

            # Checks both whether a doi already exists, as well as if it is already findable. If True, DOI exists and is findable
            # If false, DOI exists but is not yet in findable. If None, doi does not yet exist. 
            try:
                doi_exists = datacite_doi_helper.check_doi_existence_and_state(entity_dict)
            except DataciteApiException as e:
                    logger.exception(f"Exception while fetching doi for {collection_uuid}")
                    return jsonify({"error": f"Error occurred while trying to confirm existence of doi for {dataset_uuid}. {e}"}), 500
            # Doi does not exist, create draft then make it findable
            if doi_exists is None:
                try:
                    datacite_doi_helper.create_collection_draft_doi(entity_dict)
                except DataciteApiException as datacite_exception:
                    return jsonify({"error": str(datacite_exception)}), datacite_exception.error_code
                except Exception as e:
                    logger.exception(f"Exception while creating a draft doi for {collection_uuid}")
                    return jsonify({"error": f"Error occurred while trying to create a draft doi for {collection_uuid}. Check logs."}), 500
                # This will make the draft DOI created above 'findable'....
                try:
                    doi_info = datacite_doi_helper.move_doi_state_from_draft_to_findable(entity_dict, auth_tokens)
                except Exception as e:
                    logger.exception(f"Exception while creating making doi findable and saving to entity for {collection_uuid}")
                    return jsonify({"error": f"Error occurred while making doi findable and saving to entity for {collection_uuid}. Check logs."}), 500
            # Doi exists, but is not yet findable. Just make it findable
            elif doi_exists is False:
                try:
                        doi_info = datacite_doi_helper.move_doi_state_from_draft_to_findable(entity_dict, auth_tokens)
                except Exception as e:
                    logger.exception(f"Exception while creating making doi findable and saving to entity for {collection_uuid}")
                    return jsonify({"error": f"Error occurred while making doi findable and saving to entity for {collection_uuid}. Check logs."}), 500
            # The doi exists and it is already findable, skip both steps
            elif doi_exists is True:
                logger.debug(f"DOI for {collection_uuid} is already findable. Skipping creation and state change.")
                doi_name = datacite_doi_helper.build_doi_name(entity_dict)
                doi_info = {
                    'registered_doi': doi_name,
                    'doi_url': f'https://doi.org/{doi_name}'
                }
            doi_update_data = ""
            if not doi_info is None:
                doi_update_data = {"registered_doi": doi_info["registered_doi"], "doi_url": doi_info['doi_url']}
      
            entity_instance.clear_cache(collection_uuid)
            entity_instance.update_entity(collection_uuid, doi_update_data)

        return jsonify({"registered_doi": f"{doi_info['registered_doi']}"})                    

    except HTTPException as hte:
        return Response(hte.get_description(), hte.get_status_code())
    except Exception as e:
        logger.error(e, exc_info=True)
        return jsonify({"error": "Unexpected error while registering collection doi: " + str(e) + "  Check the logs"}), 500
    

#given a hubmap uuid and a valid Globus token returns, as json the attribute has_write_priv with
#value true if the user has write access to the entity.
#   has_write_priv- denotes if user has write permission for a given entity
#                   true if a user is a member of the group that the entity is a member of or
#                   the user is a member of the Data Admin group, except in the case where
#                   the entity is public or has been published, in which case no one can write
#                   in the case of a data Upload, this denotes the ability to save and validate the data.
#  has_submit_priv- denotes if a user has permission to submit a dataset or data Upload.
#                   true only if the Dataset is in the New state and the user is a member of the
#                   Data Admin group
# has_publish_priv- denotes if a user has permission to publish a Dataset
#                   true only if the Dataset is in the QA state and the user is a member of the
#                   Data Admin group
#
# example url:  https://my.endpoint.server/entities/a5659553c04f6ccbe54ff073b071f349/allowable-edit-states
# inputs:
#      - The uuid of a HuBMAP entity (Donor, Sample or Dataset) as a URL path parameter
#      - A valid nexus token in a authorization bearer header
#
# returns
#      200 json with attributes for has_write_priv, has_submit_priv and has_publish_priv each true
#          if the user can perform the specific function for the provided entity id
#      400 if invalid hubmap uuid provided or no group_uuid found for the entity
#      401 if user does not have hubmap read access or the token is invalid
#      404 if the uuid is not found
#
# Example json response:
#                  {
#                      "has_write_priv": true,
#                      "has_submit_priv": false,
#                      "has_publish_priv": false,
#                      "has_admin_priv": false
#                  }

@app.route('/entities/<hmuuid>/allowable-edit-states', methods = ['GET'])
@secured(groups="HuBMAP-read")
def allowable_edit_states(hmuuid):
    #if no uuid provided send back a 400
    if hmuuid == None or len(hmuuid) == 0:
        abort(400, jsonify( { 'error': 'hmuuid (HuBMAP UUID) parameter is required.' } ))
    accepted_arguments = ["ignore-publication-status"]
    ignore_publication_status = False
    if bool(request.args):
        for argument in request.args:
            if argument.lower() not in accepted_arguments:
                bad_request_error(f"{argument} is an unrecognized argument.")
        ignore_publication = request.args.get('ignore-publication-status')
        if ignore_publication is not None:
            if ignore_publication.lower() == "true":
                ignore_publication_status = True
            elif ignore_publication.lower() == "false":
                ignore_publication_status = False
            else:
                bad_request_error(f"The only accepted values for ignore-publication-status are 'true' or 'false'")
    try:
        #the Globus nexus auth token will be in the AUTHORIZATION section of the header
        token = str(request.headers["AUTHORIZATION"])[7:]

        #get a connection to Neo4j db
        with neo4j_driver_instance.session() as session:
            #query Neo4j db to find the entity
            stmt = "match (e:Entity {uuid:'" + hmuuid.strip() + "'}) return e.group_uuid, e.entity_type, e.data_access_level, e.status"
            recds = session.run(stmt)
            #this assumes there is only one result returned, but we use the for loop
            #here because standard list (len, [idx]) operators don't work with
            #the neo4j record list object
            count = 0
            r_val = {"has_write_priv":False, "has_submit_priv":False, "has_publish_priv":False, "has_admin_priv":False  }
            for record in recds:
                count = count + 1
                if record.get('e.group_uuid', None) != None:
                    #get user info, make sure it has group information associated
                    user_info = auth_helper_instance.getUserInfo(token, True)
                    if user_info is None:
                        return Response("Unable to obtain user information for auth token", 401)
                    if not 'hmgroupids' in user_info:
                        return Response(json.dumps(r_val), 200, mimetype='application/json')
                    group_uuid = record.get('e.group_uuid', None)
                    data_access_level = record.get('e.data_access_level', None)
                    entity_type = record.get('e.entity_type', None)
                    status = record.get('e.status', None)

                    # if user is in the data admin group
                    if data_admin_group_uuid in user_info['hmgroupids']:
                        r_val['has_admin_priv'] = True
                                        
                    if isBlank(group_uuid):
                        msg = f"ERROR: unable to obtain a group_uuid from database for entity uuid:{hmuuid} during a call to allowable-edit-states"
                        logger.error(msg)
                        return Response(msg, 500)
                    
                    if isBlank(entity_type):
                        msg = f"ERROR: unable to obtain an entity_type from database for entity uuid:{hmuuid} during a call to allowable-edit-states"
                        logger.error(msg)
                        return Response(msg, 500)
                    
                    entity_type = entity_type.lower().strip()                          
                    if not entity_type == 'upload':
                        if isBlank(data_access_level): 
                            msg = f"ERROR: unable to obtain a data_access_level from database for entity uuid:{hmuuid} during a call to allowable-edit-states"
                            logger.error(msg)
                            return Response(msg, 500)                        
                        else:
                            data_access_level = data_access_level.lower().strip()
                    else:
                        data_access_level = 'protected'
        
                    #if it is published, no write allowed
                    if entity_type in ['upload'] or\
                            get_entity_type_instanceof(entity_type, 'Dataset', auth_header="Bearer " + auth_helper_instance.getProcessSecret()):
                        if isBlank(status):
                            msg = f"ERROR: unable to obtain status field from db for {entity_type} with uuid:{hmuuid} during a call to allowable-edit-states"
                            logger.error(msg)
                            return Response(msg, 500)
                        status = status.lower().strip()
                        if ignore_publication_status is False:
                            if status == 'published' or status == 'reorganized':
                                return Response(json.dumps(r_val), 200, mimetype='application/json')
                    #if the entity is public, no write allowed
                    elif entity_type in ['sample', 'donor']:
                        if data_access_level == 'public':
                            return Response(json.dumps(r_val), 200, mimetype='application/json')

                    else:
                        return Response("Invalid data type " + entity_type + ".", 400)

                    #compare the group_uuid in the entity to the users list of groups
                    #if the user is a member of the HuBMAP-Data-Admin group,
                    #they have write access to everything and the ability to submit datasets and uploads
                    if data_admin_group_uuid in user_info['hmgroupids']:
                        if not status == 'processing':
                            r_val['has_write_priv'] = True
                        if entity_type == 'dataset':
                            if status == 'new':
                                r_val['has_submit_priv'] = True
                            elif status == 'qa':
                                r_val['has_publish_priv'] = True
                        if entity_type == 'upload':
                            if status in ['new', 'invalid', 'valid', 'error']:
                                r_val['has_submit_priv'] = True
                    #if in the users list of groups return true otherwise false
                    elif group_uuid in user_info['hmgroupids']:
                        if not status == 'processing':
                            r_val['has_write_priv'] = True
                    #if the user is a data_curator they are allowed to save/validate Uploads
                    elif data_curator_group_uuid in user_info['hmgroupids'] and entity_type == 'upload' and not status == 'processing':
                        r_val['has_write_priv'] = True
                    else:
                        r_val['has_write_priv'] = False
                else:
                    return Response("Entity group uuid not found", 400)

            #if we fall through to here without entering the loop the entity was not found
            if count == 0:
                return Response("Entity not found", 404)
            else:
                return Response(json.dumps(r_val), 200, mimetype='application/json')

    except AuthError as e:
        print(e)
        return Response('token is invalid', 401)
    except:
        msg = 'An error occurred: '
        for x in sys.exc_info():
            msg += str(x)
        abort(400, msg)


DATASETS_DATA_STATUS_KEY = "datasets_data_status_key"
DATASETS_DATA_STATUS_LAST_UPDATED_KEY = "datasets_data_status_last_updated_key"
UPLOADS_DATA_STATUS_KEY = "uploads_data_status_key"
UPLOADS_DATA_STATUS_LAST_UPDATED_KEY = "uploads_data_status_last_updated_key"
# Redis Key tracking whether the datset/uploads data-status is running or not. Redis treats these true/false values as ints 1 and 0
DATASETS_DATA_STATUS_RUNNING_KEY = "datasets_data_status_running_key"
UPLOADS_DATA_STATUS_RUNNING_KEY = "uploads_data_status_running_key"



# /has-pipeline-test-privs endpoint
# Endpoint to check if a user has permission to kick off jobs in the
# pipeline testing infrastructure.  The user has permission if they are a member
# of either the "Pipeline Testing" group or the "Data Admin" group.
#
# Request is a GET to this endpoint which includes the standard HuBMMAP Auth Bearer header/token
#
# Responses
# 200- With a json response like the following, with the "has_pipeline_test_privs" returning
#      a boolean telling if the user has permission or not (json true or false returned)
#      {
#         "has_pipeline_test_privs": false,
#         "message": "The user is not allowed to submit to pipeline runs for testing"
#      }
#
# 401- Invalid or no token received
# 500- Unexpected error occurred
@app.route('/has-pipeline-test-privs', methods=['GET'])
def has_pipeline_test_privs():
    token = auth_helper_instance.getAuthorizationTokens(request.headers)
    if isinstance(token, Response):
        return token;
    has_priv = auth_helper_instance.has_pipeline_testing_privs(token)
    if isinstance(has_priv, Response):
        return has_priv
    elif not has_priv:
        return Response(json.dumps({'has_pipeline_test_privs': False, 'message': 'The user is not allowed to submit pipeline runs for testing'}), 200, mimetype='application/json')
    else:
        return Response(json.dumps({'has_pipeline_test_privs': True, 'message': 'The user is allowed to submit pipeline runs for testing'}), 200, mimetype='application/json')



def __submit_mult_for_pipeline_testing(token, ids):
    has_priv = auth_helper_instance.has_pipeline_testing_privs(token)
    if isinstance(has_priv, Response):
        return has_priv
    elif not has_priv:
        return Response("User not authorized to submit to the pipeline testing queue", 403)

    if ids is None or len(ids) == 0:
        return Response("Missing or improper dataset identifiers", 400)
    
    #check to see if a) all ids are valid and b) they are for primary datasets
    lower_ids = ids.copy()
    lower_ids = [id.lower() for id in lower_ids]
    find_datasets_q = f"""MATCH (ds:Dataset)<-[:ACTIVITY_OUTPUT]-(a:Activity)
                             WHERE toLower(a.creation_action) = 'create dataset activity' and
                                   ds.entity_type = 'Dataset' and
                                   (toLower(ds.uuid) in {lower_ids} or
                                    toLower(ds.hubmap_id) in {lower_ids} or
                                    toLower(ds.submission_id) in {lower_ids})
                             return ds.uuid, ds.hubmap_id"""
    with neo4j_driver_instance.session() as neo_session:
        result = neo_session.run(find_datasets_q).data()
        if len(result) == 0:
            return Response("None of the submitted ids were found to be Primary Datasets.", 400)
        dset_uuids = []
        not_found_ids = []
        for id in ids:
            found = False
            for dset in result:
                lower_id = id.lower()
                if lower_id == dset['ds.uuid'].lower() or lower_id == dset['ds.hubmap_id'].lower():
                    uuid = dset['ds.uuid']
                    if not uuid in dset_uuids:
                        dset_uuids.append(uuid)
                    found = True
                    break
            if not found:
                not_found_ids.append(id)
    
    if len(not_found_ids) == 1:
        return Response(f"id {not_found_ids[0]} not found or isn't a Primary Dataset", 400)
    elif len(not_found_ids) > 1:
        return Response(f"ids not found or not Primary Datasets: {not_found_ids}", 400)
    
    submit_url = app.config['PIPELINE_TESTING_URL']
    if submit_url is None or len(submit_url) == 0:
        return Response("Check ingest-api config, PIPELINE_TESTING_URL property is invalid", 500)
    elif (submit_url.strip().lower() == "disabled"):
        return Response("Submitting to the testing pipeline is currently disabled", 202)

    
    #inner function to submit multiple datasets for processing
    #called in thread in if..elif..else block below
    def submit_remaining_to_airflow():
        try:
            for dset_uuid in dset_uuids:
                #sleep for 1 second between submitting datasets
                time.sleep(10)
                submit_request = {"collection_type": "generic_metadatatsv", "uuid_list": [dset_uuid]}
                response = requests.post(submit_url, json = submit_request)
                if response.status_code != 200:
                    error_msg = f"call to {put_url} for dataset uuid: {dset_uuid}. Failed with code:{response.status_code} and message:" + response.text
                    logger.error(error_msg)                    
        except HTTPException as hte:
            logger.error(hte)
        except Exception as e:
            logger.error(e, exc_info=True)
    
    #submit the first dataset and check for an error...if error abort the whole thing.
    submit_request = {"collection_type": "generic_metadatatsv", "uuid_list": [dset_uuids[0]]}
    response = requests.post(submit_url, json = submit_request)
    if response.status_code != 200:
        return Response(response.text, response.status_code)
    #if more than one submit them in a thread and return 202
    elif len(dset_uuids) > 1:
        dset_uuids.pop(0)
        thread = Thread(target=submit_remaining_to_airflow)
        thread.start()
        return Response("Submission accepted, Datasets currently being sent to AirFlow one at a time.", 202)     
    #if only one dataset and we got a 200 response from AirFlow, return
    else:
        return Response("The dataset was successfully submitted for pipeline processing testing", 200)    







# /datasets/{identifier}/submit-for-pipeline-testing endpoint
# This endpoint will submit a dataset for pipeline processing in the testing
# infrastructure. The {identifier} path variable is required and
# can be either a Dataset uuid or HuBMAP ID.  The submitted dataset must be
# a primary (not derived) Dataset
#
# Request POST to /datasets/{identifier}/submit-for-pipeline-testing where
#         the {identifier} is a valid uuid or HuBMAP ID of a Primary dataset
#         This POST method requires no additional data payload.
#
#         The request must include a standard HuBMAP Authorization Bearer
#         header with a user token
#
# Responses
# 200 - The dataset was successfully submitted for pipeline process testing
# 202 - The dataset was accepted, but pipeline processing is currently disabled
# 400 - An error in the requested data, either a bad identifier was submitted
#       or an identifier for a non-Primary dataset or something other than a
#       Dataset was submitted (displayable message included as response message)
# 401 - Invalid or no token supplied.
# 403 - non-authorized token supplied.  The user muse be a member of either the
#       HuBMAP-Pipeline-Testing or HuBMAP-Data-Admin groups
# 500 - An unexpected error occurred
#
#@app.route('/datasets/{identifier}/submit-for-pipeline-testing', methods=['POST'])
@app.route('/datasets/<identifier>/submit-for-pipeline-testing', methods=['POST'])
def submit_for_pipeline_testing(identifier):
    token = auth_helper_instance.getAuthorizationTokens(request.headers)
    if isinstance(token, Response):
        return token;
    return __submit_mult_for_pipeline_testing(token, [identifier])

# /datasets//submit-for-pipeline-testing endpoint
# This endpoint will submit a datasets for pipeline processing in the testing
# infrastructure. A POST json data payload of a list of dataset ids is required.
# The ids can be either Dataset uuids or HuBMAP IDs.  The submitted datasets must
# be primary datasets (not derived)
#
# Request POST to /datasets//submit-for-pipeline-testing
#            with a json data payload of a list of ids
#
#         The request must include a standard HuBMAP Authorization Bearer
#         header with a user token
#
# Responses
# 200 - The datasets were successfully submitted for pipeline process testing
# 202 - The datasets were accepted, but pipeline processing is currently disabled
# 400 - An error in the requested data, either a bad identifier was submitted
#       or an identifier for a non-Primary dataset or something other than a
#       Dataset was submitted (displayable message included as response message)
# 401 - Invalid or no token supplied.
# 403 - non-authorized token supplied.  The user muse be a member of either the
#       HuBMAP-Pipeline-Testing or HuBMAP-Data-Admin groups
# 500 - An unexpected error occurred
#
@app.route('/datasets/submit-for-pipeline-testing', methods=['POST'])
def mult_submit_for_pipeline_testing():
    token = auth_helper_instance.getAuthorizationTokens(request.headers)
    if isinstance(token, Response):
        return token;
    
    require_json(request)
    json_data = request.json    
    if json_data is None or not isinstance(json_data, list):
        return Response("Must provide a list of ids")
    return __submit_mult_for_pipeline_testing(token, json_data)
  
"""
Description
"""
@app.route('/datasets/data-status', methods=['GET'])
def dataset_data_status():
    try:
        try:
            datasets_data_status_running = bool(int(redis_connection.get(DATASETS_DATA_STATUS_RUNNING_KEY)))
            if datasets_data_status_running:
                return jsonify({"status": "Job to update dataset data-status already in progress"}), 202
        except Exception as e:
            logger.error("Failed to retrieve datasets_data_status_running_key to determine whether job already started")
        cached_data = redis_connection.get(DATASETS_DATA_STATUS_KEY)
        if cached_data:
            cached_data_json = json.loads(cached_data.decode('utf-8'))
            last_updated = redis_connection.get(DATASETS_DATA_STATUS_LAST_UPDATED_KEY)
            return jsonify({"data": cached_data_json, "last_updated": int(last_updated)})
        else:
            raise Exception
    except Exception:
        logger.error("Failed to retrieve datasets data-status from cache. Retrieving new data")

    combined_results = update_datasets_datastatus()
    last_updated = int(time.time() * 1000)
    return jsonify({"data": combined_results, "last_updated": last_updated})


"""
Description
"""
@app.route('/uploads/data-status', methods=['GET'])
def upload_data_status():
    try:
        try:
            uploads_data_status_running = bool(int(redis_connection.get(UPLOADS_DATA_STATUS_RUNNING_KEY)))
            if uploads_data_status_running == True:
                return jsonify({"status": "Job to update upload data-status already in progress"}), 202
        except Exception as e:
            logger.error("Failed to retrieve uploads_data_status_running_key to determine whether job already started")
        cached_data = redis_connection.get(UPLOADS_DATA_STATUS_KEY)
        if cached_data:
            cached_data_json = json.loads(cached_data.decode('utf-8'))
            last_updated = redis_connection.get(UPLOADS_DATA_STATUS_LAST_UPDATED_KEY)
            return jsonify({"data": cached_data_json, "last_updated": int(last_updated)})
        else:
            raise Exception
    except Exception:
        logger.error("Failed to retrieve uploads data-status from cache. Retrieving new data")

    results = update_uploads_datastatus()
    last_updated = int(time.time() * 1000)
    return jsonify({"data": results, "last_updated": last_updated})

def validate_uploaded_metadata(upload, token, data):
    sub_type = data.get('sub_type').lower()
    fullpath = upload.get("fullpath")
    validate_uuids = data.get('validate_uuids')
    message = []
    records = []
    headers = []
    sample_ids_list = []
    source_ids_list = []
    row_num = 0
    blank_sources_or_samples = False
    with open(fullpath, newline="") as tsvfile:
        reader = csv.DictReader(tsvfile, delimiter="\t")
        first = True
        for row in reader:
            row_num = row_num + 1
            data_row = {}
            for key in row.keys():
                if first:
                    headers.append(key)
                data_row[key] = row[key]
            records.append(data_row)
            sample_id = data_row.get('sample_id')
            source_id = data_row.get('source_id')
            if sample_id and sample_id.strip():
                sample_ids_list.append(data_row.get('sample_id'))
            else:
                message.append(f"Missing sample_id for row {row_num}")
                blank_sources_or_samples = True
            if source_id and source_id.strip():
                source_ids_list.append(data_row.get('source_id'))
            else:
                message.append(f"Missing source_id for row {row_num}")
                blank_sources_or_samples = True
            if first:
                first = False
    # Verify all source and sample id's exist
    source_ids_str = ", ".join([f"'{id}'" for id in source_ids_list])
    sample_ids_str = ", ".join([f"'{id}'" for id in sample_ids_list])
    entities_exist_query = (
        f"WITH [{source_ids_str}] AS source_ids, [{sample_ids_str}] AS sample_ids "
        f"UNWIND source_ids AS sid "
        f"OPTIONAL MATCH (n) WHERE n.hubmap_id = sid "
        f"WITH source_ids, sample_ids, sid, n "
        f"WHERE n IS NULL "
        f"WITH collect(sid) AS missing_source_ids, sample_ids "
        f"UNWIND sample_ids AS samp "
        f"OPTIONAL MATCH (m) WHERE m.hubmap_id = samp "
        f"WITH missing_source_ids, samp, m "
        f"WHERE m IS NULL "
        f"WITH missing_source_ids, collect(samp) AS missing_sample_ids "
        f"RETURN missing_source_ids, missing_sample_ids "
    )
    try:
        missing_source_ids = None
        missing_sample_ids = None
        with neo4j_driver_instance.session() as neo_session:       
            result = neo_session.run(entities_exist_query)
            row = result.single()
            if row:
                row = dict(row)
                missing_source_ids = row['missing_source_ids'] if 'missing_source_ids' in row else []
                missing_sample_ids = row['missing_sample_ids'] if 'missing_sample_ids' in row else []
    except Exception as e:
        internal_server_error(f"Unable to validate existence of source and sample ids. {e}")
    if missing_sample_ids:
        message.append(f"The following sample_ids were not found: {', '.join(missing_sample_ids)}")
    if missing_source_ids:
        message.append(f"The following source_ids were not found: {', '.join(missing_source_ids)}")
    if missing_sample_ids or missing_source_ids or blank_sources_or_samples:
        return message
    cedar_sample_sub_type_ids = {
        "block": "3e98cee6-d3fb-467b-8d4e-9ba7ee49eeff",
        "section": "01e9bc58-bdf2-49f4-9cf9-dd34f3cc62d7",
        "suspension": "ea4fb93c-508e-4ec4-8a4b-89492ba68088"
    }
    accepted_subtypes = ", ".join(cedar_sample_sub_type_ids.keys())
    if not sub_type in cedar_sample_sub_type_ids:
        message.append(f'Unrecognized sub_type {sub_type}. Valid subtypes for samples are: {accepted_subtypes}')
        return message
    if not (len(records) and"metadata_schema_id" in records[0]):
        message.append(f'Unsupported uploaded TSV spec for sample {sub_type}. CEDAR formatting is required for samples. For more details, check out the docs: https://hubmapconsortium.github.io/ingest-validation-tools/current')
        return message
    else:
        if records[0]["metadata_schema_id"].lower() != cedar_sample_sub_type_ids[sub_type].lower():
            message.append(f'Mismatch of "sample {sub_type}" and "metadata_schema_id". \nValid id for "{sub_type}": {cedar_sample_sub_type_ids[sub_type]}. \nFor more details, check out the docs "https://hubmapconsortium.github.io/ingest-validation-tools/"')
            return message
    schema = f'sample-{sub_type}'
    try:
        app_context = {
            "request_header": {"X-Hubmap-Application": "ingest-api"},
            "ingest_url": commons_file_helper.ensureTrailingSlashURL(app.config["FLASK_APP_BASE_URI"]),
            "entities_url": f"{commons_file_helper.ensureTrailingSlashURL(app.config['ENTITY_WEBSERVICE_URL'])}entities/",
            "constraints_url": f"{commons_file_helper.ensureTrailingSlashURL(app.config['ENTITY_WEBSERVICE_URL'])}constraints/"

        }
        validation_results = iv_utils.get_tsv_errors(
            fullpath,
            schema_name=schema,
            report_type=table_validator.ReportType.JSON,
            globus_token=token,
            app_context=app_context,
        )
    except schema_loader.PreflightError as e:
        internal_server_error(f"'Preflight': {str(e)}")
    except Exception as e:
        internal_server_error(e)
    if len(validation_results) > 0:
        if not isinstance(validation_results, list):
            validation_results = [validation_results]

        logger.error(f"Error validating metadata: {validation_results}")
        message.append(f"Error validating metadata: {validation_results}")
        return message
    if validate_uuids == "1":
        errors = []
        passing = []
        idx = 1
        for r in records:
            ok = True
            # First get the id column name, in order to get HuBMAP id in the record
            id_col = "sample_id"
            entity_id = r.get(id_col)
            if entity_id is None:
                errors.append(f"Must supply `{id_col}` and valid value", idx, id_col)
                message = errors
                return message
            try:
                url = commons_file_helper.ensureTrailingSlashURL(app.config["ENTITY_WEBSERVICE_URL"])+ "entities/"+ entity_id
                header = {'Authorization': 'Bearer ' + token,  'X-Hubmap-Application': 'ingest-api'}
                resp = requests.get(url, headers=header)
            except requests.exceptions.RequestException as e:
                logger.error(f"Error validating metadata: {e}")
            if resp.status_code > 299:
                errors.append(f"Invalid `{id_col}`: `{entity_id}`", idx, id_col)
                message = errors
                return message
            entity = resp.json()
            result_entity = {"uuid": entity["uuid"]}
            related_id_col = "source_id"
            related_entity_id = r.get('source_id')
            if related_entity_id is not None:
                try:
                    url = commons_file_helper.ensureTrailingSlashURL(app.config["ENTITY_WEBSERVICE_URL"])+ "entities/"+ related_entity_id
                    header = {'Authorization': 'Bearer ' + token,  'X-Hubmap-Application': 'ingest-api'}
                    resp = requests.get(url, headers=header)
                except requests.exceptions.RequestException as e:
                    logger.error(f"Error validating metadata: {e}")
                if resp.status_code > 299:
                    errors.append(f"Invalid `{related_id_col}`: `{related_entity_id}`", idx, id_col)
                    ok = False
            else:
                message = f'Unsupported uploaded TSV spec for "sample {sub_type}". Missing `{related_id_col}` column. For more details, check out the docs: https://hubmapconsortium.github.io/ingest-validation-tools/current'
                return message
            if sub_type is not None:
                sub_type_col = 'sample_category'
                _sub_type = entity.get(sub_type_col)
                if _sub_type.lower() not in ['block', 'section', 'suspension']:
                    errors.append(f'{sub_type} unsupported on check of given `{entity_id}`. {idx}. {sub_type_col}')
                    ok = False
                if _sub_type.lower() != sub_type.lower():
                    errors.append(f'got `{_sub_type}` on check of given `{entity_id}` expected `{sub_type}` for `{sub_type_col}`. {idx}. {id_col}')
                    ok = False
            if ok is True:
                result_entity["metadata"] = r
                passing.append(result_entity)
            idx += 1
        if len(errors) >= 0:
            message = errors
            return message
    return message
            

"""
Accepts a tsv containing metadata of multiple samples, validates with cedar via ingest-validation-tools, validates sample ids
and their associated sources. If invalid, returns the errors, if valid, updates the provided samples metadata via neo4j, 
flushes the cache in entity-api, and reindexes the entities via search-api
Input
--------
Input is via PUT request multipart/form-data body. Most of the fields are given by an attached tsv file; additional fields are also included

metadata : tsv file
    the tsv file containing datasets to have their metadata registered
sub_type : str
        The sample category of the given samples
validate_uuids: int
    An integer value 1 or 0 indicating whether the individual samples should be validated along with the schema. 
Returns
--------
message : json array of representing the individual errors returned from ingest-validation-tools
202: json containing {'message': 'accepted'}
"""
@app.route('/sample-bulk-metadata', methods=['PUT'])
def sample_bulk_metadata():
    if 'metadata' not in request.files:
        bad_request_error('No metadata part')
    file = request.files['metadata']
    sub_type = request.form.get('sub_type')
    validate_uuids = request.form.get('validate_uuids')
    if sub_type is None:
        bad_request_error('No sub_type in request')
    if validate_uuids is None:
        validate_uuids = "0"
    data = {
        "entity_type": "sample",
        "sub_type": sub_type,
        "validate_uuids": validate_uuids
    }
    if file.filename == '':
        bad_request_error('No selected file')
    file.filename = file.filename.replace(" ", "_")
    token = auth_helper_instance.getAuthorizationTokens(request.headers)
    header = {'Authorization': 'Bearer ' + token}
    try:
        temp_id = file_upload_helper_instance.save_temp_file(file)
    except Exception as e:
        bad_request_error(f"Failed to create temp_id: {e}")
    file.filename = utils.secure_filename(file.filename)
    path_name = temp_id + os.sep + file.filename
    file_details = {
        "filename": os.path.basename(path_name),
        "pathname": path_name,
        "fullpath": commons_file_helper.ensureTrailingSlash(app.config['FILE_UPLOAD_TEMP_DIR']) + temp_id + os.sep + file.filename
    }
    message = validate_uploaded_metadata(file_details, token, data)
    if len(message) > 0:
        # The validated output appears to be adding ADDITIONAL escape characters. Cleaning the message leaves it with the expected escapes.
        cleaned_message = [msg.replace('\"', '"').replace('\\n', '\n') for msg in message]
        error_message = ", ".join(cleaned_message)
        return jsonify({"error": f"Errors occurred during validation. {error_message}"}), 400
    headers = []
    records = []
    with open(file_details['fullpath'], newline="") as tsvfile:
        reader = csv.DictReader(tsvfile, delimiter="\t")
        first = True
        for row in reader:
            data_row = {}
            for key in row.keys():
                if first:
                    headers.append(key)
                data_row[key] = row[key]
            records.append(data_row)
            if first:
                first = False
    updates = []
    ids = []
    for r in records:
        id = r.get('sample_id')
        update = {
            'id': id,
            'metadata': json.dumps(r).replace('"', "'") 
        }
        updates.append(update)
        ids.append(id)

    update_query = "WITH ["
    update_query += ", ".join([f"{{id: \"{u['id']}\", metadata: \"{u['metadata']}\"}}" for u in updates])
    update_query += f"] AS updates UNWIND updates AS u MATCH (e {{hubmap_id: u.id}}) SET e.metadata = u.metadata"
    try:
        with neo4j_driver_instance.session() as neo_session:
            tx = neo_session.begin_transaction()
            result = tx.run(update_query)
            tx.commit()
    except TransactionError as e:
        if tx and tx.closed() == False:
            tx.rollback()
        internal_server_error(f"Metadata was validated but failed to update entities metadata. Transaction error: {e}")
    except Exception as e:
        internal_server_error(f"Metadata was validated but failed to update entities metadata. {e}")
    for id in ids:
        try:
            entity_resp = requests.delete(commons_file_helper.ensureTrailingSlashURL(app.config['ENTITY_WEBSERVICE_URL']) + f'flush-cache/{id}', headers=header)
            search_resp = requests.put(commons_file_helper.ensureTrailingSlashURL(app.config['SEARCH_WEBSERVICE_URL']) + f'reindex/{id}', headers=header)
        except HTTPException as hte:
            logger.error(f"Validated metadata and updated entities, but failed to reach flush entity cache or reindex entities. {hte.get_description()}, {hte.get_status_code()}")
        except Exception as e:
            logger.error(f"Validated metadata and updated entities, but failed to reach flush entity cache or reindex entities. {e}")
        
    return jsonify({"message": "Accepted"}), 202

@app.route('/donors/bulk-upload', methods=['POST'])
def bulk_donors_upload_and_validate():
    if 'file' not in request.files:
        bad_request_error('No file part')
    file = request.files['file']
    if file.filename == '':
        bad_request_error('No selected file')
    file.filename = file.filename.replace(" ", "_")
    try:
        temp_id = file_upload_helper_instance.save_temp_file(file)
    except Exception as e:
        bad_request_error(f"Failed to create temp_id: {e}")
    # uses csv.DictReader to add functionality to tsv file. Can do operations on rows and headers.
    records = []
    headers = []
    file.filename = utils.secure_filename(file.filename)
    file_location = commons_file_helper.ensureTrailingSlash(app.config['FILE_UPLOAD_TEMP_DIR']) + temp_id + os.sep + file.filename
    with open(file_location, newline='') as tsvfile:
        reader = csv.DictReader(tsvfile, delimiter='\t')
        first = True
        for row in reader:
            data_row = {}
            for key in row.keys():
                if first:
                    headers.append(key)
                data_row[key] = row[key]
            records.append(data_row)
            if first:
                first = False
    if len(records) > 40:
        bad_request_error("Bulk upload TSV files must contain no more than 40 rows. If more than 40 are needed, please split TSV file for multiple submissions.")
    validfile = validate_donors(headers, records)
    if validfile == True:
        return Response(json.dumps({'temp_id': temp_id}, sort_keys=True), 201, mimetype='application/json')
    if type(validfile) == list:
        return_validfile = {}
        error_num = 0
        for item in validfile:
            return_validfile[str(error_num)] = str(item)
            error_num = error_num + 1
        response_body = {"status": "fail", "data": return_validfile}
        return Response(json.dumps(response_body, sort_keys=True), 400,
                        mimetype='application/json')  # The exact format of the return to be determined


@app.route('/donors/bulk', methods=['POST'])
def create_donors_from_bulk():
    request_data = request.get_json()
    token = auth_helper_instance.getAuthorizationTokens(request.headers)
    header = {'Authorization': 'Bearer ' + token}
    temp_id = request_data['temp_id']
    group_uuid = None
    if "group_uuid" in request_data:
        group_uuid = request_data['group_uuid']
    temp_dir = app.config['FILE_UPLOAD_TEMP_DIR']
    tsv_directory = commons_file_helper.ensureTrailingSlash(temp_dir) + temp_id + os.sep
    if not os.path.exists(tsv_directory):
        return_body = {"status": "fail", "message": f"Temporary file with id {temp_id} does not have a temp directory"}
        return Response(json.dumps(return_body, sort_keys=True), 400, mimetype='application/json')
    fcount = 0
    temp_file_name = None
    for tfile in os.listdir(tsv_directory):
        fcount = fcount + 1
        temp_file_name = tfile
    if fcount == 0:
        return Response(json.dumps({"status": "fail", "message": f"File not found in temporary directory /{temp_id}"},
                                   sort_keys=True), 400, mimetype='application/json')
    if fcount > 1:
        return Response(
            json.dumps({"status": "fail", "message": f"Multiple files found in temporary file path /{temp_id}"},
                       sort_keys=True), 400, mimetype='application/json')
    tsvfile_name = tsv_directory + temp_file_name
    records = []
    headers = []
    with open(tsvfile_name, newline='') as tsvfile:
        reader = csv.DictReader(tsvfile, delimiter='\t')
        first = True
        for row in reader:
            data_row = {}
            for key in row.keys():
                if first:
                    headers.append(key)
                data_row[key] = row[key]
            records.append(data_row)
            if first:
                first = False
    validfile = validate_donors(headers, records)
    if type(validfile) == list:
        return_validfile = {}
        error_num = 0
        for item in validfile:
            return_validfile[str(error_num)] = str(item)
            error_num = error_num + 1
        response_body = {"status": "fail", "data": return_validfile}
        return Response(json.dumps(response_body, sort_keys=True), 400, mimetype='application/json')
    entity_response = {}
    row_num = 1
    if validfile == True:
        entity_created = False
        entity_failed_to_create = False
        for item in records:
            item['lab_donor_id'] = item['lab_id']
            del item['lab_id']
            item['label'] = item['lab_name']
            del item['lab_name']
            item['protocol_url'] = item['selection_protocol']
            del item['selection_protocol']
            if group_uuid is not None:
                item['group_uuid'] = group_uuid
            r = requests.post(
                commons_file_helper.ensureTrailingSlashURL(app.config['ENTITY_WEBSERVICE_URL']) + 'entities/donor',
                headers=header, json=item)
            entity_response[row_num] = r.json()
            row_num = row_num + 1
            status_code = r.status_code
            if r.status_code > 399:
                entity_failed_to_create = True
            else:
                entity_created = True
        if entity_created and not entity_failed_to_create:
            response_status = "Success - All Entities Created Successfully"
            status_code = 201
        elif entity_failed_to_create and not entity_created:
            response_status = "Failure - None of the Entities Created Successfully"
            status_code = 500
        elif entity_created and entity_failed_to_create:
            response_status = "Partial Success - Some Entities Created Successfully"
            status_code = 207
        response = {"status": response_status, "data": entity_response}
        return Response(json.dumps(response, sort_keys=True), status_code, mimetype='application/json')


@app.route('/samples/bulk-upload', methods=['POST'])
def bulk_samples_upload_and_validate():
    token = auth_helper_instance.getAuthorizationTokens(request.headers)
    header = {'Authorization': 'Bearer ' + token}
    if 'file' not in request.files:
        bad_request_error('No file part')
    file = request.files['file']
    if file.filename == '':
        bad_request_error('No selected file')
    file.filename = file.filename.replace(" ", "_")
    try:
        temp_id = file_upload_helper_instance.save_temp_file(file)
    except Exception as e:
        bad_request_error(f"Failed to create temp_id: {e}")
    # uses csv.DictReader to add functionality to tsv file. Can do operations on rows and headers.
    records = []
    headers = []
    file.filename = utils.secure_filename(file.filename)
    file_location = commons_file_helper.ensureTrailingSlash(
        app.config['FILE_UPLOAD_TEMP_DIR']) + temp_id + os.sep + file.filename
    with open(file_location, newline='') as tsvfile:
        reader = csv.DictReader(tsvfile, delimiter='\t')
        first = True
        for row in reader:
            data_row = {}
            for key in row.keys():
                if first:
                    headers.append(key)
                data_row[key] = row[key]
            records.append(data_row)
            if first:
                first = False
    if len(records) > 40:
        bad_request_error("Bulk upload TSV files must contain no more than 40 rows. If more than 40 are needed, please split TSV file for multiple submissions.")
    validfile = validate_samples(headers, records, header)
    if validfile == True:
        return Response(json.dumps({'temp_id': temp_id}, sort_keys=True), 201, mimetype='application/json')
    if type(validfile) == list:
        return_validfile = {}
        error_num = 0
        for item in validfile:
            return_validfile[str(error_num)] = str(item)
            error_num = error_num + 1
        response_body = {"status": "fail", "data": return_validfile}
        return Response(json.dumps(response_body, sort_keys=True), 400, mimetype='application/json')


@app.route('/samples/bulk', methods=['POST'])
def create_samples_from_bulk():
    request_data = request.get_json()
    token = auth_helper_instance.getAuthorizationTokens(request.headers)
    header = {'Authorization': 'Bearer ' + token}
    temp_id = request_data['temp_id']
    group_uuid = None
    if "group_uuid" in request_data:
        group_uuid = request_data['group_uuid']
    temp_dir = app.config['FILE_UPLOAD_TEMP_DIR']
    tsv_directory = commons_file_helper.ensureTrailingSlash(temp_dir) + temp_id + os.sep
    if not os.path.exists(tsv_directory):
        return_body = {"status": "fail", "message": f"Temporary file with id {temp_id} does not have a temp directory"}
        return Response(json.dumps(return_body, sort_keys=True), 400, mimetype='application/json')
    fcount = 0
    temp_file_name = None
    for tfile in os.listdir(tsv_directory):
        fcount = fcount + 1
        temp_file_name = tfile
    if fcount == 0:
        return Response(json.dumps({"status": "fail", "message": f"File not found in temporary directory /{temp_id}"},
                                   sort_keys=True), 400, mimetype='application/json')
    if fcount > 1:
        return Response(
            json.dumps({"status": "fail", "message": f"Multiple files found in temporary file path /{temp_id}"},
                       sort_keys=True), 400, mimetype='application/json')
    tsvfile_name = tsv_directory + temp_file_name
    records = []
    headers = []
    with open(tsvfile_name, newline='') as tsvfile:
        reader = csv.DictReader(tsvfile, delimiter='\t')
        first = True
        for row in reader:
            data_row = {}
            for key in row.keys():
                if first:
                    headers.append(key)
                data_row[key] = row[key]
            records.append(data_row)
            if first:
                first = False
    validfile = validate_samples(headers, records, header)
    if type(validfile) == list:
        return_validfile = {}
        error_num = 0
        for item in validfile:
            return_validfile[str(error_num)] = str(item)
            error_num = error_num + 1
        response_body = {"status": "fail", "data": return_validfile}
        return Response(json.dumps(response_body, sort_keys=True), 400, mimetype='application/json')
    entity_response = {}
    row_num = 1
    if validfile == True:
        entity_created = False
        entity_failed_to_create = False
        for item in records:
            item['direct_ancestor_uuid'] = item['source_id']
            del item['source_id']
            item['lab_tissue_sample_id'] = item['lab_id']
            del item['lab_id']
            
            item['organ'] = item['organ_type']
            del item['organ_type']
            item['protocol_url'] = item['sample_protocol']
            del item['sample_protocol']
            if item['organ'] == '':
                del item['organ']
            if item['rui_location'] == '':
                del item['rui_location']
            else:
                rui_location_json = json.loads(item['rui_location'])
                item['rui_location'] = rui_location_json
            if group_uuid is not None:
                item['group_uuid'] = group_uuid
            r = requests.post(
                commons_file_helper.ensureTrailingSlashURL(app.config['ENTITY_WEBSERVICE_URL']) + 'entities/sample',
                headers=header, json=item)
            entity_response[row_num] = r.json()
            row_num = row_num + 1
            if r.status_code > 399:
                entity_failed_to_create = True
            else:
                entity_created = True
        if entity_created and not entity_failed_to_create:
            response_status = "Success - All Entities Created Successfully"
            status_code = 201
        elif entity_failed_to_create and not entity_created:
            response_status = "Failure - None of the Entities Created Successfully"
            status_code = 500
        elif entity_created and entity_failed_to_create:
            response_status = "Partial Success - Some Entities Created Successfully"
            status_code = 207
        response = {"status": response_status, "data": entity_response}
        return Response(json.dumps(response, sort_keys=True), status_code, mimetype='application/json')


def validate_samples(headers, records, header):
    error_msg = []
    file_is_valid = True

    required_headers = ['source_id', 'lab_id', 'sample_category', 'organ_type', 'sample_protocol', 'description', 'rui_location']
    for field in required_headers:
        if field not in headers:
            file_is_valid = False
            error_msg.append(f"{field} is a required header. Even if a field is optional, the column and header must be present in the tsv file.")
    required_headers.append(None)
    for field in headers:
        if field == "":
            file_is_valid = False
            error_msg.append(f"<blank> is not an accepted field. Check for incorrect spaces and tabs in the header line")
        elif field not in required_headers:
            file_is_valid = False
            error_msg.append(f"{field} is not an accepted field. Check for any typo's in header row.")
    accepted_sample_categories = ["organ", "block", "section", "suspension"]

    organ_types_url = app.config['UBKG_WEBSERVICE_URL'] + 'organs/by-code?application_context=HUBMAP'
    organ_resource_file = requests.get(organ_types_url).json()

    rownum = 0
    valid_source_ids = []
    if file_is_valid is True:
        for data_row in records:
            rownum = rownum + 1

            # validate that no fields in data_row are none. If they are none, this means that there are more columns in
            #  the header than the data row and we cannot verify even if the entry we are validating is what it is
            #  supposed to be. Mark the entire row as bad if a none field exists.
            none_present = False
            for each in data_row.keys():
                if data_row[each] is None:
                    none_present = True
            if none_present:
                file_is_valid = False
                error_msg.append(
                    f"Row Number: {rownum}. This row has too few entries. Check file; verify spaces were not used where a tab should be. There should be as many entries in each column as their are headers, even if some fields are blank")
                continue

            # validate that no headers are None. This indicates that there are more columns in the data row than there
            # are columns in the header row. We cannot accurately validate the fields in this row if this is the case,
            # so mark the entire row as invalid and continue.
            if data_row.get(None) is not None:
                file_is_valid = False
                error_msg.append(f"Row Number: {rownum}. This row has too many entries. Check file; verify that there are only as many fields as there are headers")
                continue
            # validate rui_location
            rui_is_blank = True
            rui_location = data_row['rui_location']
            if len(rui_location) > 0:
                rui_is_blank = False
                if "\n" in rui_location:
                    file_is_valid = False
                    error_msg.append(f"Row Number: {rownum}. rui_location must contain no line breaks")
                try:
                    rui_location_dict = json.loads(rui_location)
                except:
                    file_is_valid = False
                    error_msg.append(f"Row Number: {rownum}. rui_location must be a valid json file")

            # validate sample_category
            sample_category = data_row['sample_category']
            if rui_is_blank is False and sample_category.lower() == 'organ':
                file_is_valid = False
                error_msg.append(f"Row Number: {rownum}. If rui_location field is not blank, sample type cannot be organ")
            if sample_category.lower() not in accepted_sample_categories:
                file_is_valid = False
                error_msg.append(f"Row Number: {rownum}. sample_category value must be a either 'organ', 'block', 'suspension', or 'section'")

            # validate organ_type
            organ_type = data_row['organ_type']
            if sample_category.lower() != "organ":
                if len(organ_type) > 0:
                    file_is_valid = False
                    error_msg.append(f"Row Number: {rownum}. organ_type field must be blank if sample_category is not 'organ'")
            if sample_category.lower() == "organ":
                if len(organ_type) < 1:
                    file_is_valid = False
                    error_msg.append(f"Row Number: {rownum}. organ_type field is required if sample_category is 'organ'")
            if len(organ_type) > 0:
                if organ_type.upper() not in organ_resource_file:
                    file_is_valid = False
                    error_msg.append(
                        f"Row Number: {rownum}. organ_type value must be a sample code listed in organ type file ({app.config['UBKG_WEBSERVICE_URL']}/organs/by-code?application_context=HUBMAP)")

            # validate description
            description = data_row['description']
            if len(description) > 10000:
                file_is_valid = False
                error_msg.append(f"Row Number: {rownum}. Description must be fewer than 10,000 characters")

            # validate sample_protocol
            protocol = data_row['sample_protocol']
            selection_protocol_pattern1 = re.match('^https://dx\.doi\.org/[\d]+\.[\d]+/protocols\.io\.[\w/]*$', protocol)
            selection_protocol_pattern2 = re.match('^[\d]+\.[\d]+/protocols\.io\.[\w/]*$', protocol)
            if selection_protocol_pattern2 is None and selection_protocol_pattern1 is None:
                file_is_valid = False
                error_msg.append(
                    f"Row Number: {rownum}. sample_protocol must either be of the format https://dx.doi.org/##.####/protocols.io.* or ##.####/protocols.io.*")
            if len(protocol) < 1:
                file_is_valid = False
                error_msg.append(f"row Number: {rownum}. sample_protocol is a required filed and cannot be blank.")

            # validate lab_id
            lab_id = data_row['lab_id']
            # lab_id_pattern = re.match('^\w*$', lab_id)
            if len(lab_id) > 1024:
                file_is_valid = False
                error_msg.append(f"Row Number: {rownum}. lab_id must be fewer than 1024 characters")
            # if lab_id_pattern is None:
            #     file_is_valid = False
            #     error_msg.append(f"Row Number: {rownum}. if lab_id is given, it must be an alphanumeric string")
            if len(lab_id) < 1:
                file_is_valid = False
                error_msg.append(f"Row Number: {rownum}. lab_id value cannot be blank")

            # validate source_id
            source_id = data_row['source_id']
            # hubmap_id_pattern = re.match('[A-Z]{3}[\d]{3}\.[A-Z]{4}\.[\d]{3}', source_id)
            # hubmap_uuid_pattern = re.match('([a-f]|[0-9]){32}', source_id)
            # hubmap_doi_pattern = re.match('[\d]{2}\.[\d]{4}/[A-Z]{3}[\d]{3}\.[A-Z]{4}\.[\d]{3}', source_id)
            if len(source_id) < 1:
                file_is_valid = False
                error_msg.append(f"Row Number: {rownum}. source_id cannot be blank")
            if len(source_id) > 0:
                source_dict = {}
                source_saved = False
                resp_status_code = False
                if len(valid_source_ids) > 0:
                    for item in valid_source_ids:
                        if item['hm_uuid'] or item['hubmap_id']:
                            if source_id == item['hm_uuid'] or source_id == item['hubmap_id']:
                                source_dict = item
                                source_saved = True
                if source_saved is False:
                    url = commons_file_helper.ensureTrailingSlashURL(app.config['UUID_WEBSERVICE_URL']) + source_id
                    # url = "https://uuid-api.dev.hubmapconsortium.org/hmuuid/" + source_id
                    resp = requests.get(url, headers=header)
                    if resp.status_code == 404:
                        file_is_valid = False
                        error_msg.append(f"Row Number: {rownum}. Unable to verify source_id exists")
                    if resp.status_code == 401:
                        file_is_valid = False
                        error_msg.append(f"Row Number: {rownum}. Unauthorized. Cannot access UUID-api")
                    if resp.status_code == 400:
                        file_is_valid = False
                        error_msg.append(f"Row Number: {rownum}. {source_id} is not a valid id format")
                    if resp.status_code < 300:
                        source_dict = resp.json()
                        valid_source_ids.append(source_dict)
                        resp_status_code = True
                if source_saved or resp_status_code:
                    data_row['source_id'] = source_dict['hm_uuid']
                    if sample_category.lower() == 'organ' and source_dict['type'].lower() != 'donor':
                        file_is_valid = False
                        error_msg.append(
                            f"Row Number: {rownum}. If sample type is organ, source_id must point to a donor")
                    if sample_category.lower() != 'organ' and source_dict['type'].lower() != 'sample':
                        file_is_valid = False
                        error_msg.append(
                            f"Row Number: {rownum}. If sample type is not organ, source_id must point to a sample")
                    if rui_is_blank is False and source_dict['type'].lower() == 'donor':
                        file_is_valid = False
                        error_msg.append(f"Row Number: {rownum}. If rui_location is not blank, source_id cannot be a donor")


    if file_is_valid:
        return file_is_valid
    if file_is_valid == False:
        return error_msg


#Validates a bulk tsv file containing multiple donors. A valid tsv of donors must have certain fields, and all fields have certain accepted values. Returns "true" if valid. If invalid, returns a list of strings of various error messages
def validate_donors(headers, records):
    error_msg = []
    file_is_valid = True

    # First we validate the header line. If the header line is wrong, its not necessary to even validate the data rows.
    required_headers = ['lab_name', 'selection_protocol', 'description', 'lab_id']
    for field in required_headers:
        if field not in headers:
            file_is_valid = False
            error_msg.append(f"{field} is a required header. Even if a field is optional, the column and header must be present in the tsv file.")
    required_headers.append(None)
    for field in headers:
        if field == "":
            file_is_valid = False
            error_msg.append(f"<blank> is not an accepted field. Check for incorrect spaces and tabs in the header line")
        elif field not in required_headers:
            file_is_valid = False
            error_msg.append(f"{field} is not an accepted field. Check for any typo's in header row.")
    rownum = 0
    if file_is_valid is True:
        for data_row in records:
            rownum = rownum + 1

            # validate that no fields in data_row are none. If they are none, this means that there are more columns in
            #  the header than the data row and we cannot verify even if the entry we are validating is what it is
            #  supposed to be. Mark the entire row as bad if a none field exists.
            none_present = False
            for each in data_row.keys():
                if data_row[each] is None:
                    none_present = True
            if none_present:
                file_is_valid = False
                error_msg.append(f"Row Number: {rownum}. This row has too few entries. Check file; verify spaces were not used where a tab should be. There should be as many entries in each column as their are headers, even if some fields are blank")
                continue

            # validate that no headers are None. This indicates that there are more columns in the data row than there
            # are columns in the header row. We cannot accurately validate the fields in this row if this is the case,
            # so mark the entire row as invalid and continue.
            if data_row.get(None) is not None:
                file_is_valid = False
                error_msg.append(
                    f"Row Number: {rownum}. This row has too many entries. Check file; verify that there are only as many fields as there are headers")
                continue
            #validate lab_name
            if len(data_row['lab_name']) > 1024:
                file_is_valid = False
                error_msg.append(f"Row Number: {rownum}. lab_name must be fewer than 1024 characters")
            if len(data_row['lab_name']) < 1:
                file_is_valid = False
                error_msg.append(f"Row Number: {rownum}. lab_name must have 1 or more characters")

            #validate selection_protocol
            protocol = data_row['selection_protocol']
            selection_protocol_pattern1 = re.match('^https://dx\.doi\.org/[\d]+\.[\d]+/protocols\.io\.[\w]*$', protocol)
            selection_protocol_pattern2 = re.match('^[\d]+\.[\d]+/protocols\.io\.[\w]*$', protocol)
            if selection_protocol_pattern2 is None and selection_protocol_pattern1 is None:
                file_is_valid = False
                error_msg.append(f"Row Number: {rownum}. selection_protocol must either be of the format https://dx.doi.org/##.####/protocols.io.* or ##.####/protocols.io.*")

            #validate description
            description = data_row['description']
            if len(description) > 10000:
                file_is_valid = False
                error_msg.append(f"Row Number: {rownum}. Description must be fewer than 10,000 characters")

            #validate lab_id
            lab_id = data_row['lab_id']
            #lab_id_pattern = re.match('^\w*$', lab_id)
            if len(lab_id) > 1024:
                file_is_valid = False
                error_msg.append(f"Row Number: {rownum}. lab_id must be fewer than 1024 characters")
            #if lab_id_pattern is None:
            #    file_is_valid = False
            #    error_msg.append(f"Row Number: {rownum}. if lab_id is given, it must be an alphanumeric string")

    if file_is_valid:
        return file_is_valid
    if file_is_valid == False:
        return error_msg


@app.route('/datasets/validate', methods=['POST'])
def validate_datasets():
    if not request.is_json:
        bad_request_error("A json body and appropriate Content-Type header are required")
    dataset_list = request.get_json()
    if not isinstance(dataset_list, list):
        bad_request_error("Required id list not found")
    token = auth_helper_instance.getAuthorizationTokens(request.headers)
    header = {'Authorization': 'Bearer ' + token}
    disallowed_status_types = ["published", "processing"]
    datasets_not_found = []
    q = """
    MATCH (ds:Entity)
    WHERE ds.uuid IN $ids OR ds.hubmap_id IN $ids
    RETURN ds.uuid AS uuid, ds.hubmap_id AS hubmap_id, ds.status AS status, ds.entity_type AS entity_type, 
    ds.group_uuid AS group_uuid, ds.contains_human_genetic_sequences AS contains_human_genetic_sequences, 
    ds.data_access_level AS data_access_level, ds.group_name AS group_name
    """
    with neo4j_driver_instance.session() as neo_session:
        output = neo_session.run(q, ids=dataset_list)
        result = list(output)
    
    matched_ids = set()
    input_to_entity = {}
    for record in result:
        uuid = record.get("uuid")
        hubmap_id = record.get("hubmap_id")
        if uuid:
            matched_ids.add(uuid)
        if hubmap_id:
            matched_ids.add(hubmap_id)

    for original_id in dataset_list:
        if original_id not in matched_ids:
            datasets_not_found.append(original_id)
        else:
            for record in result:
                if original_id == record.get("uuid") or original_id == record.get("hubmap_id"):
                    input_to_entity[original_id] = record
                    break

    if datasets_not_found:
        not_found_error(f"The following IDs could not be found: {', '.join(datasets_not_found)}")
    invalid_id_errors = []
    payload_list = []
    for original_id, record in input_to_entity.items():
        entity_type = record.get("entity_type")
        if entity_type.lower() != "dataset":
            invalid_id_errors.append(f"Invalid entity: All IDs in request must be for Datasets. Entity with id {original_id} is of type {entity_type}.")
            continue
        dataset_status = record.get("status")
        if dataset_status.lower() in disallowed_status_types:
            invalid_id_errors.append(f"Invalid entity: All IDs in request must not be in disallowed status types: {', '.join(disallowed_status_types)}. Entity with id {original_id} is currently '{dataset_status}'.")
            continue
        payload_helper = ds_helper(app.config)
        payload = payload_helper.create_ingest_payload(record)
        payload['process'] = 'validate.dataset'
        payload_list.append(payload)
    if invalid_id_errors:
        bad_request_error(f" ".join(invalid_id_errors))
    ingest_pipeline_url = commons_file_helper.ensureTrailingSlashURL(app.config["INGEST_PIPELINE_URL"]) + "request_bulk_ingest"
    try:
        ingest_res = requests.post(
            ingest_pipeline_url,
            json=payload_list,
            headers=header,
        )
        logger.info(
            f"Response from ingest-pipeline {ingest_res.status_code}: {ingest_res.text}"
        )
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to submit datasets to pipeline: {e}")
        return jsonify({"error": "Unexpected error. Failed to reach Ingest Pipeline"}), 500 

    if ingest_res.status_code == 200:
        return jsonify(list(input_to_entity.keys())), 202
    else:
        logger.error(f"Ingest Pipeline returned error {ingest_res.status_code}: {ingest_res.text}")
        return jsonify({"error": f"Ingest Pipeline responded with an unexpected error: HTTP {ingest_res.status_code}. Check the airflow logs to see which ID's were unsuccessful."}), 500
        

@app.route('/uploads/validate', methods=['POST'])
def validate_uploads():
    if not request.is_json:
        bad_request_error("A json body and appropriate Content-Type header are required")
    upload_list = request.get_json()
    if not isinstance(upload_list, list):
        bad_request_error("Required id list not found")
    token = auth_helper_instance.getAuthorizationTokens(request.headers)
    header = {'Authorization': 'Bearer ' + token}
    disallowed_status_types = ["reorganized", "processing"]
    uploads_not_found = []
    q = """
    MATCH (ds:Entity)
    WHERE ds.uuid IN $ids OR ds.hubmap_id IN $ids
    RETURN ds.uuid AS uuid, ds.hubmap_id AS hubmap_id, ds.status AS status, ds.entity_type AS entity_type, 
    ds.group_uuid AS group_uuid, ds.contains_human_genetic_sequences AS contains_human_genetic_sequences, 
    ds.data_access_level AS data_access_level, ds.group_name AS group_name
    """
    with neo4j_driver_instance.session() as neo_session:
        output = neo_session.run(q, ids=upload_list)
        result = list(output)
    
    matched_ids = set()
    input_to_entity = {}
    for record in result:
        uuid = record.get("uuid")
        hubmap_id = record.get("hubmap_id")
        if uuid:
            matched_ids.add(uuid)
        if hubmap_id:
            matched_ids.add(hubmap_id)

    for original_id in upload_list:
        if original_id not in matched_ids:
            uploads_not_found.append(original_id)
        else:
            for record in result:
                if original_id == record.get("uuid") or original_id == record.get("hubmap_id"):
                    input_to_entity[original_id] = record
                    break

    if uploads_not_found:
        not_found_error(f"The following IDs could not be found: {', '.join(uploads_not_found)}")
    invalid_id_errors = []
    payload_list = []
    for original_id, record in input_to_entity.items():
        entity_type = record.get("entity_type")
        if entity_type.lower() != "upload":
            invalid_id_errors.append(f"Invalid entity: All IDs in request must be for Uploads. Entity with id {original_id} is of type {entity_type}.")
            continue
        upload_status = record.get("status")
        if upload_status.lower() in disallowed_status_types:
            invalid_id_errors.append(f"Invalid entity: All IDs in request must not be in disallowed status types: {', '.join(disallowed_status_types)}. Entity with id {original_id} is currently '{upload_status}'.")
            continue
        ingest_helper = IngestFileHelper(app.config)
        full_path = ingest_helper.get_upload_directory_absolute_path(record['group_uuid'], record['uuid'])
        payload = {
            "submission_id": f"{record['uuid']}",
            "process": "validate.upload",
            "full_path": full_path,
            "provider": f"{record['group_name']}"
        }
        payload_list.append(payload)
    if invalid_id_errors:
        bad_request_error(f" ".join(invalid_id_errors))
    ingest_pipeline_url = commons_file_helper.ensureTrailingSlashURL(app.config["INGEST_PIPELINE_URL"]) + "request_bulk_ingest"
    try:
        ingest_res = requests.post(
            ingest_pipeline_url,
            json=payload_list,
            headers=header,
        )
        logger.info(
            f"Response from ingest-pipeline {ingest_res.status_code}: {ingest_res.text}"
        )
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to submit uploads to pipeline: {e}")
        return jsonify({"error": "Unexpected error. Failed to reach Ingest Pipeline"}), 500 

    if ingest_res.status_code == 200:
        return jsonify(list(input_to_entity.keys())), 202
    else:
        logger.error(f"Ingest Pipeline returned error {ingest_res.status_code}: {ingest_res.text}")
        return jsonify({"error": f"Ingest Pipeline responded with an unexpected error: HTTP {ingest_res.status_code}. Check the airflow logs to see which ID's were unsuccessful."}), 500


####################################################################################################
## Internal Functions
####################################################################################################

def get_dataset_abs_path(ds_uuid):
        ingest_helper = IngestFileHelper(app.config)
        with neo4j_driver_instance.session() as neo_session:
            q = (f"MATCH (entity {{uuid: '{ds_uuid}'}}) RETURN entity.entity_type AS entity_type, " 
                f"entity.group_uuid AS group_uuid, entity.contains_human_genetic_sequences as contains_human_genetic_sequences, " 
                f"entity.data_access_level AS data_access_level, entity.status AS status")
            result = neo_session.run(q).data()
            if len(result) < 1:
                raise ResponseException(f"No result found for uuid {ds_uuid}", 400)
            rval = result[0]
        ent_type = rval['entity_type']
        group_uuid = rval['group_uuid']
        is_phi = rval['contains_human_genetic_sequences']
        if ent_type is None or ent_type.strip() == '':
            raise ResponseException(f"Entity with uuid:{ds_uuid} needs to be a Dataset or Upload.", 400)
        if ent_type.lower().strip() == 'upload':
            return ingest_helper.get_upload_directory_absolute_path(group_uuid=group_uuid, upload_uuid=ds_uuid)
        if not get_entity_type_instanceof(ent_type, 'Dataset', auth_header=request.headers.get("AUTHORIZATION")):
            raise ResponseException(f"Entity with uuid: {ds_uuid} is not a Dataset, Publication or upload", 400)
        if group_uuid is None:
            raise ResponseException(f"Unable to find group uuid on dataset {ds_uuid}", 400)
        if is_phi is None:
            raise ResponseException(f"Contains_human_genetic_sequences is not set on dataset {ds_uuid}", 400)
        
        path = ingest_helper.get_dataset_directory_absolute_path(rval, group_uuid, ds_uuid)

        return path

# Determines if a dataset is Primary. If the list returned from the neo4j query is empty, the dataset is not primary
def dataset_is_primary(dataset_uuid):
    with neo4j_driver_instance.session() as neo_session:
        q = (f"MATCH (ds:Dataset {{uuid: '{dataset_uuid}'}})<-[:ACTIVITY_OUTPUT]-(a:Activity) WHERE toLower(a.creation_action) = 'create dataset activity' RETURN ds.uuid")
        result = neo_session.run(q).data()
        if len(result) == 0:
            return False
        return True


def dataset_has_entity_lab_processed_data_type(dataset_uuid):
    with neo4j_driver_instance.session() as neo_session:
        q = (f"MATCH (ds:Dataset {{uuid: '{dataset_uuid}'}})<-[:ACTIVITY_OUTPUT]-(a:Activity) WHERE a.creation_action = 'Lab Process' RETURN ds.uuid")
        result = neo_session.run(q).data()
        if len(result) == 0:
            return False
        return True

def dataset_is_multi_assay_component(dataset_uuid):
    with neo4j_driver_instance.session() as neo_session:
        q = (f"MATCH (ds:Dataset {{uuid: '{dataset_uuid}'}})<-[:ACTIVITY_OUTPUT]-(a:Activity) WHERE toLower(a.creation_action) = 'multi-assay split' RETURN ds.uuid")
        result = neo_session.run(q).data()
        if len(result) == 0:
            return False
        return True

def get_components_primary_path(component_uuid):
    with neo4j_driver_instance.session() as neo_session:
        q = (f"MATCH (pri:Dataset)-[:ACTIVITY_INPUT]->(a:Activity {{creation_action:'Multi-Assay Split'}})-[:ACTIVITY_OUTPUT]->(ds:Dataset {{uuid: '{component_uuid}'}}) RETURN pri.uuid as primary_uuid")
        result = neo_session.run(q).data()
        if len(result) == 0:            
            raise HTTPException(f"{component_uuid} no primary dataset found for component dataset", 500)
        pri_uuid = result[0]['primary_uuid']
        
        try:
            path = get_dataset_abs_path(pri_uuid)
        except ResponseException as re:
            raise HTTPException(f"{component_uuid} unable to fine path for primary parent {pri_uuid}. {re.message}", 500)

        return path

    
    
def validate_json_list(data):
    if not isinstance(data, list):
        return False
    if len(data) < 1:
        return False
    for item in data:
        if not isinstance(item, str):
            return False
    return True

def run_query(query, results, i):
    logger.info(query)
    with neo4j_driver_instance.session() as session:
        results[i] = session.run(query).data()


def get_globus_url(data_access_level, group_name, uuid):
    globus_server_uuid = None
    dir_path = ''
    # public access
    if data_access_level == "public":
        globus_server_uuid = app.config['GLOBUS_PUBLIC_ENDPOINT_UUID']
        access_dir = access_level_prefix_dir(app.config['PUBLIC_DATA_SUBDIR'])
        dir_path = dir_path + access_dir + "/"
    # consortium access
    elif data_access_level == 'consortium':
        globus_server_uuid = app.config['GLOBUS_CONSORTIUM_ENDPOINT_UUID']
        access_dir = access_level_prefix_dir(app.config['CONSORTIUM_DATA_SUBDIR'])
        dir_path = dir_path + access_dir + group_name + "/"
    # protected access
    elif data_access_level == 'protected':
        globus_server_uuid = app.config['GLOBUS_PROTECTED_ENDPOINT_UUID']
        access_dir = access_level_prefix_dir(app.config['PROTECTED_DATA_SUBDIR'])
        dir_path = dir_path + access_dir + group_name + "/"

    if globus_server_uuid is not None:
        dir_path = dir_path + uuid + "/"
        dir_path = urllib.parse.quote(dir_path, safe='')

        # https://app.globus.org/file-manager?origin_id=28bb03c-a87d-4dd7-a661-7ea2fb6ea631&origin_path=2%FIEC%20Testing%20Group%20F03584b3d0f8b46de1b29f04be1568779%2F
        globus_url = commons_file_helper.ensureTrailingSlash(app.config[
                                                                 'GLOBUS_APP_BASE_URL']) + "file-manager?origin_id=" + globus_server_uuid + "&origin_path=" + dir_path

    else:
        globus_url = ""
    if uuid is None:
        globus_url = ""
    return globus_url

"""
Ensure the access level dir with leading and trailing slashes

Parameters
----------
dir_name : str
    The name of the sub directory corresponding to each access level

Returns
-------
str 
    One of the formatted dir path string: /public/, /protected/, /consortium/
"""
def access_level_prefix_dir(dir_name):
    if isBlank(dir_name):
        return ''

    return commons_file_helper.ensureTrailingSlashURL(commons_file_helper.ensureBeginningSlashURL(dir_name))


def update_datasets_datastatus():
    rui_organs_url = app.config['UBKG_WEBSERVICE_URL'] + 'organs?application_context=HUBMAP'
    rui_organs_list = requests.get(rui_organs_url).json()
    organ_types_url = app.config['UBKG_WEBSERVICE_URL'] + 'organs/by-code?application_context=HUBMAP'
    organ_types_dict = requests.get(organ_types_url).json()
    all_datasets_query = (
        "MATCH (ds:Dataset)<-[:ACTIVITY_OUTPUT]-(a:Activity)<-[:ACTIVITY_INPUT]-(ancestor) "
        "RETURN ds.uuid AS uuid, ds.group_name AS group_name, "
        "ds.hubmap_id AS hubmap_id, ds.lab_dataset_id AS provider_experiment_id, ds.status AS status, "
        "ds.status_history AS status_history, ds.assigned_to_group_name AS assigned_to_group_name, "
        "ds.last_modified_timestamp AS last_touch, ds.published_timestamp AS published_timestamp, ds.created_timestamp AS created_timestamp, "
        "ds.data_access_level AS data_access_level, ds.ingest_task AS ingest_task, ds.error_message AS error_message, ds.dataset_type as dataset_type, ds.priority_project_list AS priority_project_list, "
        "COALESCE(ds.contributors IS NOT NULL) AS has_contributors, "
        "COALESCE(ds.contacts IS NOT NULL) AS has_contacts, "
        "a.creation_action AS activity_creation_action, collect({hubmap_id: ancestor.hubmap_id, uuid: ancestor.uuid}) AS parent_ancestors"
    )

    organ_query = (
        "MATCH (ds:Dataset)<-[*]-(o:Sample {sample_category: 'organ'}) "
        "WHERE (ds)<-[:ACTIVITY_OUTPUT]-(:Activity) "
        "RETURN DISTINCT ds.uuid AS uuid, o.organ AS organ, o.hubmap_id as organ_hubmap_id, o.uuid as organ_uuid "
    )

    donor_query = (
        "MATCH (ds:Dataset)<-[*]-(dn:Donor) "
        "WHERE (ds)<-[:ACTIVITY_OUTPUT]-(:Activity) "
        "RETURN DISTINCT ds.uuid AS uuid, "
        "COLLECT(DISTINCT dn.hubmap_id) AS donor_hubmap_id, COLLECT(DISTINCT dn.submission_id) AS donor_submission_id, "
        "COLLECT(DISTINCT dn.lab_donor_id) AS donor_lab_id, COALESCE(dn.metadata IS NOT NULL) AS has_donor_metadata"
    )

    processed_datasets_query = (
        "MATCH (s:Dataset)<-[:ACTIVITY_OUTPUT]-(a:Activity)<-[:ACTIVITY_INPUT]-(ds:Dataset) WHERE "
                             "a.creation_action in ['Central Process', 'Lab Process'] RETURN DISTINCT ds.uuid AS uuid, "
        "COLLECT(DISTINCT {uuid: s.uuid, hubmap_id: s.hubmap_id, status: s.status, created_timestamp: s.created_timestamp, data_access_level: s.data_access_level, group_name: s.group_name}) AS processed_datasets"
    )

    upload_query = (
        "MATCH (u:Upload)<-[:IN_UPLOAD]-(ds) "
        "RETURN DISTINCT ds.uuid AS uuid, COLLECT(DISTINCT u.hubmap_id) AS upload"
    )

    has_rui_query = (
        "MATCH (ds:Dataset) "
        "WHERE (ds)<-[:ACTIVITY_OUTPUT]-(:Activity) "
        "WITH ds, [(ds)<-[*]-(s:Sample) | s.rui_location] AS rui_locations, "
        "[(ds)<-[*]-(s:Sample) WHERE s.sample_category = 'block' | {hubmap_id: s.hubmap_id, uuid: s.uuid}] AS blocks "
        "RETURN ds.uuid AS uuid, any(rui_location IN rui_locations WHERE rui_location IS NOT NULL) AS has_rui_info, blocks"
)

    has_source_sample_metadata_query = (
        "MATCH (ds:Dataset)<-[:ACTIVITY_OUTPUT]-(a:Activity {creation_action: 'Create Dataset Activity'}) "
        "WITH ds, [s IN [(ds)<-[*]-(s:Sample) | s] "
        "WHERE (s)-[:ACTIVITY_INPUT]->(:Activity)-[:ACTIVITY_OUTPUT]->(:Dataset) | s.metadata] AS sourceMetadataList "
        "RETURN ds.uuid AS uuid, any(md IN sourceMetadataList WHERE md IS NOT NULL) AS has_source_sample_metadata"
    )

    displayed_fields = [
        "hubmap_id", "group_name", "status", "organ", "provider_experiment_id", "last_touch", "has_contacts",
        "has_contributors", "donor_hubmap_id", "donor_submission_id", "donor_lab_id", "has_dataset_metadata", 
        "has_donor_metadata", "upload", "has_rui_info", "globus_url", "has_data", "error_message", "organ_hubmap_id", "has_source_sample_metadata",
        "priority_project_list"
    ]

    queries = [all_datasets_query, organ_query, donor_query, processed_datasets_query,
               upload_query, has_rui_query, has_source_sample_metadata_query]
    results = [None] * len(queries)
    threads = []
    for i, query in enumerate(queries):
        thread = Thread(target=run_query, args=(query, results, i))
        thread.start()
        threads.append(thread)
    for thread in threads:
        thread.join()
    output_dict = {}
    # Here we specifically indexed the values in 'results' in case certain threads completed out of order
    all_datasets_result = results[0]
    organ_result = results[1]
    donor_result = results[2]
    processed_datasets_result = results[3]
    upload_result = results[4]
    has_rui_result = results[5]
    has_source_sample_metadata_result = results[6]

    for dataset in all_datasets_result:
        output_dict[dataset['uuid']] = dataset
    for dataset in organ_result:
        if output_dict.get(dataset['uuid']):
            output_dict[dataset['uuid']]['organ'] = dataset['organ']
            output_dict[dataset['uuid']]['organ_hubmap_id'] = dataset['organ_hubmap_id']
            output_dict[dataset['uuid']]['organ_uuid'] = dataset['organ_uuid']
    for dataset in donor_result:
        if output_dict.get(dataset['uuid']):
            output_dict[dataset['uuid']]['donor_hubmap_id'] = dataset['donor_hubmap_id']
            output_dict[dataset['uuid']]['donor_submission_id'] = dataset['donor_submission_id']
            output_dict[dataset['uuid']]['donor_lab_id'] = dataset['donor_lab_id']
            output_dict[dataset['uuid']]['has_donor_metadata'] = dataset['has_donor_metadata']
    for dataset in processed_datasets_result:
        if output_dict.get(dataset['uuid']):
            output_dict[dataset['uuid']]['processed_datasets'] = dataset['processed_datasets']
    for dataset in upload_result:
        if output_dict.get(dataset['uuid']):
            output_dict[dataset['uuid']]['upload'] = dataset['upload']
    for dataset in has_rui_result:
        if output_dict.get(dataset['uuid']):
            output_dict[dataset['uuid']]['has_rui_info'] = dataset['has_rui_info']
            output_dict[dataset['uuid']]['blocks'] = dataset['blocks']
    for dataset in has_source_sample_metadata_result:
        if output_dict.get(dataset['uuid']):
            output_dict[dataset['uuid']]['has_source_sample_metadata'] = dataset['has_source_sample_metadata']

    combined_results = []
    for uuid in output_dict:
        combined_results.append(output_dict[uuid])

    for dataset in combined_results:
        globus_url = get_globus_url(dataset.get('data_access_level'), dataset.get('group_name'), dataset.get('uuid'))
        dataset['globus_url'] = globus_url
        dataset['last_touch'] = dataset['last_touch'] if dataset['published_timestamp'] is None else dataset['published_timestamp']
        
        # Identify primary dataset based on `Activity.creation_action == "Create Dataset Activity"`
        # Component datasets grnerated by `Multi-Assay Split` and 
        # Processed datasets from `Central Process|ExternalProcess|Lab Process` are NOT primary
        # For performance, don't call `dataset_is_primary()` since it issues separate Neo4j query on each dataset - Zhou 2/10/2025
        dataset['is_primary'] = "True" if dataset.get('activity_creation_action').lower() == "create dataset activity" else "False"

        has_data = files_exist(dataset.get('uuid'), dataset.get('data_access_level'), dataset.get('group_name'))
        has_dataset_metadata = files_exist(dataset.get('uuid'), dataset.get('data_access_level'), dataset.get('group_name'), metadata=True)
        dataset['has_data'] = has_data
        dataset['has_dataset_metadata'] = has_dataset_metadata

        for prop in dataset:
            if isinstance(dataset[prop], list) and prop != 'processed_datasets':
                if len(dataset[prop]) > 0 and isinstance(dataset[prop][0], dict):
                    pass
                else:
                    dataset[prop] = ", ".join(dataset[prop])
            if isinstance(dataset[prop], (bool)):
                dataset[prop] = str(dataset[prop])
            if isinstance(dataset[prop], str) and \
                    len(dataset[prop]) >= 2 and \
                    dataset[prop][0] == "[" and dataset[prop][-1] == "]":
                
                # For cases like `"ingest_task": "[Empty directory]"` we should not
                # convert to a list and will cause ValueError if we try to convert
                # Leave it as the original value and move on - Zhou 7/22/2024
                try:
                    prop_as_list = string_helper.convert_str_literal(dataset[prop])
                    if len(prop_as_list) > 0:
                        dataset[prop] = prop_as_list
                    else:
                        dataset[prop] = ""
                except ValueError:
                    pass
            if dataset[prop] is None:
                dataset[prop] = ""
            if prop == 'processed_datasets':
                for processed in dataset['processed_datasets']:
                    processed['globus_url'] = get_globus_url(processed.get('data_access_level'), processed.get('group_name'), processed.get('uuid'))
        for field in displayed_fields:
            if dataset.get(field) is None:
                dataset[field] = ""
        if dataset.get('organ') and rui_organs_list:
            rui_codes = [organ['rui_code'] for organ in rui_organs_list]
            if dataset['organ'].upper() not in rui_codes:
                dataset['has_rui_info'] = "not-applicable"
        if dataset.get('organ') and dataset.get('organ') in organ_types_dict:
            dataset['organ'] = organ_types_dict[dataset['organ']]

    try:
        combined_results_string = json.dumps(combined_results)
    except json.JSONDecodeError as e:
        try:
            redis_connection.set(DATASETS_DATA_STATUS_RUNNING_KEY, int(False))
        except Exception as v:
            logger.error(f"Failed to set datasets_data_status_running {v}")
        bad_request_error(e)
    try:
        redis_connection.set(DATASETS_DATA_STATUS_KEY, combined_results_string)
        redis_connection.set(DATASETS_DATA_STATUS_LAST_UPDATED_KEY, int(time.time() * 1000))
        redis_connection.set(DATASETS_DATA_STATUS_RUNNING_KEY, int(False))
    except Exception as e:
        # In the event of a caching failue, the endpoint should regenerate the data every call
        logger.error(f"Failed to set datasets_data_status in redis {e}")
    return combined_results

def update_uploads_datastatus():
    all_uploads_query = (
        "MATCH (up:Upload) "
        "OPTIONAL MATCH (up)<-[:IN_UPLOAD]-(ds:Dataset) "
        "RETURN up.uuid AS uuid, up.group_name AS group_name, up.hubmap_id AS hubmap_id, up.status AS status, "
        "up.title AS title, up.ingest_task AS ingest_task, up.error_message AS error_message, up.assigned_to_group_name AS assigned_to_group_name, "
        "up.intended_organ AS intended_organ, up.intended_dataset_type AS intended_dataset_type, up.priority_project_list AS priority_project_list, "
        "up.anticipated_complete_upload_month AS anticipated_complete_upload_month, up.anticipated_dataset_count AS anticipated_dataset_count, "
        "COLLECT(DISTINCT ds.uuid) AS datasets "
    )

    with neo4j_driver_instance.session() as session:
        results = session.run(all_uploads_query).data()
        for upload in results:
            globus_url = get_globus_url('protected', upload.get('group_name'), upload.get('uuid'))
            upload['globus_url'] = globus_url
            for prop in upload:
                if isinstance(upload[prop], list):
                    upload[prop] = ", ".join(upload[prop])
                if isinstance(upload[prop], (bool, int)):
                    upload[prop] = str(upload[prop])
                if isinstance(upload[prop], str) and \
                        len(upload[prop]) >= 2 and \
                        upload[prop][0] == "[" and upload[prop][-1] == "]":
                    # For cases like `"ingest_task": "[Empty directory]"` we should not
                    # convert to a list and will cause ValueError if we try to convert
                    try:
                        prop_as_list = string_helper.convert_str_literal(upload[prop])
                        if len(prop_as_list) > 0:
                            upload[prop] = prop_as_list
                        else:
                            upload[prop] = ""
                    except ValueError:
                        pass
                if upload[prop] is None:
                    upload[prop] = ""
    try:
        results_string = json.dumps(results)
    except json.JSONDecodeError as e:
        try:
            redis_connection.set(UPLOADS_DATA_STATUS_RUNNING_KEY, int(False))
        except Exception as v:
            logger.error(f"Failed to set uploads_data_status_running {v}")
        bad_request_error(e)
    try:
        redis_connection.set(UPLOADS_DATA_STATUS_KEY, results_string)
        redis_connection.set(UPLOADS_DATA_STATUS_LAST_UPDATED_KEY, int(time.time() * 1000))
        redis_connection.set(UPLOADS_DATA_STATUS_RUNNING_KEY, int(False))
    except Exception as e:
        # In the event of a caching failue, the endpoint should regenerate the data every call
        logger.error(f"Failed to set uploads_data_status in redis {e}")
    return results


def files_exist(uuid, data_access_level, group_name, metadata=False):
    if not uuid or not data_access_level:
        return False
    if data_access_level == "public":
        absolute_path = commons_file_helper.ensureTrailingSlashURL(app.config['GLOBUS_PUBLIC_ENDPOINT_FILEPATH'])
    # consortium access
    elif data_access_level == 'consortium':
        absolute_path = commons_file_helper.ensureTrailingSlashURL(app.config['GLOBUS_CONSORTIUM_ENDPOINT_FILEPATH'] + '/' + group_name)
    # protected access
    elif data_access_level == 'protected':
        absolute_path = commons_file_helper.ensureTrailingSlashURL(app.config['GLOBUS_PROTECTED_ENDPOINT_FILEPATH'] + '/'  + group_name)

    file_path = absolute_path + uuid
    if os.path.exists(file_path) and os.path.isdir(file_path) and os.listdir(file_path):
        if not metadata:
            return True
        else:
            if any(glob.iglob(os.path.join(file_path, '*metadata.tsv'))):
                return True
            else:
                return False
    else:
        return False



# From the time update_datasets/uploads_datastatus are queued, until they complete for the first time, a 202 should be returned
# This flag is tracked in redis    
redis_connection = redis.from_url(app.config['REDIS_URL'])
try:
    redis_connection.set(DATASETS_DATA_STATUS_RUNNING_KEY, int(True))
    redis_connection.set(UPLOADS_DATA_STATUS_RUNNING_KEY, int(True))
except Exception as e:
    # If for some reason redis were to encounter a problem here, just log it so it doesn't hold up the rest of the ingest service. A redundant 
    # call to update data status is better than throwing an error
    logger.error("Failed to set datasets/uploads_data_status_running_key")

scheduler = BackgroundScheduler()
scheduler.start()


scheduler.add_job(
    func=update_datasets_datastatus,
    trigger=IntervalTrigger(hours=1),
    id='update_dataset_data_status',
    name="Update Dataset Data Status Job"
)

scheduler.add_job(
    func=update_uploads_datastatus,
    trigger=IntervalTrigger(hours=1),
    id='update_upload_data_status',
    name="Update Upload Data Status Job"
)

scheduler.add_job(
    func=update_datasets_datastatus,
    trigger=DateTrigger(run_date=datetime.datetime.now() + datetime.timedelta(minutes=1)),
    name="Initial run of Dataset Data Status Job"
)

scheduler.add_job(
    func=update_uploads_datastatus,
    trigger=DateTrigger(run_date=datetime.datetime.now() + datetime.timedelta(minutes=1)),
    name="Initial run of Dataset Data Status Job"
)

# For local development/testing
if __name__ == '__main__':
    try:
        parser = argparse.ArgumentParser()
        parser.add_argument("-p", "--port")
        args = parser.parse_args()
        port = 8484
        if args.port:
            port = int(args.port)
        app.run(port=port, host='0.0.0.0')
    finally:
        pass
