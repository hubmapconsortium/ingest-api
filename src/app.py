import datetime
import redis
import os
import sys
import logging
import urllib.request
import requests
import re
import json
from uuid import UUID
import yaml
import csv
from typing import List
import time
from threading import Thread
from hubmap_sdk import EntitySdk
from queue import Queue
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
# Don't confuse urllib (Python native library) with urllib3 (3rd-party library, requests also uses urllib3)
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import argparse
from pathlib import Path
from flask import Flask, g, jsonify, abort, request, json, Response
from flask_cors import CORS
from flask_mail import Mail, Message

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

from atlas_consortia_commons.ubkg import initialize_ubkg
from atlas_consortia_commons.rest import get_http_exceptions_classes, abort_err_handler
from atlas_consortia_commons.ubkg.ubkg_sdk import init_ontology

# Local modules
from specimen import Specimen
from ingest_file_helper import IngestFileHelper
from file_upload_helper import UploadFileHelper
import app_manager
from dataset import Dataset
from datacite_doi_helper_object import DataCiteDoiHelper

from app_utils.request_validation import require_json
from app_utils.error import unauthorized_error, not_found_error, internal_server_error, bad_request_error
from app_utils.misc import __get_dict_prop
from app_utils.entity import __get_entity, get_entity_type_instanceof
from app_utils.task_queue import TaskQueue
from werkzeug import utils

from routes.auth import auth_blueprint
from routes.datasets import datasets_blueprint
from routes.file import file_blueprint
from routes.assayclassifier import bp as assayclassifier_blueprint
from routes.validation import validation_blueprint


# Set logging format and level (default is warning)
# All the API logging is forwarded to the uWSGI server and gets written into the log file `uwsgi-ingest-api.log`
# Log rotation is handled via logrotate on the host system with a configuration file
# Do NOT handle log file and rotation via the Python logging to avoid issues with multi-worker processes
logging.basicConfig(format='[%(asctime)s] %(levelname)s in %(module)s: %(message)s',
                    level=logging.DEBUG,
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


"""
Close the current neo4j connection at the end of every request
"""
@app.teardown_appcontext
def close_neo4j_driver(error):
    if hasattr(g, 'neo4j_driver_instance'):
        # Close the driver instance
        neo4j_driver.close()
        # Also remove neo4j_driver_instance from Flask's application context
        g.neo4j_driver_instance = None


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
    response_data = {
        # Use strip() to remove leading and trailing spaces, newlines, and tabs
        'version': (Path(__file__).absolute().parent.parent / 'VERSION').read_text().strip(),
        'build': (Path(__file__).absolute().parent.parent / 'BUILD').read_text().strip(),
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
## Ingest API Endpoints
####################################################################################################

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
        post_url = commons_file_helper.ensureTrailingSlashURL(app.config['ENTITY_WEBSERVICE_URL']) + f'entities/{entity_type}'
        response = requests.post(post_url, json = dataset_request, headers = {'Authorization': 'Bearer ' + token, 'X-Hubmap-Application':'ingest-api' }, verify = False)
        if response.status_code != 200:
            return Response(response.text, response.status_code)
        new_dataset = response.json()

        ingest_helper.create_dataset_directory(new_dataset, requested_group_uuid, new_dataset['uuid'])

        return jsonify(new_dataset)
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

        requested_group_uuid = None
        if 'group_uuid' in component_request:
            requested_group_uuid = component_request['group_uuid']

        ingest_helper = IngestFileHelper(app.config)
        requested_group_uuid = auth_helper.get_write_group_uuid(token, requested_group_uuid)
        component_request['group_uuid'] = requested_group_uuid
        post_url = commons_file_helper.ensureTrailingSlashURL(app.config['ENTITY_WEBSERVICE_URL']) + 'datasets/components'
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




def get_data_type_of_external_dataset_providers(ubkg_base_url: str) -> List[str]:
    """
    The web service call will return a list of dictionaries having the following keys:
    'alt-names', 'contains-pii', 'data_type', 'dataset_provider', 'description',
     'primary', 'vis-only', 'vitessce-hints'.

     This will only return a list of strings that are the 'data_type's.
    """

    url = f"{ubkg_base_url.rstrip('/')}/datasets?application_context=HUBMAP&dataset_provider=external"
    resp = requests.get(url)
    if resp.status_code != 200:
        return {}
    return [x['data_type'].strip() for x in resp.json()]


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
            q = f"MATCH (dataset:Dataset {{uuid: '{dataset_uuid}'}})<-[:ACTIVITY_OUTPUT]-(e1)<-[:ACTIVITY_INPUT|ACTIVITY_OUTPUT*]-(all_ancestors:Entity) RETURN distinct all_ancestors.uuid as uuid, all_ancestors.entity_type as entity_type, all_ancestors.data_types as data_types, all_ancestors.data_access_level as data_access_level, all_ancestors.status as status, all_ancestors.metadata as metadata"
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
                        living_donor = True
                        organ_donor = True
                        if metadata_dict.get('organ_donor_data') is None:
                            living_donor = False
                        if metadata_dict.get('living_donor_data') is None:
                            organ_donor = False
                        if (organ_donor and living_donor) or (not organ_donor and not living_donor):
                            return jsonify({"error": f"donor.metadata.organ_donor_data or "
                                                     f"donor.metadata.living_donor_data required. "
                                                     f"Both cannot be None. Both cannot be present. Only one."}), 400
                    donors_to_reindex.append(uuid)
                    if data_access_level != 'public':
                        uuids_for_public.append(uuid)
                elif entity_type == 'Dataset':
                    if status != 'Published':
                        return Response(f"{dataset_uuid} has an ancestor dataset that has not been Published. Will not Publish. Ancestor dataset is: {uuid}", 400)

            if has_donor is False:
                return Response(f"{dataset_uuid}: no donor found for dataset, will not Publish")

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
            entity = entity_instance.get_entity_by_id(dataset_uuid)
            entity_dict: dict = vars(entity)
            data_type_edp: List[str] = \
                get_data_type_of_external_dataset_providers(app.config['UBKG_WEBSERVICE_URL'])
            entity_lab_processed_data_types: List[str] =\
                [i for i in entity_dict.get('data_types') if i in data_type_edp]
            has_entity_lab_processed_data_type: bool = len(entity_lab_processed_data_types) > 0


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

            if is_primary or has_entity_lab_processed_data_type:
                if dataset_contacts is None or dataset_contributors is None:
                    return jsonify({"error": f"{dataset_uuid} missing contacts or contributors. Must have at least one of each"}), 400
                dataset_contacts = dataset_contacts.replace("'", '"')
                dataset_contributors = dataset_contributors.replace("'", '"')
                if len(json.loads(dataset_contacts)) < 1 or len(json.loads(dataset_contributors)) < 1:
                    return jsonify({"error": f"{dataset_uuid} missing contacts or contributors. Must have at least one of each"}), 400
            ingest_helper = IngestFileHelper(app.config)

            # Save a .json file with the metadata information at the top level directory...
            if dataset_ingest_matadata_dict is not None:
                json_object = json.dumps(dataset_ingest_matadata_dict['metadata'], indent=4)
                json_object += '\n'
                ds_path = ingest_helper.dataset_directory_absolute_path(dataset_data_access_level,
                                                                        dataset_group_uuid, dataset_uuid, False)
                md_file = os.path.join(ds_path, "metadata.json")
                logger.info(f"publish_datastage; writing md_file: '{md_file}'; "
                            f"containing ingest_matadata.metadata: '{json_object}'")
                try:
                    with open(md_file, "w") as outfile:
                        outfile.write(json_object)
                except Exception as e:
                    logger.exception(f"Fatal error while writing md_file {md_file}; {str(e)}")
                    return jsonify({"error": f"{dataset_uuid} problem writing json file."}), 500

            data_access_level = dataset_data_access_level
            #if consortium access level convert to public dataset, if protected access leave it protected
            if dataset_data_access_level == 'consortium':
                #before moving check to see if there is currently a link for the dataset in the assets directory
                asset_dir = ingest_helper.dataset_asset_directory_absolute_path(dataset_uuid)
                asset_dir_exists = os.path.exists(asset_dir)
                ingest_helper.move_dataset_files_for_publishing(dataset_uuid, dataset_group_uuid, 'consortium')
                uuids_for_public.append(dataset_uuid)
                data_access_level = 'public'
                if asset_dir_exists:
                    ingest_helper.relink_to_public(dataset_uuid)

            acls_cmd = ingest_helper.set_dataset_permissions(dataset_uuid, dataset_group_uuid, data_access_level,
                                                             True, no_indexing_and_acls)


            auth_tokens = auth_helper.getAuthorizationTokens(request.headers)
            entity_instance = EntitySdk(token=auth_tokens, service_url=app.config['ENTITY_WEBSERVICE_URL'])
            doi_info = None
            # Generating DOI's for lab processed/derived data as well as IEC/pipeline/airflow processed/derived data).
            if is_primary or has_entity_lab_processed_data_type:
                # DOI gets generated here
                # Note: moved dataset title auto generation to entity-api - Zhou 9/29/2021
                datacite_doi_helper = DataCiteDoiHelper()


                entity = entity_instance.get_entity_by_id(dataset_uuid)
                entity_dict = vars(entity)

                try:
                    datacite_doi_helper.create_dataset_draft_doi(entity_dict, check_publication_status=False)
                except Exception as e:
                    logger.exception(f"Exception while creating a draft doi for {dataset_uuid}")
                    return jsonify({"error": f"Error occurred while trying to create a draft doi for {dataset_uuid}. Check logs."}), 500
                # This will make the draft DOI created above 'findable'....
                try:
                    doi_info = datacite_doi_helper.move_doi_state_from_draft_to_findable(entity_dict, auth_tokens)
                except Exception as e:
                    logger.exception(f"Exception while creating making doi findable and saving to entity for {dataset_uuid}")
                    return jsonify({"error": f"Error occurred while making doi findable and saving to entity for {dataset_uuid}. Check logs."}), 500
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
            out = entity_instance.clear_cache(dataset_uuid)

            # if all else worked set the list of ids to public that need to be public
            if len(uuids_for_public) > 0:
                id_list = string_helper.listToCommaSeparated(uuids_for_public, quoteChar="'")
                update_q = "match (e:Entity) where e.uuid in [" + id_list + "] set e.data_access_level = 'public'"
                logger.info(identifier + "\t" + dataset_uuid + "\tNEO4J-update-ancestors\t" + update_q)
                neo_session.run(update_q)
                for e_id in uuids_for_public:
                    out = entity_instance.clear_cache(e_id)

        if no_indexing_and_acls:
            r_val = {'acl_cmd': acls_cmd, 'donors_for_indexing': donors_to_reindex}
        else:
            r_val = {'acl_cmd': '', 'donors_for_indexing': []}

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
        return Response("Unexpected error while creating a dataset: " + str(e) + "  Check the logs", 500)


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
        json_object = json.dumps(dataset_ingest_metadata['metadata'], indent=4)
        json_object += '\n'
        ingest_helper = IngestFileHelper(app.config)
        # Save a .json file with the metadata information at the top level directory...
        ds_path = ingest_helper.dataset_directory_absolute_path(dataset_data_access_level,
                                                                dataset_group_uuid,
                                                                identifier,
                                                                dataset_published)
        md_file = os.path.join(ds_path, "metadata.json")
        logger.info(f"publish_datastage; writing md_file: '{md_file}'; "
                    f"containing ingest_matadata.metadata: '{json_object}'")
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


# Called by "data ingest pipeline" to update status of dataset...
@app.route('/datasets/status', methods = ['PUT'])
# @secured(groups="HuBMAP-read")
def update_ingest_status():
    if not request.json:
        abort(400, jsonify( { 'error': 'no data found cannot process update' } ))
    
    try:
        entity_api = EntitySdk(token=app_manager.groups_token_from_request_headers(request.headers),
                               service_url=commons_file_helper.removeTrailingSlashURL(
                                   app.config['ENTITY_WEBSERVICE_URL']))

        return app_manager.update_ingest_status_title_thumbnail(app.config, 
                                                                request.json, 
                                                                request.headers, 
                                                                entity_api,
                                                                file_upload_helper_instance)
    except HTTPException as hte:
        return Response(hte.get_description(), hte.get_status_code())
    except ValueError as ve:
        logger.error(str(ve))
        return jsonify({'error' : str(ve)}), 400
    except Exception as e:
        logger.error(e, exc_info=True)
        return Response("Unexpected error while saving dataset: " + str(e), 500)     


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
    try:
        put_url = commons_file_helper.ensureTrailingSlashURL(app.config['ENTITY_WEBSERVICE_URL']) + 'entities/' + uuid
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

        siblingid_list = Specimen.get_ingest_group_list(neo4j_driver_instance, uuid)
        return jsonify({'ingest_group_ids': siblingid_list}), 200 

    except AuthError as e:
        print(e)
        return Response('token is invalid', 401)
    except:
        msg = 'An error occurred: '
        for x in sys.exc_info():
            msg += str(x)
        abort(400, msg)
    # finally:
    #     if conn != None:
    #         if conn.get_driver().closed() == False:
    #             conn.close()



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


"""
Description
"""
@app.route('/datasets/data-status', methods=['GET'])
def dataset_data_status():
    redis_connection = redis.from_url(app.config['REDIS_URL'])
    try:
        cached_data = redis_connection.get("datasets_data_status_key")
        if cached_data:
            cached_data_json = json.loads(cached_data.decode('utf-8'))
            return jsonify(cached_data_json)
        else:
            raise Exception
    except Exception:
        logger.error("Failed to retrieve datasets data-status from cache. Retrieving new data")
        combined_results = update_datasets_datastatus()
        return jsonify(combined_results)


"""
Description
"""
@app.route('/uploads/data-status', methods=['GET'])
def upload_data_status():
    redis_connection = redis.from_url(app.config['REDIS_URL'])
    try:
        cached_data = redis_connection.get("uploads_data_status_key")
        if cached_data:
            cached_data_json = json.loads(cached_data.decode('utf-8'))
            return jsonify(cached_data_json)
        else:
            raise Exception
    except Exception:
        logger.error("Failed to retrieve uploads data-status from cache. Retrieving new data")
        results = update_uploads_datastatus()
        return jsonify(results)


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

    with urllib.request.urlopen(
            'https://raw.githubusercontent.com/hubmapconsortium/search-api/main/src/search-schema/data/definitions/enums/organ_types.yaml') as urlfile:
        organ_resource_file = yaml.load(urlfile, Loader=yaml.FullLoader)

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
                        f"Row Number: {rownum}. organ_type value must be a sample code listed in tissue sample type files (https://raw.githubusercontent.com/hubmapconsortium/search-api/main/src/search-schema/data/definitions/enums/organ_types.yaml)")

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

####################################################################################################
## Internal Functions
####################################################################################################

# Determines if a dataset is Primary. If the list returned from the neo4j query is empty, the dataset is not primary
def dataset_is_primary(dataset_uuid):
    with neo4j_driver_instance.session() as neo_session:
        q = (f"MATCH (ds:Dataset {{uuid: '{dataset_uuid}'}})<-[:ACTIVITY_OUTPUT]-(a:Activity) WHERE NOT toLower(a.creation_action) ENDS WITH 'process' RETURN ds.uuid")
        result = neo_session.run(q).data()
        if len(result) == 0:
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
    primary_assays_url = app.config['UBKG_WEBSERVICE_URL'] + 'assaytype?application_context=HUBMAP&primary=true'
    alt_assays_url = app.config['UBKG_WEBSERVICE_URL'] + 'assaytype?application_context=HUBMAP&primary=false'
    rui_organs_url = app.config['UBKG_WEBSERVICE_URL'] + 'organs?application_context=HUBMAP'
    primary_assay_types_list = requests.get(primary_assays_url).json().get("result")
    alt_assay_types_list = requests.get(alt_assays_url).json().get("result")
    rui_organs_list = requests.get(rui_organs_url).json()
    assay_types_dict = {item["name"].strip(): item for item in primary_assay_types_list + alt_assay_types_list}
    organ_types_url = app.config['UBKG_WEBSERVICE_URL'] + 'organs/by-code?application_context=HUBMAP'
    organ_types_dict = requests.get(organ_types_url).json()
    all_datasets_query = (
        "MATCH (ds:Dataset)<-[:ACTIVITY_OUTPUT]-(:Activity)<-[:ACTIVITY_INPUT]-(ancestor) "
        "RETURN "
        "ds.uuid AS uuid, ds.group_name AS group_name, ds.data_types AS data_types, "
        "ds.hubmap_id AS hubmap_id, ds.lab_dataset_id AS provider_experiment_id, ds.status AS status, "
        "ds.status_history AS status_history, "
        "ds.last_modified_timestamp AS last_touch, ds.data_access_level AS data_access_level, "
        "COALESCE(ds.contributors IS NOT NULL) AS has_contributors, "
        "COALESCE(ds.contacts IS NOT NULL) AS has_contacts, "
        "ancestor.entity_type AS ancestor_entity_type"
    )

    organ_query = (
        "MATCH (ds:Dataset)<-[*]-(o:Sample {sample_category: 'organ'}) "
        "WHERE (ds)<-[:ACTIVITY_OUTPUT]-(:Activity) "
        "RETURN DISTINCT "
        "ds.uuid AS uuid, o.organ AS organ, o.hubmap_id as organ_hubmap_id, o.uuid as organ_uuid"
    )

    donor_query = (
        "MATCH (ds:Dataset)<-[*]-(dn:Donor) "
        "WHERE (ds)<-[:ACTIVITY_OUTPUT]-(:Activity) "
        "RETURN DISTINCT "
        "ds.uuid AS uuid, "
        "COLLECT(DISTINCT dn.hubmap_id) AS donor_hubmap_id, COLLECT(DISTINCT dn.submission_id) AS donor_submission_id, "
        "COLLECT(DISTINCT dn.lab_donor_id) AS donor_lab_id, COALESCE(dn.metadata IS NOT NULL) AS has_metadata"
    )

    descendant_datasets_query = (
        "MATCH (dds:Dataset)<-[*]-(ds:Dataset)<-[:ACTIVITY_OUTPUT]-(:Activity)<-[:ACTIVITY_INPUT]-(:Sample) "
        "RETURN DISTINCT "
        "ds.uuid AS uuid, COLLECT(DISTINCT dds.hubmap_id) AS descendant_datasets"
    )

    upload_query = (
        "MATCH (u:Upload)<-[:IN_UPLOAD]-(ds) "
        "RETURN DISTINCT "
        "ds.uuid AS uuid, COLLECT(DISTINCT u.hubmap_id) AS upload"
    )

    has_rui_query = (
        "MATCH (ds:Dataset) "
        "WHERE (ds)<-[:ACTIVITY_OUTPUT]-(:Activity) "
        "WITH ds, [(ds)<-[*]-(s:Sample) | s.rui_location] AS rui_locations "
        "RETURN "
        "ds.uuid AS uuid, any(rui_location IN rui_locations WHERE rui_location IS NOT NULL) AS has_rui_info"
    )

    displayed_fields = [
        "hubmap_id", "group_name", "status", "status_history", "organ", "provider_experiment_id", "last_touch",
        "has_contacts", "has_contributors", "data_types", "donor_hubmap_id", "donor_submission_id", "donor_lab_id",
        "has_metadata", "descendant_datasets", "upload", "has_rui_info", "globus_url", "has_data", "organ_hubmap_id"
    ]

    queries = [all_datasets_query, organ_query, donor_query, descendant_datasets_query,
               upload_query, has_rui_query]
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
    descendant_datasets_result = results[3]
    upload_result = results[4]
    has_rui_result = results[5]

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
            output_dict[dataset['uuid']]['has_metadata'] = dataset['has_metadata']
    for dataset in descendant_datasets_result:
        if output_dict.get(dataset['uuid']):
            output_dict[dataset['uuid']]['descendant_datasets'] = dataset['descendant_datasets']
    for dataset in upload_result:
        if output_dict.get(dataset['uuid']):
            output_dict[dataset['uuid']]['upload'] = dataset['upload']
    for dataset in has_rui_result:
        if output_dict.get(dataset['uuid']):
            output_dict[dataset['uuid']]['has_rui_info'] = dataset['has_rui_info']

    combined_results = []
    for uuid in output_dict:
        combined_results.append(output_dict[uuid])

    for dataset in combined_results:
        globus_url = get_globus_url(dataset.get('data_access_level'), dataset.get('group_name'), dataset.get('uuid'))
        dataset['globus_url'] = globus_url
        dataset['last_touch'] = str(datetime.datetime.utcfromtimestamp(dataset['last_touch'] / 1000))
        if dataset.get('ancestor_entity_type').lower() != "dataset":
            dataset['is_primary'] = "true"
        else:
            dataset['is_primary'] = "false"
        has_data = files_exist(dataset.get('uuid'), dataset.get('data_access_level'), dataset.get('group_name'))
        dataset['has_data'] = has_data

        for prop in dataset:
            if isinstance(dataset[prop], list):
                dataset[prop] = ", ".join(dataset[prop])
            if isinstance(dataset[prop], (bool, int)):
                dataset[prop] = str(dataset[prop])
            if isinstance(dataset[prop], str) and \
                    len(dataset[prop]) >= 2 and \
                    dataset[prop][0] == "[" and dataset[prop][-1] == "]":
                dataset[prop] = dataset[prop].replace("'", '"')
                dataset[prop] = json.loads(dataset[prop])
                if len(dataset[prop]) > 0:
                    dataset[prop] = dataset[prop][0]
                else:
                    dataset[prop] = " "
            if dataset[prop] is None:
                dataset[prop] = " "
        if dataset.get('data_types') and dataset.get('data_types') in assay_types_dict:
            dataset['data_types'] = assay_types_dict[dataset['data_types']]['description'].strip()
        for field in displayed_fields:
            if dataset.get(field) is None:
                dataset[field] = " "
        if dataset.get('organ') and rui_organs_list:
            rui_codes = [organ['rui_code'] for organ in rui_organs_list]
            if dataset['organ'].upper() not in rui_codes:
                dataset['has_rui_info'] = "not-applicable"
        if dataset.get('organ') and dataset.get('organ') in organ_types_dict:
            dataset['organ'] = organ_types_dict[dataset['organ']]

    try:
        combined_results_string = json.dumps(combined_results)
    except json.JSONDecodeError as e:
        bad_request_error(e)
    redis_connection = redis.from_url(app.config['REDIS_URL'])
    cache_key = "datasets_data_status_key"
    redis_connection.set(cache_key, combined_results_string)
    return combined_results

def update_uploads_datastatus():
    """
    This will cache the 'all_uploads_query' results from Neo4J in the redis
    entry 'datasets_data_status_key' after serializing it.
    It will then return the un-serialized json.

    Returns json
    -------

    """
    all_uploads_query = (
        "MATCH (up:Upload) "
        "OPTIONAL MATCH (up)<-[:IN_UPLOAD]-(ds:Dataset) "
        "RETURN "
        "up.uuid AS uuid, up.group_name AS group_name, up.hubmap_id AS hubmap_id, "
        "up.status AS status, up.status_history AS status_history, "
        "up.title AS title, "
        "COLLECT(DISTINCT ds.uuid) AS datasets"
    )

    displayed_fields = [
        "uuid", "group_name", "hubmap_id", "status", "status_history", "title", "datasets"
    ]

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
                if upload[prop] and upload[prop][0] == "[" and upload[prop][-1] == "]":
                    upload[prop] = upload[prop].replace("'", '"')
                    upload[prop] = json.loads(upload[prop])
                    upload[prop] = upload[prop][0]
                if upload[prop] is None:
                    upload[prop] = " "
            for field in displayed_fields:
                if upload.get(field) is None:
                    upload[field] = " "
    try:
        results_string = json.dumps(results)
    except json.JSONDecodeError as e:
        bad_request_error(e)
    redis_connection = redis.from_url(app.config['REDIS_URL'])
    cache_key = "uploads_data_status_key"
    redis_connection.set(cache_key, results_string)
    return results


def files_exist(uuid, data_access_level, group_name):
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
        return True
    else:
        return False

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

update_datasets_datastatus()
update_uploads_datastatus()

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
