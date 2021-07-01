import os
import sys
import time
import hashlib
import logging
import requests
import argparse
from pathlib import Path
from shutil import copy2 # Used by thumbnail.jpg
from flask import Flask, g, jsonify, abort, request, session, redirect, json, Response
from flask_cors import CORS
from globus_sdk import AccessTokenAuthorizer, AuthClient, ConfidentialAppAuthClient

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
from dataset import Dataset
from specimen import Specimen
from ingest_file_helper import IngestFileHelper
from file_upload_helper import UploadFileHelper


# Set logging fromat and level (default is warning)
# All the API logging is forwarded to the uWSGI server and gets written into the log file `uwsgo-entity-api.log`
# Log rotation is handled via logrotate on the host system with a configuration file
# Do NOT handle log file and rotation via the Python logging to avoid issues with multi-worker processes
logging.basicConfig(format='[%(asctime)s] %(levelname)s in %(module)s: %(message)s', level=logging.DEBUG, datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger(__name__)

# Specify the absolute path of the instance folder and use the config file relative to the instance path
app = Flask(__name__, instance_path=os.path.join(os.path.abspath(os.path.dirname(__file__)), 'instance'), instance_relative_config=True)
app.config.from_pyfile('app.cfg')

# Enable/disable CORS from configuration based on docker or non-docker deployment
if app.config['ENABLE_CORS']:
    CORS(app)


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
# This neo4j_driver_instance will be used for application-specifc neo4j queries
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
## Default and Status Routes
####################################################################################################

@app.route('/', methods = ['GET'])
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
@app.route('/status', methods = ['GET'])
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
## Endpoints for UI Login and Logout
####################################################################################################

# Redirect users from react app login page to Globus auth login widget then redirect back
@app.route('/login')
def login():
    #redirect_uri = url_for('login', _external=True)
    redirect_uri = app.config['FLASK_APP_BASE_URI'] + 'login'

    confidential_app_auth_client = ConfidentialAppAuthClient(app.config['APP_CLIENT_ID'], app.config['APP_CLIENT_SECRET'])
    confidential_app_auth_client.oauth2_start_flow(redirect_uri, refresh_tokens=True)

    # If there's no "code" query string parameter, we're in this route
    # starting a Globus Auth login flow.
    # Redirect out to Globus Auth
    if 'code' not in request.args:                                        
        auth_uri = confidential_app_auth_client.oauth2_get_authorize_url(additional_params={"scope": "openid profile email urn:globus:auth:scope:transfer.api.globus.org:all urn:globus:auth:scope:auth.globus.org:view_identities urn:globus:auth:scope:nexus.api.globus.org:groups" })
        return redirect(auth_uri)
    # If we do have a "code" param, we're coming back from Globus Auth
    # and can start the process of exchanging an auth code for a token.
    else:
        auth_code = request.args.get('code')

        token_response = confidential_app_auth_client.oauth2_exchange_code_for_tokens(auth_code)
        
        # Get all Bearer tokens
        auth_token = token_response.by_resource_server['auth.globus.org']['access_token']
        nexus_token = token_response.by_resource_server['nexus.api.globus.org']['access_token']
        transfer_token = token_response.by_resource_server['transfer.api.globus.org']['access_token']
        # Also get the user info (sub, email, name, preferred_username) using the AuthClient with the auth token
        user_info = get_user_info(auth_token)
        
        info = {
            'name': user_info['name'],
            'email': user_info['email'],
            'globus_id': user_info['sub'],
            'auth_token': auth_token,
            'nexus_token': nexus_token,
            'transfer_token': transfer_token,
        }

        # Turns json dict into a str
        json_str = json.dumps(info)
        #print(json_str)
        
        # Store the resulting tokens in server session
        session.update(
            tokens=token_response.by_resource_server
        )
      
        # Finally redirect back to the client
        return redirect(app.config['GLOBUS_CLIENT_APP_URI'] + '?info=' + str(json_str))

   
@app.route('/logout')
def logout():
    """
    - Revoke the tokens with Globus Auth.
    - Destroy the session state.
    - Redirect the user to the Globus Auth logout page.
    """
    confidential_app_auth_client = ConfidentialAppAuthClient(app.config['APP_CLIENT_ID'], app.config['APP_CLIENT_SECRET'])

    # Revoke the tokens with Globus Auth
    if 'tokens' in session:    
        for token in (token_info['access_token']
            for token_info in session['tokens'].values()):
                confidential_app_auth_client.oauth2_revoke_token(token)

    # Destroy the session state
    session.clear()

    # build the logout URI with query params
    # there is no tool to help build this (yet!)
    globus_logout_url = (
        'https://auth.globus.org/v2/web/logout' +
        '?client={}'.format(app.config['APP_CLIENT_ID']) +
        '&redirect_uri={}'.format(app.config['GLOBUS_CLIENT_APP_URI']) +
        '&redirect_name={}'.format(app.config['GLOBUS_CLIENT_APP_NAME']))

    # Redirect the user to the Globus Auth logout page
    return redirect(globus_logout_url)


####################################################################################################
## Register error handlers
####################################################################################################

# Error handler for 400 Bad Request with custom error message
@app.errorhandler(400)
def http_bad_request(e):
    return jsonify(error=str(e)), 400

# Error handler for 500 Internal Server Error with custom error message
@app.errorhandler(500)
def http_internal_server_error(e):
    return jsonify(error=str(e)), 500


####################################################################################################
## Ingest API Endpoints
####################################################################################################


"""
File upload handling for Donor and Sample

Returns
-------
json
    A JSON containing the temp file id
"""
@app.route('/file-upload', methods=['POST'])
def upload_file():
    # Check if the post request has the file part
    if 'file' not in request.files:
        bad_request_error('No file part')

    file = request.files['file']

    if file.filename == '':
        bad_request_error('No selected file')

    try:
        temp_id = file_upload_helper_instance.save_temp_file(file)
        rspn_data = {
            "temp_file_id": temp_id
        }

        return jsonify(rspn_data), 201
    except Exception as e:
        # Log the full stack trace, prepend a line with our message
        msg = "Failed to upload files"
        logger.exception(msg)
        internal_server_error(msg)

"""
File commit triggered by entity-api trigger method for Donor/Sample/Dataset

Donor: image files
Sample: image files and metadata files
Dataset: only the one thumbnail file

This call also creates the symbolic from the file uuid dir under uploads
to the assets dir so the uploaded files can be exposed via gateway's file assets service

Returns
-------
json
    A JSON containing the file uuid info
"""
@app.route('/file-commit', methods=['POST'])
def commit_file():
    # Always expect a json body
    require_json(request)

    # Parse incoming json string into json data(python dict object)
    json_data_dict = request.get_json()

    temp_file_id = json_data_dict['temp_file_id']
    entity_uuid = json_data_dict['entity_uuid']
    user_token = json_data_dict['user_token']

    file_uuid_info = file_upload_helper_instance.commit_file(temp_file_id, entity_uuid, user_token)

    # Link the uploaded file uuid dir to assets
    # /hive/hubmap/hm_uploads/<file_uuid> (for PROD)
    uploaded_dir = os.path.join(str(app.config['FILE_UPLOAD_DIR']), file_uuid_info['file_uuid'])
    # /hive/hubmap/assets/<file_uuid> (for PROD)
    assets_symbolic_dir = os.path.join(str(app.config['HUBMAP_WEBSERVICE_FILEPATH']), file_uuid_info['file_uuid'])

    # Create the file_uuid directory under assets dir
    # and a symbolic link to the uploaded dir
    try:
        # IngestFileHelper.make_directory() is a static method
        IngestFileHelper.make_directory(uploaded_dir, assets_symbolic_dir)
    except Exception as e:
        logger.exception(f"Failed to create the symbolic link from {uploaded_dir} to {assets_symbolic_dir}")

    # Send back the updated file_uuid_info
    return jsonify(file_uuid_info)

"""
File removal triggered by entity-api trigger method for Donor/Sample/Dataset
during entity update

Donor: image files
Sample: image files and metadata files
Dataset: only the one thumbnail file

Returns
-------
json
    A JSON list containing the updated files info
    It's an empty list for Dataset since there's only one thumbnail file
"""
@app.route('/file-remove', methods=['POST'])
def remove_file():
    # Always expect a json body
    require_json(request)

    # Parse incoming json string into json data(python dict object)
    json_data_dict = request.get_json()

    entity_uuid = json_data_dict['entity_uuid']
    file_uuids = json_data_dict['file_uuids']
    files_info_list = json_data_dict['files_info_list']

    # `upload_dir` is already normalized with trailing slash
    entity_upload_dir = file_upload_helper_instance.upload_dir + entity_uuid + os.sep
    
    # Remove the physical files from the file system
    for file_uuid in file_uuids:
        # Get back the updated files_info_list
        files_info_list = file_upload_helper_instance.remove_file(entity_upload_dir, file_uuid, files_info_list)
    
    # Send back the updated files_info_list
    return jsonify(files_info_list)


@app.route('/datasets/<ds_uuid>/file-system-abs-path', methods = ['GET'])
def get_file_system_absolute_path(ds_uuid):
    try:
        dset = __get_entity(ds_uuid, auth_header = request.headers.get("AUTHORIZATION"))
        ent_type = __get_dict_prop(dset, 'entity_type')
        group_uuid = __get_dict_prop(dset, 'group_uuid')
        is_phi = __get_dict_prop(dset, 'contains_human_genetic_sequences')
        if ent_type is None or not ent_type.lower().strip() == 'dataset':
            return Response(f"Entity with uuid:{ds_uuid} is not a Dataset", 400)
        if group_uuid is None:
            return Response(f"Error: Unable to find group uuid on dataset {ds_uuid}", 400)
        if is_phi is None:
            return Response(f"Error: contains_human_genetic_sequences is not set on dataset {ds_uuid}", 400)
        ingest_helper = IngestFileHelper(app.config)
        path = ingest_helper.get_dataset_directory_absolute_path(dset, group_uuid, ds_uuid)
        return jsonify ({'path': path}), 200    
    except HTTPException as hte:
        return Response(f"Error while getting file-system-abs-path for {ds_uuid}: " + hte.get_description(), hte.get_status_code())
    except Exception as e:
        logger.error(e, exc_info=True)
        return Response(f"Unexpected error while retrieving entity {ds_uuid}: " + str(e), 500)

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
Input JSON example:
{
"source_dataset_uuid":"e517ce652d3c4f22ace7f21fd64208ac",
"derived_dataset_name":"Test derived dataset 1",
"derived_dataset_types":["QX11", "xxx"]
}

Output JSON example:
{
    "derived_dataset_uuid": "2ecc257c3fd1875be08a12ff654f1264",
    "group_display_name": "IEC Testing Group",
    "group_uuid": "5bd084c8-edc2-11e8-802f-0e368f3075e8"
}
"""
@app.route('/datasets/derived', methods=['POST'])
#@secured(groups="HuBMAP-read")
def create_derived_dataset():
    if not request.is_json:
        abort(400, jsonify( { 'error': 'This request requires json in the body' } ))
    
    json_data = request.get_json()
    logger.info("++++++++++Calling /datasets/derived")
    logger.info("++++++++++Request:" + json.dumps(json_data))

    if 'source_dataset_uuid' not in json_data:
        abort(400, jsonify( { 'error': "The 'source_dataset_uuid' property is required." } ))
    
    if 'derived_dataset_name' not in json_data:
        abort(400, jsonify( { 'error': "The 'derived_dataset_name' property is required." } ))

    if 'derived_dataset_types' not in json_data:
        abort(400, jsonify( { 'error': "The 'derived_dataset_types' property is required." } ))

    # Ensure the data types is an array
    if not isinstance(json_data['derived_dataset_types'], list):
        abort(400, jsonify( { 'error': "The 'derived_dataset_types' values must be an json array" } ))

    try:
        dataset = Dataset(app.config)

        # Note: the user who can create the derived dataset doesn't have to be the same person who created the source dataset
        # Get the nexus token from request headers
        nexus_token = None
        try:
            nexus_token = AuthHelper.parseAuthorizationTokens(request.headers)
        except:
            raise ValueError("Unable to parse globus token from request header")

        new_record = dataset.create_derived_datastage(nexus_token, json_data)
        return jsonify( new_record ), 201
    except HTTPException as hte:
        return Response(hte.get_description(), hte.get_status_code())
    except Exception as e:
        logger.error(e, exc_info=True)
        return Response("Unexpected error while creating derived dataset: " + str(e), 500)        


@app.route('/datasets', methods=['POST'])
def create_datastage():
    if not request.is_json:
        return Response("json request required", 400)    
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
        post_url = commons_file_helper.ensureTrailingSlashURL(app.config['ENTITY_WEBSERVICE_URL']) + '/entities/dataset'
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


@app.route('/datasets/<identifier>/publish', methods = ['PUT'])
@secured(groups="HuBMAP-read")
def publish_datastage(identifier):
    try:
        auth_helper = AuthHelper.configured_instance(app.config['APP_CLIENT_ID'], app.config['APP_CLIENT_SECRET'])
        user_info = auth_helper.getUserInfoUsingRequest(request, getGroups = True)
        if user_info is None:
            return Response("Unable to obtain user information for auth token", 401)
        if isinstance(user_info, Response):
            return user_info
        
        if not 'hmgroupids' in user_info:
            return Response("User has no valid group information to authorize publication.", 403)
        if not data_admin_group_uuid in user_info['hmgroupids']:
            return Response("User must be a member of the HuBMAP Data Admin group to publish data.", 403)


        if identifier == None or len(identifier) == 0:
            abort(400, jsonify( { 'error': 'identifier parameter is required to publish a dataset' } ))


        r = requests.get(app.config['UUID_WEBSERVICE_URL'] + "/" + identifier, headers={'Authorization': request.headers["AUTHORIZATION"]})
        if r.ok == False:
            raise ValueError("Cannot find specimen with identifier: " + identifier)
        dataset_uuid = json.loads(r.text)['hm_uuid']

        suspend_indexing_and_acls = string_helper.isYes(request.args.get('suspend-indexing-and-acls'))
        no_indexing_and_acls = False
        if suspend_indexing_and_acls: no_indexing_and_acls = True 

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
            q = f"MATCH (dataset:Dataset {{uuid: '{dataset_uuid}'}})<-[:ACTIVITY_OUTPUT]-(e1)<-[:ACTIVITY_INPUT|ACTIVITY_OUTPUT*]-(all_ancestors:Entity) RETURN distinct all_ancestors.uuid as uuid, all_ancestors.entity_type as entity_type, all_ancestors.data_types as data_types, all_ancestors.data_access_level as data_access_level, all_ancestors.status as status"
            rval = neo_session.run(q).data()
            uuids_for_public = []
            donor_uuid = None
            for node in rval:
                uuid = node['uuid']
                entity_type = node['entity_type']
                data_access_level = node['data_access_level']
                status = node['status']
                if entity_type == 'Sample':                        
                    #if this sample is already set to public, no need to set again
                    if not data_access_level == 'public':
                        uuids_for_public.append(uuid)
                elif entity_type == 'Donor':
                    donor_uuid = uuid
                    donors_to_reindex.append(uuid)
                    if not data_access_level == 'public':
                        uuids_for_public.append(uuid)
                elif entity_type == 'Dataset':
                    if not status == 'Published':
                        return Response(f"{dataset_uuid} has an ancestor dataset that has not been Published. Will not Publish. Ancestor dataset is: {uuid}", 400)
            
            if donor_uuid is None:
                return Response(f"{dataset_uuid}: no donor found for dataset, will not Publish")
            
            #get info for the dataset to be published
            q = f"MATCH (e:Dataset {{uuid: '{dataset_uuid}'}}) RETURN e.uuid as uuid, e.entity_type as entitytype, e.status as status, e.data_access_level as data_access_level, e.group_uuid as group_uuid"
            rval = neo_session.run(q).data()
            dataset_status = rval[0]['status']
            dataset_entitytype = rval[0]['entitytype']
            dataset_data_access_level = rval[0]['data_access_level']
            dataset_group_uuid = rval[0]['group_uuid']
            if dataset_entitytype != 'Dataset':
                return Response(f"{dataset_uuid} is not a dataset will not Publish, entity type is {dataset_entitytype}", 400)
            if not dataset_status == 'QA':
                return Response(f"{dataset_uuid} is not in QA state will not Publish, status is {dataset_status}", 400)
            
            ingest_helper = IngestFileHelper(app.config)
            
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
            
            acls_cmd = ingest_helper.set_dataset_permissions(dataset_uuid, dataset_group_uuid, data_access_level, True, no_indexing_and_acls)
            
            #set dataset status to published and set the last modified user info and user who published
            update_q = "match (e:Entity {uuid:'" + dataset_uuid + "'}) set e.status = 'Published', e.last_modified_user_sub = '" + user_info['sub'] + "', e.last_modified_user_email = '" + user_info['email'] + "', e.last_modified_user_displayname = '" + user_info['name'] + "', e.last_modified_timestamp = TIMESTAMP(), e.published_timestamp = TIMESTAMP(), e.published_user_email = '" + user_info['email'] + "', e.published_user_sub = '" + user_info['sub'] + "', e.published_user_displayname = '" + user_info['name'] + "'"
            logger.info(dataset_uuid + "\t" + dataset_uuid + "\tNEO4J-update-base-dataset\t" + update_q)
            neo_session.run(update_q)
    
            #if all else worked set the list of ids to public that need to be public
            if len(uuids_for_public) > 0:
                id_list = string_helper.listToCommaSeparated(uuids_for_public, quoteChar = "'")
                update_q = "match (e:Entity) where e.uuid in [" + id_list + "] set e.data_access_level = 'public'"
                logger.info(identifier + "\t" + dataset_uuid + "\tNEO4J-update-ancestors\t" + update_q)
                neo_session.run(update_q)
                    
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

    
    return Response("This method is not implemented. Use manual publication script", 501)

             
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
    
@app.route('/datasets/status', methods = ['PUT'])
# @secured(groups="HuBMAP-read")
def update_ingest_status():
    if not request.json:
        abort(400, jsonify( { 'error': 'no data found cannot process update' } ))
    
    try:
        dataset = Dataset(app.config)
        ds_request = request.json
        logger.info("++++++++++Calling /datasets/status")
        logger.info("++++++++++Request:" + json.dumps(ds_request))
        # expecting something like this:
        #{'dataset_id' : '287d61b60b806fdf54916e3b7795ad5a', 'status': '<', 'message': 'the process ran', 'metadata': [maybe some metadata stuff], 'thumbnail_image_abs_path': 'full path to the image'}
        updated_ds = dataset.get_dataset_ingest_update_record(ds_request)

        # For thumbnail image handling if ingest-pipeline finds the file
        # and sends the absolute file path back
        if 'thumbnail_file_abs_path' in updated_ds:
            thumbnail_file_abs_path = updated_ds['thumbnail_file_abs_path']

            # Generate a temp file id and copy the source file to the temp upload dir
            temp_file_id = file_upload_helper_instance.get_temp_file_id()

            # Create the temp file dir under the temp uploads for the thumbnail
            # /hive/hubmap/hm_uploads_tmp/<temp_file_id> (for PROD)
            temp_file_dir = os.path.join(str(app.config['FILE_UPLOAD_TEMP_DIR']), temp_file_id)
            
            try:
                IngestFileHelper.make_directory(temp_file_dir)
            except Exception as e:
                logger.exception(f"Failed to create the thumbnail temp upload dir {temp_file_dir} for thumbnail file attched to Dataset {result_json['uuid']}")

            # Then copy the source thumbnail file to the temp file dir
            # shutil.copy2 is identical to shutil.copy() method
            # but it also try to preserves the file’s metadata
            copy2(thumbnail_image_abs_path, temp_file_dir)

            # Now add the thumbnail file by making a call to entity-api
            # And the entity-api will execute the trigger method defined
            # for the property 'thumbnail_file_to_add' to commit this
            # file via ingest-api's /file-commit endpoint, which treats
            # the tmp file as uploaded and moves it to the generated file_uuid
            # dir under the upload dir: /hive/hubmap/hm_uploads/<file_uuid> (for PROD)
            # and also creates the symbolic link to the assets
            updated_ds['thumbnail_file_to_add'] = {
                'temp_file_id': temp_file_id
            }

            # Remove the 'thumbnail_file_abs_path' property 
            # since it's not defined in entity-api schema
            updated_ds.pop('thumbnail_file_abs_path')

        # Update the dataset via entity-api via a PUT call
        headers = {'Authorization': request.headers["AUTHORIZATION"], 'Content-Type': 'application/json', 'X-Hubmap-Application':'ingest-api'}
        entity_uuid = ds_request['dataset_id']
        update_url = commons_file_helper.ensureTrailingSlashURL(app.config['ENTITY_WEBSERVICE_URL']) + 'entities/' + entity_uuid
        
        response = requests.put(update_url, json = updated_ds, headers = headers, verify = False)
        if response.status_code != 200:
            err_msg = f"Error while calling {update_url} status code:{response.status_code}  message:{response.text}"
            logger.error(err_msg)
            logger.error("Sent: " + json.dumps(updated_ds))
            return Response(response.text, response.status_code)

        result_json = response.json()

        return jsonify( { 'result' : result_json } ), response.status_code
    
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

        pipeline_url = commons_file_helper.ensureTrailingSlashURL(app.config['INGEST_PIPELINE_URL']) + 'request_ingest'
        r = requests.post(pipeline_url, json={"submission_id" : "{uuid}".format(uuid=uuid),
                                     "process" : app.config['INGEST_PIPELINE_DEFAULT_PROCESS'],
                                              "full_path": ingest_helper.get_dataset_directory_absolute_path(dataset_request, group_uuid, uuid),
                                     "provider": "{group_name}".format(group_name=AuthHelper.getGroupDisplayName(group_uuid))}, 
                                          headers={'Content-Type':'application/json', 'Authorization': 'Bearer {token}'.format(token=AuthHelper.instance().getProcessSecret() )}, verify=False)
        if r.ok == True:
            """expect data like this:
            {"ingest_id": "abc123", "run_id": "run_657-xyz", "overall_file_count": "99", "top_folder_contents": "["IMS", "processed_microscopy","raw_microscopy","VAN0001-RK-1-spatial_meta.txt"]"}
            """
            data = json.loads(r.content.decode())
            submission_data = data['response']
            dataset_request[HubmapConst.DATASET_INGEST_ID_ATTRIBUTE] = submission_data['ingest_id']
            dataset_request[HubmapConst.DATASET_RUN_ID] = submission_data['run_id']
        else:
            logger.error('Failed call to AirFlow HTTP Response: ' + str(r.status_code) + ' msg: ' + str(r.text)) 
            return Response("Ingest pipeline failed: " + str(r.text), r.status_code)
        
        dataset_request['status'] = 'Processing'
        put_url = commons_file_helper.ensureTrailingSlashURL(app.config['ENTITY_WEBSERVICE_URL']) + 'entities/' + uuid
        response = requests.put(put_url, json = dataset_request, headers = {'Authorization': 'Bearer ' + token, 'X-Hubmap-Application':'ingest-api' }, verify = False)
        if not response.status_code == 200:
            logger.error(f"call to {put_url} failed with code:{response.status_code} message:" + response.text)
            return Response(response.text, response.status_code)
        updated_dataset = response.json()
        return jsonify(updated_dataset)
    except HTTPException as hte:
        return Response(hte.get_description(), hte.get_status_code())
    except Exception as e:
        logger.error(e, exc_info=True)
        return Response("Unexpected error while creating a dataset: " + str(e) + "  Check the logs", 500)        
 

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
        elif 'nexus_token' in auth_tokens:
            token = auth_tokens['nexus_token']
        else:
            return(Response("Valid nexus auth token required", 401))
        
        requested_group_uuid = None
        if 'group_uuid' in upload_request:
            requested_group_uuid = upload_request['group_uuid']
        
        ingest_helper = IngestFileHelper(app.config)
        requested_group_uuid = auth_helper.get_write_group_uuid(token, requested_group_uuid)
        upload_request['group_uuid'] = requested_group_uuid            
        post_url = commons_file_helper.ensureTrailingSlashURL(app.config['ENTITY_WEBSERVICE_URL']) + '/entities/upload'
        response = requests.post(post_url, json = upload_request, headers = {'Authorization': 'Bearer ' + token, 'X-Hubmap-Application':'ingest-api' }, verify = False)
        if response.status_code != 200:
            return Response(response.text, response.status_code)
        new_upload = response.json()
        ingest_helper.create_upload_directory(new_upload, requested_group_uuid, new_upload['uuid'])
        return jsonify(new_upload)
    except HTTPException as hte:
        return Response(hte.get_description(), hte.get_status_code())
    except Exception as e:
        logger.error(e, exc_info=True)
        return Response("Unexpected error while creating a upload: " + str(e) + "  Check the logs", 500)        

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
    auth_headers = {'Authorization': request.headers["AUTHORIZATION"], 'X-Hubmap-Application':'ingest-api'} 

    #update the Upload with any changes from the request
    #and change the status to "Processing", the validate
    #pipeline will update the status when finished
    upload_changes['status'] = 'Processing'
    update_url = commons_file_helper.ensureTrailingSlashURL(app.config['ENTITY_WEBSERVICE_URL']) + 'entities/' + upload_uuid
    resp = requests.put(update_url, headers=auth_headers)
    if resp.status_code >= 300:
        return Response(resp.text, resp.status_code)
    
    #call the AirFlow validation workflow
    validate_url = commons_file_helper.ensureTrailingSlashURL(app.config['INGEST_PIPELINE_URL']) + 'uploads/' + upload_uuid + "/validate"
    resp = requests.put(validate_url, headers=auth_headers)
    if resp.status_code >= 300:
        return Response(resp.text, resp.status_code)
    

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
#                      "has_publish_priv": false
#                  }

@app.route('/entities/<hmuuid>/allowable-edit-states', methods = ['GET'])
@secured(groups="HuBMAP-read")
def allowable_edit_states(hmuuid):
    #if no uuid provided send back a 400
    if hmuuid == None or len(hmuuid) == 0:
        abort(400, jsonify( { 'error': 'hmuuid (HuBMAP UUID) parameter is required.' } ))

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
            r_val = {"has_write_priv":False, "has_submit_priv":False, "has_publish_priv":False }
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
                    if entity_type == 'dataset' or entity_type == 'upload':
                        if isBlank(status):
                            msg = f"ERROR: unable to obtain status field from db for {entity_type} with uuid:{hmuuid} during a call to allowable-edit-states"
                            logger.error(msg)
                            return Response(msg, 500)
                        status = status.lower().strip()
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


####################################################################################################
## Internal Functions
####################################################################################################

"""
Always expect a json body from user request

request : Flask request object
    The Flask request passed from the API endpoint
"""
def require_json(request):
    if not request.is_json:
        bad_request_error("A json body and appropriate Content-Type header are required")

"""
Throws error for 400 Bad Reqeust with message

Parameters
----------
err_msg : str
    The custom error message to return to end users
"""
def bad_request_error(err_msg):
    abort(400, description = err_msg)

"""
Throws error for 500 Internal Server Error with message
Parameters
----------
err_msg : str
    The custom error message to return to end users
"""
def internal_server_error(err_msg):
    abort(500, description = err_msg)
    

def get_user_info(token):
    auth_client = AuthClient(authorizer=AccessTokenAuthorizer(token))
    return auth_client.oauth2_userinfo()

def __get_dict_prop(dic, prop_name):
    if not prop_name in dic: return None
    val = dic[prop_name]
    if isinstance(val, str) and val.strip() == '': return None
    return val

def __get_entity(entity_uuid, auth_header = None):
    if auth_header is None:
        headers = None
    else:
        headers = {'Authorization': auth_header, 'Accept': 'application/json', 'Content-Type': 'application/json'}
    get_url = commons_file_helper.ensureTrailingSlashURL(app.config['ENTITY_WEBSERVICE_URL']) + 'entities/' + entity_uuid

    response = requests.get(get_url, headers = headers, verify = False)
    if response.status_code != 200:
        err_msg = f"Error while calling {get_url} status code:{response.status_code}  message:{response.text}"
        logger.error(err_msg)
        raise HTTPException(err_msg, response.status_code)

    return response.json()



# For local development/testing
if __name__ == '__main__':
    try:
        parser = argparse.ArgumentParser()
        parser.add_argument("-p", "--port")
        args = parser.parse_args()
        port = 5000
        if args.port:
            port = int(args.port)
        app.run(port=port, host='0.0.0.0')
    finally:
        pass
