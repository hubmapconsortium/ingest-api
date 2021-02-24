'''
Created on Apr 23, 2019

@author: chb69
'''
import sys
import os
import pathlib
import requests
import argparse
import shutil
from flask import Flask, jsonify, abort, request, session, redirect, json, Response
from flask_cors import CORS
from globus_sdk import AccessTokenAuthorizer, AuthClient, ConfidentialAppAuthClient
import uuid

from dataset import Dataset
from collection import Collection
from specimen import Specimen
from ingest_file_helper import IngestFileHelper
#from file_helper import FileHelper

from hubmap_commons.hubmap_const import HubmapConst 
from hubmap_commons.neo4j_connection import Neo4jConnection
from hubmap_commons.hm_auth import AuthHelper, secured
from hubmap_commons.entity import Entity
from hubmap_commons.autherror import AuthError
from hubmap_commons.metadata import Metadata
from hubmap_commons.hubmap_error import HubmapError
from hubmap_commons.exceptions import HTTPException
from hubmap_commons import string_helper
from hubmap_commons import net_helper
from hubmap_commons import file_helper as commons_file_helper

import time
import logging
from pathlib import Path

LOG_FILE_NAME = "../log/ingest-api-" + time.strftime("%d-%m-%Y-%H-%M-%S") + ".log" 
logger = None

# Specify the absolute path of the instance folder and use the config file relative to the instance path
app = Flask(__name__, instance_path=os.path.join(os.path.abspath(os.path.dirname(__file__)), 'instance'), instance_relative_config=True)
app.config.from_pyfile('app.cfg')

# Enable/disable CORS from configuration based on docker or non-docker deployment
if app.config['ENABLE_CORS']:
    CORS(app)

token_list = {}

# Initialize the AuthHelper
# This is used by the @secured decorator
if AuthHelper.isInitialized() == False:
    authcache = AuthHelper.create(
        app.config['APP_CLIENT_ID'], app.config['APP_CLIENT_SECRET'])
else:
    authcache = AuthHelper.instance()

data_admin_group_uuid = '89a69625-99d7-11ea-9366-0e98982705c1'

@app.before_first_request
def init():
    global logger
    try:
        logger = logging.getLogger('ingest.service')
        logger.setLevel(logging.INFO)
        logFH = logging.FileHandler(LOG_FILE_NAME)
        logger.addHandler(logFH)
        logger.info("started")
    except Exception as e:
        print("Error opening log file during startup")
        print(str(e))


####################################################################################################
## Default Routes
####################################################################################################

# Default endpoint for testing with gateway
@app.route('/', methods = ['GET'])
def index():
    return "Hello! This is HuBMAP Ingest API service :)"


@app.route('/hello', methods=['GET'])
@secured(groups="HuBMAP-read")
def hello():
    return jsonify({'uuid': 'hello'}), 200


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
            conn = Neo4jConnection(app.config['NEO4J_SERVER'], app.config['NEO4J_USERNAME'], app.config['NEO4J_PASSWORD'])
            driver = conn.get_driver()
            is_connected = conn.check_connection(driver)
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


def get_user_info(token):
    auth_client = AuthClient(authorizer=AccessTokenAuthorizer(token))
    return auth_client.oauth2_userinfo()


####################################################################################################
## Ingest API Endpoints
####################################################################################################
'''
@app.route('/datasets', methods = ['GET'])
@secured(groups="HuBMAP-read")
def get_datasets():
    conn = None
    try:
        token = str(request.headers["AUTHORIZATION"])[7:]
        conn = Neo4jConnection(app.config['NEO4J_SERVER'], app.config['NEO4J_USERNAME'], app.config['NEO4J_PASSWORD'])
        driver = conn.get_driver()
        entity = Entity(app.config['APP_CLIENT_ID'], app.config['APP_CLIENT_SECRET'], app.config['UUID_WEBSERVICE_URL'])
        readonly_group_list = entity.get_readonly_user_groups(token)
        writeable_group_list = entity.get_writeable_user_groups(token)
        readonly_uuid_list = []
        writeable_uuid_list = []
        #build UUID group list
        for readonly_group_data in readonly_group_list:
            readonly_uuid_list.append(readonly_group_data['uuid'])
        for writeable_group_data in writeable_group_list:
            writeable_uuid_list.append(writeable_group_data['uuid'])
            
        filtered_group_uuid_list = [] 
        searchterm = None
        if 'keywords' in request.args:
            searchterm = request.args.get('keywords')
        # by default, show data from all the groups that the user can access
        filtered_group_uuid_list.extend(readonly_uuid_list)
        filtered_group_uuid_list.extend(writeable_uuid_list)
        
        # get a unique list of the groups:
        filtered_group_uuid_list = list(set(filtered_group_uuid_list))

        # remove the test group, by default
        test_group_uuid = '5bd084c8-edc2-11e8-802f-0e368f3075e8'
        if test_group_uuid in filtered_group_uuid_list:
            filtered_group_uuid_list.remove(test_group_uuid)

        # remove the readonly group by default
        read_only_group = '5777527e-ec11-11e8-ab41-0af86edb4424'
        if read_only_group in filtered_group_uuid_list:
            filtered_group_uuid_list.remove(read_only_group)

        # if the user selects a specific group in the search filter,
        # then use it for the search
        if 'group' in request.args:
            group_name = request.args.get('group')
            if group_name != 'All Groups':
                group_info = entity.get_group_by_name(group_name)
                # reset the filtered group list
                filtered_group_uuid_list = []
                filtered_group_uuid_list.append(group_info['uuid'])
        dataset = Dataset(app.config)        
        dataset_list =  dataset.search_datasets(driver, token, searchterm, readonly_uuid_list, writeable_uuid_list, filtered_group_uuid_list)
        return jsonify({'datasets': dataset_list}), 200 

    except AuthError as e:
        print(e)
        return Response('token is invalid', 401)
    except:
        msg = 'An error occurred: '
        for x in sys.exc_info():
            msg += str(x)
        abort(400, msg)
    finally:
        if conn != None:
            if conn.get_driver().closed() == False:
                conn.close()

@app.route('/datasets/<identifier>', methods = ['GET'])
@secured(groups="HuBMAP-read")
def get_dataset(identifier):
    if identifier == None or len(identifier) == 0:
        abort(400, jsonify( { 'error': 'identifier parameter is required to get a dataset' } ))
    
    conn = None
    new_uuid = None
    try:
        token = str(request.headers["AUTHORIZATION"])[7:]
        r = requests.get(app.config['UUID_WEBSERVICE_URL'] + "/" + identifier, headers={'Authorization': 'Bearer ' + token })
        if r.ok == False:
            raise ValueError("Cannot find specimen with identifier: " + identifier)
        uuid = json.loads(r.text)[0]['hm_uuid']
        conn = Neo4jConnection(app.config['NEO4J_SERVER'], app.config['NEO4J_USERNAME'], app.config['NEO4J_PASSWORD'])
        driver = conn.get_driver()
        dataset_record = Dataset.get_dataset(driver, uuid)
        conn.close()
        return jsonify( { 'dataset': dataset_record } ), 200
    
    except:
        msg = 'An error occurred: '
        for x in sys.exc_info():
            msg += str(x)
        abort(400, msg)
    finally:
        if conn != None:
            if conn.get_driver().closed() == False:
                conn.close()

@app.route('/datasets/ingest', methods=['POST'])
@secured(groups="HuBMAP-read")
def ingest_dataset():
    if not request.json:
        abort(400)
    
    #build a dataset from the json
    conn = None
    new_dataset_list = []
    try:
        conn = Neo4jConnection(app.config['NEO4J_SERVER'], app.config['NEO4J_USERNAME'], app.config['NEO4J_PASSWORD'])
        driver = conn.get_driver()
        dataset = Dataset(app.config)
        current_token = None
        nexus_token = None
        try:
            current_token = AuthHelper.parseAuthorizationTokens(request.headers)
        except:
            raise ValueError("Unable to parse token")
        if 'nexus_token' in current_token:
            nexus_token = current_token['nexus_token']
        else:
            nexus_token = current_token
        test_group_uuid = '5bd084c8-edc2-11e8-802f-0e368f3075e8'
        if not is_user_in_group(nexus_token, test_group_uuid):
            return Response('Unauthorized: Current user is not a member of a group allowed to directly upload datasets', 401)
        json_data = request.json
        new_record = dataset.ingest_datastage(driver, request.headers, json_data, nexus_token)
        conn.close()
        try:
            #reindex this node in elasticsearch
            rspn = requests.put(app.config['SEARCH_WEBSERVICE_URL'] + "/reindex/" + new_record['uuid'], headers={'Authorization': request.headers["AUTHORIZATION"]})
        except:
            print("Error happened when calling reindex web service")

        return jsonify( new_record ), 201
    
    except:
        msg = 'An error occurred: '
        for x in sys.exc_info():
            msg += str(x)
        abort(400, msg)
    finally:
        if conn != None:
            if conn.get_driver().closed() == False:
                conn.close()
'''

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
        
        #this method is called only to ensure that the user has the proper
        #write privileges.  If not an HTTPException will be thrown and handled below
        ingest_helper = IngestFileHelper(app.config)
        auth_helper.get_write_group_uuid(token, requested_group_uuid)
                    
        post_url = commons_file_helper.ensureTrailingSlashURL(app.config['ENTITY_WEBSERVICE_URL']) + '/entities/dataset'
        response = requests.post(post_url, json = dataset_request, headers = {'Authorization': 'Bearer ' + token }, verify = False)
        if response.status_code != 200:
            return Response(response.text, response.status_code)
        new_dataset = response.json()
        
        ingest_helper.create_dataset_directory(new_dataset)

        return jsonify(new_dataset)
    except HTTPException as hte:
        return Response(hte.get_description(), hte.get_status_code())
    except Exception as e:
        logger.error(e, exc_info=True)
        return Response("Unexpected error while creating a dataset: " + str(e) + "  Check the logs", 500)        
'''
@app.route('/datasets/<uuid>/validate', methods = ['PUT'])
@secured(groups="HuBMAP-read")
def validate_dataset(uuid):
    if not request.json or uuid == None or len(uuid) == 0:
        abort(400, jsonify( { 'error': 'uuid parameter is required to validate a dataset' } ))
    
    conn = None
    new_uuid = None
    try:
        conn = Neo4jConnection(app.config['NEO4J_SERVER'], app.config['NEO4J_USERNAME'], app.config['NEO4J_PASSWORD'])
        driver = conn.get_driver()
        dataset = Dataset(app.config)
        new_uuid = dataset.validate_dataset(driver, uuid)
        conn.close()

        try:
            #reindex this node in elasticsearch
            rspn = requests.put(app.config['SEARCH_WEBSERVICE_URL'] + "/reindex/" + new_uuid, headers={'Authorization': request.headers["AUTHORIZATION"]})
        except:
            print("Error happened when calling reindex web service")

        return jsonify( { 'uuid': new_uuid, 'status': 'Valid' } ), 200
    
    except:
        msg = 'An error occurred: '
        for x in sys.exc_info():
            msg += x
        abort(400, msg)
    finally:
        if conn != None:
            if conn.get_driver().closed() == False:
                conn.close()
'''
@app.route('/datasets/<uuid>/publish', methods = ['PUT'])
@secured(groups="HuBMAP-read")
def publish_datastage(uuid):
    if uuid == None or len(uuid) == 0:
        abort(400, jsonify( { 'error': 'uuid parameter is required to publish a dataset' } ))
    
    return Response("This method is not implemented. Use manual publication script", 501)


'''
@app.route('/datasets/<uuid>/unpublish', methods = ['PUT'])
@secured(groups="HuBMAP-read")
def unpublish_datastage(uuid):
    if uuid == None or len(uuid) == 0:
        abort(400, jsonify( { 'error': 'uuid parameter is required to unpublish a dataset' } ))
    
    conn = None
    new_uuid = None
    try:
        conn = Neo4jConnection(app.config['NEO4J_SERVER'], app.config['NEO4J_USERNAME'], app.config['NEO4J_PASSWORD'])
        driver = conn.get_driver()
        dataset = Dataset(app.config)        
        group_uuid = get_group_uuid_from_request(request)        
        new_uuid = dataset.publishing_process(driver, request.headers, uuid, group_uuid, False)
        conn.close()
        try:
            #reindex this node in elasticsearch
            rspn = requests.put(app.config['SEARCH_WEBSERVICE_URL'] + "/reindex/" + new_uuid, headers={'Authorization': request.headers["AUTHORIZATION"]})
        except:
            print("Error happened when calling reindex web service")

        return jsonify( { 'uuid': new_uuid } ), 204
    
    except ValueError:
        abort(404, jsonify( { 'error': 'dataset {uuid} not found'.format(uuid=uuid) } ))
        
    except:
        msg = 'An error occurred: '
        for x in sys.exc_info():
            msg += str(x)
        print (msg)
        abort(400, msg)
    finally:
        if conn != None:
            if conn.get_driver().closed() == False:
                conn.close()
'''                
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
        conn = Neo4jConnection(app.config['NEO4J_SERVER'], app.config['NEO4J_USERNAME'], app.config['NEO4J_PASSWORD'])
        driver = conn.get_driver()
        dataset = Dataset(app.config)
        status_obj = dataset.set_status(driver, uuid, new_status)
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
    finally:
        if conn != None:
            if conn.get_driver().closed() == False:
                conn.close()

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
        #{'dataset_id' : '287d61b60b806fdf54916e3b7795ad5a', 'status': '<', 'message': 'the process ran', 'metadata': [maybe some metadata stuff]}
        updated_ds = dataset.get_dataset_ingest_update_record(ds_request)

        auth_headers = {'Authorization': request.headers["AUTHORIZATION"]}
        entity_uuid = ds_request['dataset_id']
        update_url = commons_file_helper.ensureTrailingSlashURL(app.config['ENTITY_WEBSERVICE_URL']) + '/entities/' + entity_uuid
        
        response = requests.put(update_url, json = updated_ds, headers = auth_headers, verify = False)

        return jsonify( { 'result' : response.json() } ), response.status_code
    
    except HTTPException as hte:
        return Response(hte.get_description(), hte.get_status_code())
    
    except ValueError as ve:
        print('ERROR: ' + str(ve))
        return jsonify({'error' : str(ve)}), 400
        
    except Exception as e:
        logger.error(e, exc_info=True)
        return Response("Unexpected error while saving dataset: " + str(e), 500)        

'''
@app.route('/datasets/submissions/request_ingest', methods = ['POST'])
# @secured(groups="HuBMAP-read")
def temp_request_ingest_call():
    # NOTE: this is just a placeholder until Joel welling's code is ready for me to test
    # simply return the dataset's uuid as the ingest_id and add some characters for the run_id
    if not request.json:
        abort(400, jsonify( { 'error': 'no data found cannot process request_ingest' } ))
    
    conn = None
    try:

        # for now just return some dummy data
        json_data = request.json
        #{"ingest_id": "abc123", "run_id": "run_657-xyz", "overall_file_count": "99", "top_folder_contents": "["IMS", "processed_microscopy","raw_microscopy","VAN0001-RK-1-spatial_meta.txt"]"}
        return_obj = {"ingest_id" : json_data['submission_id'], "run_id" : json_data['submission_id'] + '-1111', "overall_file_count": "10", "top_folder_contents": "[\"dir1\",\"dir2\",\"dir3\"]"}       
        return jsonify( { "submission" : return_obj } ), 200
    
    except ValueError:
        abort(404, jsonify( { 'error': 'ingest_id not found'} ))
        
    except:
        msg = 'An error occurred: '
        for x in sys.exc_info():
            msg += str(x)
        print (msg)
        abort(400, msg)
    finally:
        if conn != None:
            if conn.get_driver().closed() == False:
                conn.close()


def get_group_uuid_from_request(request):
    return_group_uuid = None
    try:
        form_data = json.loads(request.form['data'])

        current_token = None
        try:
            current_token = AuthHelper.parseAuthorizationTokens(request.headers)
        except:
            raise ValueError("Unable to parse token")
        
        nexus_token = current_token
        if 'nexus_token' in current_token:
            nexus_token = current_token['nexus_token']

        # determine the group UUID to use when creating the dataset
        group_uuid = None
        form_data = json.loads(request.form['data'])
        if 'user_group_uuid' in form_data:
            if is_user_in_group(nexus_token, form_data['user_group_uuid']):
                group_uuid = form_data['user_group_uuid']
                entity = Entity(app.config['APP_CLIENT_ID'], app.config['APP_CLIENT_SECRET'], app.config['UUID_WEBSERVICE_URL'])
                grp_info = None
                try:
                    grp_info = entity.get_group_by_identifier(group_uuid)
                except ValueError as ve:
                    return Response('Unauthorized: Cannot find information on group: ' + str(group_uuid), 401)
                if grp_info['generateuuid'] == False:
                    return Response('Unauthorized: This group {grp_info} is not a group with write privileges.'.format(grp_info=grp_info), 401)
            else:
                return Response('Unauthorized: Current user is not a member of group: ' + str(group_uuid), 401) 
        else:
            #manually find the group id given the current user:
            entity = Entity(app.config['APP_CLIENT_ID'], app.config['APP_CLIENT_SECRET'], app.config['UUID_WEBSERVICE_URL'])
            group_list = entity.get_user_groups(nexus_token)
            for grp in group_list:
                if grp['generateuuid'] == True:
                    return_group_uuid = grp['uuid']
                    break

            if return_group_uuid == None:
                return Response('Unauthorized: Current user is not a member of a group allowed to create new datasets', 401)
            return return_group_uuid
    except:
        msg = 'An error occurred: '
        for x in sys.exc_info():
            msg += x
        abort(400, msg)
'''
        
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
        
        conn = Neo4jConnection(app.config['NEO4J_SERVER'], app.config['NEO4J_USERNAME'], app.config['NEO4J_PASSWORD'])
        driver = conn.get_driver()
        
        with driver.session() as session:
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
                                     "full_path": ingest_helper.get_dataset_directory_absolute_path(dataset_request),
                                     "provider": "{group_name}".format(group_name=AuthHelper.getGroupDisplayName(dataset_request['group_uuid']))}, 
                                          headers={'Content-Type':'application/json', 'Authorization': 'Bearer {token}'.format(token=AuthHelper.instance().getProcessSecret() )})
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
        put_url = commons_file_helper.ensureTrailingSlashURL(app.config['ENTITY_WEBSERVICE_URL']) + '/entities/dataset/' + uuid
        response = requests.post(put_url, json = dataset_request, headers = {'Authorization': 'Bearer ' + token }, verify = False)
        if response.status_code != 200:
            return Response(response.text, response.status_code)
        updated_dataset = response.json()
        return jsonify(updated_dataset)
    except HTTPException as hte:
        return Response(hte.get_description(), hte.get_status_code())
    except Exception as e:
        logger.error(e, exc_info=True)
        return Response("Unexpected error while creating a dataset: " + str(e) + "  Check the logs", 500)        
 
 
'''              
@app.route('/datasets/<uuid>', methods = ['PUT'])
@secured(groups="HuBMAP-read")
def modify_dataset(uuid):
    if not request.form or uuid == None or len(uuid) == 0:
        abort(400, jsonify( { 'error': 'uuid parameter is required to modify a dataset' } ))
    if 'data' not in request.form:
        abort(400, jsonify( { 'error': 'form data is required to modify a dataset' } ))

    current_token = None
    try:
        current_token = AuthHelper.parseAuthorizationTokens(request.headers)
    except:
        raise ValueError("Unable to parse token")
    
    nexus_token = current_token
    
    if 'nexus_token' in current_token:
        nexus_token = current_token['nexus_token']

    conn = None
    new_uuid = None
    try:
        group_uuid = get_group_uuid_from_request(request)    
        conn = Neo4jConnection(app.config['NEO4J_SERVER'], app.config['NEO4J_USERNAME'], app.config['NEO4J_PASSWORD'])
        driver = conn.get_driver()
        dataset = Dataset(app.config)
        
        form_data = json.loads(request.form['data'])
        if form_data['status'] == 'processing' and not is_user_in_group(nexus_token, app.config['HUBMAP_DATA_ADMIN_GROUP_UUID']):
            return jsonify( { 'error': 'user need to be a hubmap data admin to submit a datatset' }), 403

        new_uuid = dataset.modify_dataset(driver, request.headers, uuid, form_data, group_uuid)
        conn.close()

        try:
            #reindex this node in elasticsearch
            rspn = requests.put(app.config['SEARCH_WEBSERVICE_URL'] + "/reindex/" + new_uuid, headers={'Authorization': request.headers["AUTHORIZATION"]})
        except:
            print("Error happened when calling reindex web service")

        return jsonify( { 'uuid': new_uuid } ), 204
    
    except:
        msg = 'An error occurred: '
        for x in sys.exc_info():
            msg += x
        abort(400, msg)
    finally:
        if conn != None:
            if conn.get_driver().closed() == False:
                conn.close()
'''
                    
"""
@app.route('/datasets/<uuid>/lock', methods = ['PUT'])
@secured(groups="HuBMAP-read")
def lock_dataset(uuid):
    if not request.json or uuid == None or len(uuid) == 0:
        abort(400, jsonify( { 'error': 'uuid parameter is required to lock a dataset' } ))
    
    conn = None
    new_uuid = None
    try:
        conn = Neo4jConnection(app.config['NEO4J_SERVER'], app.config['NEO4J_USERNAME'], app.config['NEO4J_PASSWORD'])
        driver = conn.get_driver()
        dataset = Dataset(app.config)
        new_uuid = dataset.lock_dataset(driver, uuid)
        conn.close()
        return jsonify( { 'uuid': new_uuid, 'status': 'Locked' } ), 200
    
    except:
        msg = 'An error occurred: '
        for x in sys.exc_info():
            msg += x
        abort(400, msg)
    finally:
        if conn != None:
            if conn.get_driver().closed() == False:
                conn.close()

@app.route('/datasets/<uuid>/reopen', methods = ['PUT'])
@secured(groups="HuBMAP-read")
def reopen_dataset(uuid):
    if not request.json or uuid == None or len(uuid) == 0:
        abort(400, jsonify( { 'error': 'uuid parameter is required to reopen a dataset' } ))
    
    conn = None
    new_uuid = None
    try:
        conn = Neo4jConnection(app.config['NEO4J_SERVER'], app.config['NEO4J_USERNAME'], app.config['NEO4J_PASSWORD'])
        driver = conn.get_driver()
        dataset = Dataset(app.config)
        new_uuid = dataset.reopen_dataset(driver, uuid)
        conn.close()
        return jsonify( { 'uuid': new_uuid, 'status': 'Locked' } ), 200
    
    except:
        msg = 'An error occurred: '
        for x in sys.exc_info():
            msg += x
        abort(400, msg)
    finally:
        if conn != None:
            if conn.get_driver().closed() == False:
                conn.close()

@app.route('/collections', methods = ['GET'])
@secured(groups="HuBMAP-read")
def get_collections():
    conn = None
    try:
        conn = Neo4jConnection(app.config['NEO4J_SERVER'], app.config['NEO4J_USERNAME'], app.config['NEO4J_PASSWORD'])
        driver = conn.get_driver()
        collection_records = Collection.get_collections(driver)
        conn.close()
        return jsonify( { 'collections': collection_records } ), 200
    
    except:
        msg = 'An error occurred: '
        for x in sys.exc_info():
            msg += str(x)
        abort(400, msg)
    finally:
        if conn != None:
            if conn.get_driver().closed() == False:
                conn.close()

    

@app.route('/collections', methods = ['POST'])
@secured(groups="HuBMAP-read")
def create_collection():
    if not request.form:
        abort(400)
    if 'data' not in request.form:
        abort(400)
    conn = None
    new_uuid = None
    try:
        token = str(request.headers["AUTHORIZATION"])[7:]
        conn = Neo4jConnection(app.config['NEO4J_SERVER'], app.config['NEO4J_USERNAME'], app.config['NEO4J_PASSWORD'])
        driver = conn.get_driver()
        collection = Collection(app.config)
        form_data = json.loads(request.form['data'])
        collection_uuid = Collection.create_collection(driver, token, form_data)
        
        conn.close()
        return jsonify({ 'uuid': collection_uuid}), 201 

    except AuthError as e:
        print(e)
        return Response('token is invalid', 401)
    except:
        msg = 'An error occurred: '
        for x in sys.exc_info():
            msg += str(x)
        abort(400, msg)
    finally:
        if conn != None:
            if conn.get_driver().closed() == False:
                conn.close()

@app.route('/new-collection', methods = ['POST'])
@secured(groups="HuBMAP-read")
def create_collection_json():
    conn = None
    try:
        token = str(request.headers["AUTHORIZATION"])[7:]
        data = request.get_json()
        if not 'label' in data:
            return Response("Required field missing: label.", 400)
        if not 'description' in data:
            return Response("Required field missing: description", 400)
        conn = Neo4jConnection(app.config['NEO4J_SERVER'], app.config['NEO4J_USERNAME'], app.config['NEO4J_PASSWORD'])
        driver = conn.get_driver()
        collection = Collection(app.config)
        
        collection_uuid = Collection.create_collection(driver, token, data)
        
        conn.close()
        return jsonify({ 'uuid': collection_uuid}), 201 

    except AuthError as e:
        print(e)
        return Response('token is invalid', 401)
    except:
        msg = 'An error occurred: '
        for x in sys.exc_info():
            msg += str(x)
        abort(400, msg)
    finally:
        if conn != None:
            if conn.get_driver().closed() == False:
                conn.close()
                
                
@app.route('/collections/<uuid>', methods = ['PUT'])
@secured(groups="HuBMAP-read")
def update_collection(uuid):
    global logger
    conn = None
    try:
        if not request.is_json:
            return Response("json payload required", 400)
        
        record = request.get_json()
        coll = Collection(app.config)
        coll.update_collection(uuid, record)
        return Response("OK", 200)
    except HTTPException as he:
        logger.error(he, exc_info=True)
        return(Response(he.get_description(), he.get_status_code()))
    except Exception as e:
        eMsg = str(e)
        logger.error(e, exc_info=True)
        return(Response("Unexpected error: " + eMsg, 500))
    finally:
        if conn != None:
            if conn.get_driver().closed() == False:
                conn.close()   


@app.route('/collections/<identifier>', methods = ['GET'])
@secured(groups="HuBMAP-read")
def get_collection(identifier):
    if identifier == None or len(identifier) == 0:
        abort(400, jsonify( { 'error': 'identifier parameter is required to get a dataset' } ))
    
    conn = None
    new_uuid = None
    try:
        conn = Neo4jConnection(app.config['NEO4J_SERVER'], app.config['NEO4J_USERNAME'], app.config['NEO4J_PASSWORD'])
        driver = conn.get_driver()
        collection_record = Collection.get_collection(driver, identifier)
        conn.close()
        return jsonify( { 'collection': collection_record } ), 200
    
    except:
        msg = 'An error occurred: '
        for x in sys.exc_info():
            msg += str(x)
        abort(400, msg)
    finally:
        if conn != None:
            if conn.get_driver().closed() == False:
                conn.close()
"""



####################################################################################################
## Metadata API Endpoints
####################################################################################################

@app.route('/metadata/usergroups', methods = ['GET'])
@secured(groups="HuBMAP-read")
def user_group_list():
    token = str(request.headers["AUTHORIZATION"])[7:]
    try:
        entity = Entity(app.config['APP_CLIENT_ID'], app.config['APP_CLIENT_SECRET'], app.config['UUID_WEBSERVICE_URL'])
        group_list = entity.get_user_groups(token)
        return jsonify( {'groups' : group_list}), 200
    except AuthError as e:
        print(e)
        return Response('token is invalid', 401)
    except:
        msg = 'An error occurred: '
        for x in sys.exc_info():
            msg += str(x)
        abort(400, msg)

@app.route('/metadata/userroles', methods = ['GET'])
@secured(groups="HuBMAP-read")
def user_role_list():
    token = str(request.headers["AUTHORIZATION"])[7:]
    try:
        entity = Entity(app.config['APP_CLIENT_ID'], app.config['APP_CLIENT_SECRET'], app.config['UUID_WEBSERVICE_URL'])
        role_list = entity.get_user_roles(token)
        
        #temp code!!
        #role_list = []
        
        return jsonify( {'roles' : role_list}), 200
    except AuthError as e:
        print(e)
        return Response('token is invalid', 401)
    except:
        msg = 'An error occurred: '
        for x in sys.exc_info():
            msg += str(x)
        abort(400, msg)

'''
# this method returns a JSON list of the UUIDs for the entities the current user can edit.  The entitytype is an optional parameter.  If it is not set,
# the method returns all the editable entities available to the user. 
@app.route('/metadata/usercanedit/type', methods = ['GET'])
@app.route('/metadata/usercanedit/type/<entitytype>', methods = ['GET'])
@secured(groups="HuBMAP-read")
def user_edit_entity_list(entitytype=None):
    token = str(request.headers["AUTHORIZATION"])[7:]
    conn = None
    try:
        conn = Neo4jConnection(app.config['NEO4J_SERVER'], app.config['NEO4J_USERNAME'], app.config['NEO4J_PASSWORD'])
        driver = conn.get_driver()
        entity = Entity(app.config['APP_CLIENT_ID'], app.config['APP_CLIENT_SECRET'], app.config['UUID_WEBSERVICE_URL'])
        edit_list = entity.get_editable_entities_by_type(driver, token, entitytype)
        return jsonify( { 'entity_list': edit_list } ), 200
    except AuthError as e:
        print(e)
        return Response('token is invalid', 401)
    except:
        msg = 'An error occurred: '
        for x in sys.exc_info():
            msg += str(x)
        abort(400, msg)
    finally:
        conn.close()

# this method returns a simple JSON message {'editable':'True|False'}.  True indicates that the current
# user can edit the given entity.  False indicates they cannot edit the entity.
@app.route('/metadata/usercanedit/<entityuuid>', methods = ['GET'])
@secured(groups="HuBMAP-read")
def can_user_edit_entity(entityuuid):
    token = str(request.headers["AUTHORIZATION"])[7:]
    #entityuuid = request.args.get('entityuuid')
    if len(entityuuid) == 0:
        abort(400, jsonify( { 'error': 'entityuuid parameter is required' } ))
    conn = None
    try:
        conn = Neo4jConnection(app.config['NEO4J_SERVER'], app.config['NEO4J_USERNAME'], app.config['NEO4J_PASSWORD'])
        driver = conn.get_driver()
        entity = Entity(app.config['APP_CLIENT_ID'], app.config['APP_CLIENT_SECRET'], app.config['UUID_WEBSERVICE_URL'])
        can_edit = entity.can_user_edit_entity(driver, token, entityuuid)
        return jsonify( { 'editable': can_edit } ), 200
    
    except:
        msg = 'An error occurred: '
        for x in sys.exc_info():
            msg += str(x)
        abort(400, msg)
    finally:
        conn.close()

# this method returns JSON containing a group uuid if given the name of a group (ex: hubmap-read) or returns
# the name of the group if given a uuid (ex: 5777527e-ec11-11e8-ab41-0af86edb4424).  If the idenfier cannot be found,
# it returns a 404.
# The JSON returned looks like {"groupuuid":"5777527e-ec11-11e8-ab41-0af86edb4424", "groupname":"hubmap-all-access"}
# example url: /metadata/groups/hubmap-read or /metadata/groups/777527e-ec11-11e8-ab41-0af86edb4424  
@app.route('/metadata/groups/<identifier>', methods = ['GET'])
@secured(groups="HuBMAP-read")
def get_group_by_identifier(identifier):
    if len(identifier) == 0:
        abort(400, jsonify( { 'error': 'identifier parameter is required' } ))
    metadata = Metadata(app.config['APP_CLIENT_ID'], app.config['APP_CLIENT_SECRET'], app.config['UUID_WEBSERVICE_URL'])
    try:
        group = metadata.get_group_by_identifier(identifier)
        return jsonify( { 'group': group } ), 200
    except ValueError as ve:
        return jsonify( { 'error': 'cannot find a Hubmap group matching: [' + identifier + ']' } ), 404
        

'''

@app.route('/metadata/source/type/<type_code>', methods = ['GET'])
@secured(groups="HuBMAP-read")
def get_metadata_by_source_type(type_code):
    if type_code == None or len(type_code) == 0:
        abort(400, jsonify( { 'error': 'type_code parameter is required to get a metadata instance' } ))
    
    conn = None
    try:
        conn = Neo4jConnection(app.config['NEO4J_SERVER'], app.config['NEO4J_USERNAME'], app.config['NEO4J_PASSWORD'])
        driver = conn.get_driver()
        metadata = Metadata(app.config['APP_CLIENT_ID'], app.config['APP_CLIENT_SECRET'], app.config['UUID_WEBSERVICE_URL'])
        general_type_attr = HubmapConst.get_general_node_type_attribute(type_code)
        if len(general_type_attr) == 0:
            abort(400, 'Unable to find type data for type: ' + type_code)
        metadata_record = metadata.get_metadata_by_source_type(driver, general_type_attr, type_code)
        conn.close()
        #TODO: figure out how to jsonify an array
        return jsonify( { 'metadata': metadata_record } ), 200
    
    except:
        msg = 'An error occurred: '
        for x in sys.exc_info():
            msg += str(x)
        abort(400, msg)
    finally:
        conn.close()

'''
@app.route('/metadata/source/<uuid>', methods = ['GET'])
@secured(groups="HuBMAP-read")
def get_metadata_by_source(uuid):
    if uuid == None or len(uuid) == 0:
        abort(400, jsonify( { 'error': 'uuid parameter is required to get a metadata instance' } ))
    
    conn = None
    try:
        conn = Neo4jConnection(app.config['NEO4J_SERVER'], app.config['NEO4J_USERNAME'], app.config['NEO4J_PASSWORD'])
        driver = conn.get_driver()
        metadata = Metadata(app.config['APP_CLIENT_ID'], app.config['APP_CLIENT_SECRET'], app.config['UUID_WEBSERVICE_URL'])
        metadata_record = metadata.get_metadata_by_source(driver, uuid)
        conn.close()
        #TODO: figure out how to jsonify an array
        return jsonify( { 'metadata': metadata_record } ), 200
    
    except:
        msg = 'An error occurred: '
        for x in sys.exc_info():
            msg += str(x)
        abort(400, msg)
    finally:
        conn.close()

@app.route('/metadata/<uuid>', methods = ['GET'])
@secured(groups="HuBMAP-read")
def get_metadata(uuid):
    if uuid == None or len(uuid) == 0:
        abort(400, jsonify( { 'error': 'uuid parameter is required to get a metadata instance' } ))
    
    conn = None
    try:
        conn = Neo4jConnection(app.config['NEO4J_SERVER'], app.config['NEO4J_USERNAME'], app.config['NEO4J_PASSWORD'])
        driver = conn.get_driver()
        metadata = Metadata(app.config['APP_CLIENT_ID'], app.config['APP_CLIENT_SECRET'], app.config['UUID_WEBSERVICE_URL'])
        metadata_record = metadata.get_metadata(driver, uuid)
        conn.close()
        return jsonify( { 'metadata': metadata_record } ), 200
    
    except:
        msg = 'An error occurred: '
        for x in sys.exc_info():
            msg += str(x)
        abort(400, msg)
    finally:
        conn.close()





####################################################################################################
## Specimen API Endpoints
####################################################################################################
   
@app.route('/specimens', methods=['POST'])
@secured(groups="HuBMAP-read")
def create_specimen():
    if not request.form:
        abort(400)
    if 'data' not in request.form:
        abort(400)

    # build a dataset from the json
    #new_specimen = {}
    # Convert the incoming JSON into an associative array using the JSON keys as the keys for the array
    # for key in request.json.keys():
    #    new_specimen[key] = request.json[key]
    # TODO: make this a list in a configuration file
    #min_datastage_keys = ['name','description','hasphi','labcreatedat','createdby','parentcollection']
    #missing_key_list = [x for x in min_datastage_keys if x not in request.json.keys()]
    # if len(missing_key_list) > 0:
    #    abort(400, "Bad request, the JSON is missing these required fields:" + str(missing_key_list))


    conn = None
    new_uuid = None
    try:
        token = str(request.headers["AUTHORIZATION"])[7:]
        conn = Neo4jConnection(app.config['NEO4J_SERVER'], app.config['NEO4J_USERNAME'], app.config['NEO4J_PASSWORD'])
        driver = conn.get_driver()
        specimen = Specimen(app.config)
        sourceuuid = None
        if 'data' not in request.form:
            return Response('form data is invalid', 401)
        form_data = json.loads(request.form['data'])
        
        # determine the group UUID to use when creating the specimen
        group_uuid = None
        if 'user_group_uuid' in form_data:
            if is_user_in_group(token, form_data['user_group_uuid']):
                group_uuid = form_data['user_group_uuid']
                entity = Entity(app.config['APP_CLIENT_ID'], app.config['APP_CLIENT_SECRET'], app.config['UUID_WEBSERVICE_URL'])
                grp_info = None
                try:
                    grp_info = entity.get_group_by_identifier(group_uuid)
                except ValueError as ve:
                    return Response('Unauthorized: Cannot find information on group: ' + str(group_uuid), 401)
                if grp_info['generateuuid'] == False:
                    return Response('Unauthorized: This group {grp_info} is not a group with write privileges.'.format(grp_info=grp_info), 401)
            else:
                return Response('Unauthorized: Current user is not a member of group: ' + str(group_uuid), 401) 
        else:
            #manually find the group id given the current user:
            entity = Entity(app.config['APP_CLIENT_ID'], app.config['APP_CLIENT_SECRET'], app.config['UUID_WEBSERVICE_URL'])
            group_list = entity.get_user_groups(token)
            for grp in group_list:
                if grp['generateuuid'] == True:
                    group_uuid = grp['uuid']
                    break

            if group_uuid == None:
                return Response('Unauthorized: Current user is not a member of a group allowed to create new specimens', 401)
        # default to one new specimen
        sample_count = 1    
        if 'source_uuid' in form_data:
            sourceuuid = form_data['source_uuid']
            # the source_uuid is now a dictionary like this: "source_uuid":{"hubmap_identifier":"TEST0006-LI-1-1-1","datatype":"Fresh Frozen Tissue Section"}
            if isinstance(sourceuuid, dict):
                sourceuuid = sourceuuid["hubmap_identifier"]
            r = requests.get(app.config['UUID_WEBSERVICE_URL'] + "/" + sourceuuid, headers={'Authorization': 'Bearer ' + token })
            if r.ok == False:
                raise ValueError("Cannot find specimen with identifier: " + sourceuuid)
            sourceuuid = json.loads(r.text)[0]['hm_uuid']
            
            if 'sample_count' in form_data:
                if len(str(form_data['sample_count'])) > 0:
                    sample_count = int(form_data['sample_count'])

        new_uuid_records = specimen.create_specimen(
            driver, request, form_data, request.files, token, group_uuid, sourceuuid, sample_count)
        #new_uuid_record = specimen.create_specimen(
        #    driver, request, form_data, request.files, token, group_uuid, sourceuuid, sample_count)
        conn.close()
        #return jsonify({'uuid': new_uuid_record[HubmapConst.UUID_ATTRIBUTE]}), 201 

        print('Before reindex calls')
        try:
            #reindex this node in elasticsearch
            for samples in new_uuid_records['new_samples']:
                print(f"Begining of reindex {samples['uuid']} call")
                print(app.config['SEARCH_WEBSERVICE_URL'] + "/reindex/" + samples['uuid'])
                rspn = requests.put(app.config['SEARCH_WEBSERVICE_URL'] + "/reindex/" + samples['uuid'], headers={'Authorization': request.headers["AUTHORIZATION"]})
                print(rspn)
                print(rspn.text)
                print(f"After reindex {samples['uuid']} call")
        except:
            print('Error happended when call teh reindex web service')
        print('Before Return')

        return jsonify(new_uuid_records), 201 

    except HubmapError as he:
        print('A Hubmap error was encountered: ', str(he))
        return jsonify( he.getJson()), 400
        #return Response(jsonify(he.getJson()), 401)
    except AuthError as e:
        print(e)
        return Response('token is invalid', 401)
    except:
        msg = 'An error occurred: '
        for x in sys.exc_info():
            msg += str(x)
        abort(400, msg)
    finally:
        if conn != None:
            if conn.get_driver().closed() == False:
                conn.close()

def is_user_in_group(token, group_uuid):
    entity = Entity(app.config['APP_CLIENT_ID'], app.config['APP_CLIENT_SECRET'], app.config['UUID_WEBSERVICE_URL'])
    group_list = entity.get_user_groups(token)
    for grp in group_list:
        if grp['uuid'] == group_uuid:
            return True
    return False

@app.route('/specimens/<identifier>', methods=['PUT'])
@secured(groups="HuBMAP-read")
def update_specimen(identifier):
    if not request.form:
        abort(400)
    if 'data' not in request.form:
        abort(400)

    # build a dataset from the json
    #new_specimen = {}
    # Convert the incoming JSON into an associative array using the JSON keys as the keys for the array
    # for key in request.json.keys():
    #    new_specimen[key] = request.json[key]
    # TODO: make this a list in a configuration file
    #min_datastage_keys = ['name','description','hasphi','labcreatedat','createdby','parentcollection']
    #missing_key_list = [x for x in min_datastage_keys if x not in request.json.keys()]
    # if len(missing_key_list) > 0:
    #    abort(400, "Bad request, the JSON is missing these required fields:" + str(missing_key_list))


    conn = None
    new_uuid = None
    try:
        token = str(request.headers["AUTHORIZATION"])[7:]
        r = requests.get(app.config['UUID_WEBSERVICE_URL'] + "/" + identifier, headers={'Authorization': 'Bearer ' + token })
        if r.ok == False:
            raise ValueError("Cannot find specimen with identifier: " + identifier)
        uuid = json.loads(r.text)[0]['hm_uuid']
        conn = Neo4jConnection(app.config['NEO4J_SERVER'], app.config['NEO4J_USERNAME'], app.config['NEO4J_PASSWORD'])
        driver = conn.get_driver()
        specimen = Specimen(app.config)
        form_data = request.form['data']
        # use the group uuid if it is sent from the front-end
        group_uuid = None
        if 'user_group_uuid' in form_data:
            if is_user_in_group(token, form_data['user_group_uuid']):
                group_uuid = form_data['user_group_uuid']
            else:
                return Response('Unauthorized: Current user is not a member of group: ' + str(group_uuid), 401) 
        sourceuuid = None
        new_uuid_record = specimen.update_specimen(
            driver, uuid, request, json.loads(form_data), request.files, token, group_uuid)
        conn.close()
        try:
            #reindex this node in elasticsearch
            rspn = requests.put(app.config['SEARCH_WEBSERVICE_URL'] + "/reindex/" + new_uuid_record, headers={'Authorization': request.headers["AUTHORIZATION"]})
        except:
            print("Error happend when calling reindex web service")
        return jsonify({'uuid': uuid}), 200 

    except AuthError as e:
        print(e)
        return Response('token is invalid', 401)
    except:
        msg = 'An error occurred: '
        for x in sys.exc_info():
            msg += str(x)
        abort(400, msg)
    finally:
        if conn != None:
            if conn.get_driver().closed() == False:
                conn.close()

@app.route('/specimens', methods=['PUT'])
@secured(groups="HuBMAP-read")
def update_specimen_lab_ids():
    
    #Batch update specimen lab ids
    #request payload: request.data
    #example: 
    #[{'TEST0001': '123456', 'TEST0002': '234567'}]
    #return: 200 OK
    #        400 Bad Request

    if not request.data:
        abort(400)
    
    conn = None
    try:
        token = str(request.headers["AUTHORIZATION"])[7:]

        conn = Neo4jConnection(app.config['NEO4J_SERVER'], app.config['NEO4J_USERNAME'], app.config['NEO4J_PASSWORD'])
        driver = conn.get_driver()
        specimen = Specimen(app.config)

        result = specimen.batch_update_specimen_lab_ids(
            driver, request.json, token)
        conn.close()
        for item in request.json:
            uuid = item['uuid']
            try:
                #reindex this node in elasticsearch
                rspn = requests.put(app.config['SEARCH_WEBSERVICE_URL'] + "/reindex/" + uuid, headers={'Authorization': request.headers["AUTHORIZATION"]})
            except:
                print("Error happened when calling reindex web service")
        if result:
            return jsonify({'success':True}), 200
        else:
            return jsonify({'success':False}), 400

    except AuthError as e:
        print(e)
        return Response('token is invalid', 401)
    except:
        msg = 'An error occurred: '
        for x in sys.exc_info():
            msg += str(x)
        abort(400, msg)
    finally:
        if conn != None:
            if conn.get_driver().closed() == False:
                conn.close()

@app.route('/specimens/exists/<uuid>', methods=['GET'])
@secured(groups="HuBMAP-read")
def does_specimen_exist(uuid):
    if uuid == None:
        abort(400)
    if len(uuid) == 0:
        abort(400)

    conn = None
    try:
        token = str(request.headers["AUTHORIZATION"])[7:]
        r = requests.get(app.config['UUID_WEBSERVICE_URL'] + "/" + uuid, headers={'Authorization': 'Bearer ' + token })
        return jsonify({'exists': r.ok}), 200 

    except AuthError as e:
        print(e)
        return Response('token is invalid', 401)
    except:
        msg = 'An error occurred: '
        for x in sys.exc_info():
            msg += str(x)
        abort(400, msg)

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
        conn = Neo4jConnection(app.config['NEO4J_SERVER'], app.config['NEO4J_USERNAME'], app.config['NEO4J_PASSWORD'])
        driver = conn.get_driver()
        siblingid_list = Specimen.get_ingest_group_list(driver, uuid)
        return jsonify({'ingest_group_ids': siblingid_list}), 200 

    except AuthError as e:
        print(e)
        return Response('token is invalid', 401)
    except:
        msg = 'An error occurred: '
        for x in sys.exc_info():
            msg += str(x)
        abort(400, msg)
    finally:
        if conn != None:
            if conn.get_driver().closed() == False:
                conn.close()

@app.route('/specimens/<identifier>/ingest-group-count', methods=['GET'])
@secured(groups="HuBMAP-read")
def get_ingest_group_count(identifier):
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
        conn = Neo4jConnection(app.config['NEO4J_SERVER'], app.config['NEO4J_USERNAME'], app.config['NEO4J_PASSWORD'])
        driver = conn.get_driver()
        sibling_count = Specimen.get_ingest_group_count(driver, uuid)
        return jsonify({'ingest_group_count': sibling_count}), 200 

    except AuthError as e:
        print(e)
        return Response('token is invalid', 401)
    except:
        msg = 'An error occurred: '
        for x in sys.exc_info():
            msg += str(x)
        abort(400, msg)
    finally:
        if conn != None:
            if conn.get_driver().closed() == False:
                conn.close()


@app.route('/specimens/<identifier>', methods=['GET'])
@secured(groups="HuBMAP-read")
def get_specimen(identifier):
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
        uuid = json.loads(r.text)[0]['hm_uuid']
        conn = Neo4jConnection(app.config['NEO4J_SERVER'], app.config['NEO4J_USERNAME'], app.config['NEO4J_PASSWORD'])
        driver = conn.get_driver()
        specimen = Entity.get_entity_metadata(driver, uuid)
        return jsonify({'specimen': specimen}), 200 

    except AuthError as e:
        print(e)
        return Response('token is invalid', 401)
    except:
        msg = 'An error occurred: '
        for x in sys.exc_info():
            msg += str(x)
        abort(400, msg)
    finally:
        if conn != None:
            if conn.get_driver().closed() == False:
                conn.close()

@app.route('/specimens/search', methods=['GET'])
@secured(groups="HuBMAP-read")
def search_specimen():
    """ Search using Lucene indices.  The items returned are visible to the user according to their token.
    
    Some example URLs are:
        http://localhost:5004/specimens/search?search_term=test donor&entity_type=whole_organ
        uses Lucene index to find items with matching terms
        
        http://localhost:5004/specimens/search/
        uses straight Neo4j query to find items the current user is allowed to see

    """
    conn = None
    try:
        token = str(request.headers["AUTHORIZATION"])[7:]
        conn = Neo4jConnection(app.config['NEO4J_SERVER'], app.config['NEO4J_USERNAME'], app.config['NEO4J_PASSWORD'])
        driver = conn.get_driver()
        entity = Entity(app.config['APP_CLIENT_ID'], app.config['APP_CLIENT_SECRET'], app.config['UUID_WEBSERVICE_URL'])
        readonly_group_list = entity.get_readonly_user_groups(token)
        writeable_group_list = entity.get_writeable_user_groups(token)
        readonly_uuid_list = []
        writeable_uuid_list = []
        #build UUID group list
        for readonly_group_data in readonly_group_list:
            readonly_uuid_list.append(readonly_group_data['uuid'])
        for writeable_group_data in writeable_group_list:
            writeable_uuid_list.append(writeable_group_data['uuid'])
            
        filtered_group_uuid_list = [] 
        entity_type_list = request.args.get('entity_type')
        specimen_type = None
        searchterm = None
        include_datasets = False
        if 'specimen_type' in request.args:
            specimen_type = request.args.get('specimen_type')
        if 'search_term' in request.args:
            searchterm = request.args.get('search_term')
        if 'include_datasets' in request.args:
            include_datasets_string = request.args.get('include_datasets')
            if str(include_datasets_string).lower() == 'true':
                include_datasets = True
        # by default, show data from all the groups that the user can access
        filtered_group_uuid_list.extend(readonly_uuid_list)
        filtered_group_uuid_list.extend(writeable_uuid_list)
        
        # get a unique list of the groups:
        filtered_group_uuid_list = list(set(filtered_group_uuid_list))
        
        # remove the test group, by default
        test_group_uuid = '5bd084c8-edc2-11e8-802f-0e368f3075e8'
        if test_group_uuid in filtered_group_uuid_list:
            filtered_group_uuid_list.remove(test_group_uuid)
            
        # remove the readonly group by default
        read_only_group = '5777527e-ec11-11e8-ab41-0af86edb4424'
        if read_only_group in filtered_group_uuid_list:
            filtered_group_uuid_list.remove(read_only_group)
        # if the user selects a specific group in the search filter,
        # then use it for the search
        if 'group' in request.args:
            group_name = request.args.get('group')
            if group_name != 'All Groups':
                group_info = entity.get_group_by_name(group_name)
                # reset the filtered group list
                filtered_group_uuid_list = []
                filtered_group_uuid_list.append(group_info['uuid'])
                
        specimen_list =  Specimen.search_specimen(driver, searchterm, readonly_uuid_list, writeable_uuid_list, filtered_group_uuid_list, specimen_type, include_datasets)
        """if searchterm == None:
            specimen_list = entity.get_editable_entities_by_type(driver, token, specimen_type)
        else:
            specimen_list =  Specimen.search_specimen(driver, searchterm, readonly_uuid_list, writeable_uuid_list, filtered_group_uuid_list, specimen_type)
        """
        return jsonify({'specimens': specimen_list}), 200 

    except AuthError as e:
        print(e)
        return Response('token is invalid', 401)
    except:
        msg = 'An error occurred: '
        for x in sys.exc_info():
            msg += str(x)
        abort(400, msg)
    finally:
        if conn != None:
            if conn.get_driver().closed() == False:
                conn.close()


#@app.route('/files', methods=['POST'])
#@secured(groups="HuBMAP-read")
#def create_file():
#    try:
#        token = str(request.headers["AUTHORIZATION"])[7:]
#        userinfo = authcache.getUserInfo(token, True)

#        globus_id = userinfo.get('sub')
#        form_id = request.form.get('form_id')
#        if form_id is None:
#            abort(400, "form_id is missing.")
        
#        directory_path = f'{globus_id}/{form_id}'
        # save file
#        FileHelper.save_file(request.files['file'],
#                           directory_path, 
#                           create_folder=True)

#        return "file uploaded.", 201 
#    except:
#        msg = 'An error occurred: '
#        for x in sys.exc_info():
#            msg += str(x)
#        abort(400, msg)

@app.route('/donor', methods=['POST'])
@secured(groups="HuBMAP-read")
def create_donor():
    data = request.get_json()
    token = str(request.headers["AUTHORIZATION"])[7:]
    userinfo = authcache.getUserInfo(token, True)
    globus_id = userinfo.get('sub')
    form_id = data.get('form_id')

    specimen = Specimen(app.config)
    entity = Entity(app.config['APP_CLIENT_ID'],
                    app.config['APP_CLIENT_SECRET'],
                    app.config['UUID_WEBSERVICE_URL'])
    # 1. get the group uuid
    group_uuid = data.get('user_group_uuid')
    if  group_uuid is not None:
        if is_user_in_group(token, group_uuid):
            try:
                grp_info = entity.get_group_by_identifier(group_uuid)
            except ValueError as ve:
                return Response("Unauthorized: Cannot find information on group:" + str(group_uuid), 401)
            if grp_info['generateuuid'] == False:
                return Response(f"Unauthorized: This group {grp_info} is not a group with write privileges.", 401)
        else:
            return Response("Unauthorized: Current user is not a member of group: " + str(group_uuid), 401)
    group_uuid = (next(g for g in entity.get_user_groups(token) 
                      if g['generateuuid']) 
                 if group_uuid is None 
                 else group_uuid)
    if group_uuid is None:
        return Response("Unauthorized: Current user is not a member of a group allowed to create new specimens", 401)
    data['group_uuid'] = group_uuid
    # 3. create donor
    file_list = []
    try:
        directory = f'{globus_id}/{form_id}'
        for filename in os.listdir(pathlib.Path(directory)):
            file_list.append(os.path.join(directory, filename))
    except FileNotFoundError:
        pass
    conn = Neo4jConnection(app.config['NEO4J_SERVER'],
                            app.config['NEO4J_USERNAME'],
                            app.config['NEO4J_PASSWORD'])
    driver = conn.get_driver()
    record = specimen.create_specimen(driver, request,
                            data, file_list, token, 
                            data.get('group_uuid'), None, 1)

    conn.close()
    # 4. delete temporary files
    if os.path.exists(globus_id):
        shutil.rmtree(globus_id)
    uuid = record.get('new_samples')[0].get('uuid')
    # 5. reindex is done on entity-api
    try:
        #reindex this node in elasticsearch
        rspn = requests.put(app.config['SEARCH_WEBSERVICE_URL'] +
                            "/reindex/" +
                            uuid,
                            headers={'Authorization': 'Bearer '+token})
    except Exception:
        print("Error happened when calling reindex web service")
    # 6. reurn 201
    return jsonify(record), 201

@app.route('/donor/<uuid>', methods=['PUT'])
@secured(groups="HuBMAP-read")
def update_donor(uuid):
    data = request.get_json()
    token = str(request.headers["AUTHORIZATION"])[7:]
    userinfo = authcache.getUserInfo(token, True)
    globus_id = userinfo.get('sub')    

    form_id = data.get('form_id')
    new_metadatas = data.get('new_metadatas')
    deleted_metadatas = data.get('deleted_metadatas')
    new_images = data.get('new_images')
    deleted_images = data.get('deleted_images')

    specimen = Specimen(app.config)
    entity = Entity(app.config['APP_CLIENT_ID'],
                    app.config['APP_CLIENT_SECRET'],
                    app.config['UUID_WEBSERVICE_URL'])
    # 1. get the group uuid
    group_uuid = None
    if 'user_group_uuid' in data:
        if is_user_in_group(token, data['user_group_uuid']):
            group_uuid = data['user_group_uuid']
        else:
            return Response('Unauthorized: Current user is not a member of group: ' + str(group_uuid), 401) 
    data['group_uuid'] = group_uuid
    try:
        conn = Neo4jConnection(app.config['NEO4J_SERVER'],
                            app.config['NEO4J_USERNAME'],
                            app.config['NEO4J_PASSWORD'])
        driver = conn.get_driver()
        file_list = []
        try:
            directory = f'{globus_id}/{form_id}'
            for filename in os.listdir(pathlib.Path(directory)):
                file_list.append(os.path.join(directory, filename))
        except FileNotFoundError:
            pass
        new_uuid_record = specimen.update_specimen(
                driver, uuid, request, data, file_list, token, group_uuid)
        conn.close()

        if os.path.exists(globus_id):
            shutil.rmtree(globus_id)
        try:
            #reindex this node in elasticsearch
            rspn = requests.put(app.config['SEARCH_WEBSERVICE_URL'] + "/reindex/" + new_uuid_record, headers={'Authorization': request.headers["AUTHORIZATION"]})
        except:
            print("Error happend when calling reindex web service")
        return jsonify({'uuid': uuid}), 200 

    except AuthError as e:
        print(e)
        return Response('token is invalid', 401)
    except:
        msg = 'An error occurred: '
        for x in sys.exc_info():
            msg += str(x)
        abort(400, msg)
    finally:
        if conn != None:
            if conn.get_driver().closed() == False:
                conn.close()

@app.route('/sample', methods=['POST'])
@secured(groups="HuBMAP-read")
def create_sample():
    data = request.get_json()
    token = str(request.headers["AUTHORIZATION"])[7:]
    userinfo = authcache.getUserInfo(token, True)
    globus_id = userinfo.get('sub')
    form_id = data.get('form_id')

    specimen = Specimen(app.config)
    entity = Entity(app.config['APP_CLIENT_ID'],
                    app.config['APP_CLIENT_SECRET'],
                    app.config['UUID_WEBSERVICE_URL'])
    # 1. get the group uuid
    group_uuid = data.get('user_group_uuid')
    if  group_uuid is not None:
        if is_user_in_group(token, group_uuid):
            try:
                grp_info = entity.get_group_by_identifier(group_uuid)
            except ValueError as ve:
                return Response("Unauthorized: Cannot find information on group: " + str(group_uuid), 401)
            if grp_info['generateuuid'] == False:
                return Response(f"Unauthorized: This group {grp_info} is not a group with write privileges.", 401)
        else:
            return Response("Unauthorized: Current user is not a member of group: " + str(group_uuid), 401)
    group_uuid = (next(g for g in entity.get_user_groups(token) 
                      if g['generateuuid']) 
                 if group_uuid is None 
                 else group_uuid)
    if group_uuid is None:
        return Response("Unauthorized: Current user is not a member of a group allowed to create new specimens", 401)
    data['group_uuid'] = group_uuid
    # 3. create sample
    file_list = []
    try:
        directory = f'{globus_id}/{form_id}'
        for filename in os.listdir(pathlib.Path(directory)):
            file_list.append(os.path.join(directory, filename))
    except FileNotFoundError:
        pass
    conn = Neo4jConnection(app.config['NEO4J_SERVER'],
                            app.config['NEO4J_USERNAME'],
                            app.config['NEO4J_PASSWORD'])
    driver = conn.get_driver()
    record = specimen.create_specimen(driver, request,
                            data, file_list, token, 
                            data.get('group_uuid'), None, 1)

    conn.close()
    # 4. delete temporary files
    if os.path.exists(globus_id):
        shutil.rmtree(globus_id)
    uuid = record.get('new_samples')[0].get('uuid')
    # 5. reindex is done on entity-api
    try:
        #reindex this node in elasticsearch
        rspn = requests.put(app.config['SEARCH_WEBSERVICE_URL'] +
                            "/reindex/" +
                            uuid,
                            headers={'Authorization': 'Bearer '+token})
    except Exception:
        print("Error happened when calling reindex web service")
    # 6. reurn 201
    return jsonify(record), 201

@app.route('/sample/<uuid>', methods=['PUT'])
@secured(groups="HuBMAP-read")
def update_sample(uuid):
    data = request.get_json()
    token = str(request.headers["AUTHORIZATION"])[7:]
    userinfo = authcache.getUserInfo(token, True)
    globus_id = userinfo.get('sub')    

    form_id = data.get('form_id')
    new_metadatas = data.get('new_metadatas')
    deleted_metadatas = data.get('deleted_metadatas')
    new_images = data.get('new_images')
    deleted_images = data.get('deleted_images')

    specimen = Specimen(app.config)
    entity = Entity(app.config['APP_CLIENT_ID'],
                    app.config['APP_CLIENT_SECRET'],
                    app.config['UUID_WEBSERVICE_URL'])
    # 1. get the group uuid
    group_uuid = None
    if 'user_group_uuid' in data:
        if is_user_in_group(token, data['user_group_uuid']):
            group_uuid = data['user_group_uuid']
        else:
            return Response('Unauthorized: Current user is not a member of group: ' + str(group_uuid), 401) 
    data['group_uuid'] = group_uuid
    try:
        conn = Neo4jConnection(app.config['NEO4J_SERVER'],
                            app.config['NEO4J_USERNAME'],
                            app.config['NEO4J_PASSWORD'])
        driver = conn.get_driver()
        file_list = []
        try:
            directory = f'{globus_id}/{form_id}'
            for filename in os.listdir(pathlib.Path(directory)):
                file_list.append(os.path.join(directory, filename))
        except FileNotFoundError:
            pass
        new_uuid_record = specimen.update_specimen(
                driver, uuid, request, data, file_list, token, group_uuid)
        conn.close()

        if os.path.exists(globus_id):
            shutil.rmtree(globus_id)
        try:
            #reindex this node in elasticsearch
            rspn = requests.put(app.config['SEARCH_WEBSERVICE_URL'] + "/reindex/" + new_uuid_record, headers={'Authorization': request.headers["AUTHORIZATION"]})
        except:
            print("Error happend when calling reindex web service")
        return jsonify({'uuid': uuid}), 200 

    except AuthError as e:
        print(e)
        return Response('token is invalid', 401)
    except:
        msg = 'An error occurred: '
        for x in sys.exc_info():
            msg += str(x)
        abort(400, msg)
    finally:
        if conn != None:
            if conn.get_driver().closed() == False:
                conn.close()
'''

#given a hubmap uuid and a valid Globus token returns, as json the attribute has_write_priv with
#value true if the user has write access to the entity.
#   has_write_priv- denotes if user has write permission for a given entity
#                   true if a user is a member of the group that the entity is a member of or
#                   the user is a member of the Data Admin group, except in the case where
#                   the entity is public or has been published, in which case no one can write
#  has_submit_priv- denotes if a user has permission to submit a dataset.
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
        conn = Neo4jConnection(app.config['NEO4J_SERVER'], app.config['NEO4J_USERNAME'], app.config['NEO4J_PASSWORD'])
        driver = conn.get_driver()
        with driver.session() as session:
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
                    user_info = authcache.getUserInfo(token, True)
                    if user_info is None:
                        return Response("Unable to obtain user information for auth token", 401)
                    if not 'hmgroupids' in user_info:
                        return Response(json.dumps(r_val), 200, mimetype='application/json')
                    group_uuid = record.get('e.group_uuid', '').strip()
                    data_access_level = record.get('e.data_access_level', '').strip().lower()
                    status = record.get('e.status', '').strip().lower()
                    entity_type = record.get('e.entity_type', '').strip().lower()
                    
                    #if it is published, no write allowed
                    if entity_type == 'dataset':
                        if status == 'published':
                            return Response(json.dumps(r_val), 200, mimetype='application/json')
                    #if the entity is public, no write allowed
                    elif entity_type in ['sample', 'donor']:
                        if data_access_level == 'public':
                            return Response(json.dumps(r_val), 200, mimetype='application/json')
                    else:
                        return Response("Invalid data type " + entity_type + ".", 400)

                    #compare the group_uuid in the entity to the users list of groups
                    #if the user is a member of the HuBMAP-Data-Admin group,
                    #they have write access to everything and the ability to submit datasets
                    if data_admin_group_uuid in user_info['hmgroupids']:
                        r_val['has_write_priv'] = True
                        if entity_type == 'dataset':
                            if status == 'new':
                                r_val['has_submit_priv'] = True
                            elif status == 'qa':
                                r_val['has_publish_priv'] = True
                    #if in the users list of groups return true otherwise false
                    elif group_uuid in user_info['hmgroupids']:
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
    finally:
        if conn != None:
            if conn.get_driver().closed() == False:
                conn.close()


# This is for development only
if __name__ == '__main__':
    try:
        parser = argparse.ArgumentParser()
        parser.add_argument("-p", "--port")
        args = parser.parse_args()
        port = 5000
        if args.port:
            port = int(args.port)
        app.run(port=port)
    finally:
        pass
