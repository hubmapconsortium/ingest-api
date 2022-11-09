import time
from flask import jsonify
import sys
import os
import requests
import threading
import time
import traceback
sys.path.append(os.path.join(os.path.dirname(__file__), '../src/'))
from ingest_file_helper import IngestFileHelper
from flask import Flask, request, json, Response
from hubmap_commons import file_helper as commons_file_helper
ip = os.path.dirname(__file__)
app = Flask(__name__, instance_path=os.path.join(os.path.abspath(os.path.dirname(__file__))), instance_relative_config=True)
#use the ingest-api config
app.config.from_pyfile('../src/instance/app.cfg')

# Default endpoint for testing with gateway
@app.route('/', methods = ['GET'])
def index():
    return "Hello! This is HuBMAP Mock Service.  Use for testing and local development purposes only."

@app.route('/api/hubmap/uploads/<upload_uuid>/validate', methods = ['PUT'])
def upload_validate(upload_uuid):
    ingest_helper = IngestFileHelper(app.config)
    url = commons_file_helper.ensureTrailingSlashURL(app.config['ENTITY_WEBSERVICE_URL']) + 'entities/' + upload_uuid
    auth_headers = {'Authorization': request.headers["AUTHORIZATION"], 'X-Hubmap-Application':'ingest-api' } 
    resp = requests.get(url, headers=auth_headers)
    if resp.status_code >= 300:
        return Response(resp.text, resp.status_code)
    upload = resp.json()
    prev_status = upload['status']
    upload_path = ingest_helper.get_upload_directory_absolute_path(None, upload['group_uuid'], upload_uuid)
    if not os.path.exists(upload_path):
        return Response(f"upload directory does not exist: {upload_path}", 500)
    mock_cfg_path = commons_file_helper.ensureTrailingSlash(upload_path) + "mock_run.json"
    if not os.path.exists(mock_cfg_path):
        return Response(f"mock configuration json file does not exist: {mock_cfg_path}")
    
    ''' Example mock_run.json
    {
      "mock_processing_time_seconds": 20,
      "new_status_message": "new message",
      "new_status": "Invalid"
    }
    '''
    #read the mock_run json file into a dict
    with open(mock_cfg_path) as json_file:
        mock_run = json.load(json_file)
    
    x = threading.Thread(target=__apply_mock_run, args=[mock_run, upload_path, upload_uuid, auth_headers, prev_status])
    x.start()
    
    return Response("Accepted", 202)

@app.route('/api/hubmap/request_ingest', methods = ['POST'])
def request_ingest():
    time.sleep(10)
    return Response("Good", 200)

def __apply_mock_run(mock_run_data, upload_path, upload_uuid, auth_headers, prev_status):
    try:
        wait_seconds = mock_run_data['mock_processing_time_seconds']
        update_rcd = {'status': prev_status}
        if 'new_status' in mock_run_data:
            update_rcd['status'] = mock_run_data['new_status']
        if 'new_status_message' in mock_run_data:
            update_rcd['validation_message'] = mock_run_data['new_status_message']
        update_url = commons_file_helper.ensureTrailingSlashURL(app.config['ENTITY_WEBSERVICE_URL']) + 'entities/' + upload_uuid
        
        time.sleep(wait_seconds)
        resp = requests.put(update_url, json=update_rcd, headers=auth_headers)
        if resp.status_code >= 300:
            print(f"ERROR calling Upload update method received status: {resp.status_code} with message: {resp.text}")
        
        
    except Exception as e:
        print (f"Exception while applying mock run for Upload: {upload_uuid}")
        traceback.print_exc()
        
# This is for development only
if __name__ == '__main__':
    try:
        port = 8000
        app.run(port=port, host='0.0.0.0')
    finally:
        pass
