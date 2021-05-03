import sys
import os
import requests
sys.path.append(os.path.join(os.path.dirname(__file__), '../src/'))
from ingest_file_helper import IngestFileHelper
from flask import Flask, jsonify, abort, request, session, redirect, json, Response
from hubmap_commons import file_helper as commons_file_helper
ip = os.path.dirname(__file__)
app = Flask(__name__, instance_path=os.path.dirname(__file__), instance_relative_config=True)
#use the ingest-api config
app.config.from_pyfile('../src/instance/app.cfg')

# Default endpoint for testing with gateway
@app.route('/', methods = ['GET'])
def index():
    return "Hello! This is HuBMAP Mock Service.  Use for testing and local development purposes only."

@app.route('/uploads/<upload_uuid>/validate', methods = ['PUT'])
def upload_validate(upload_uuid):
    ingest_helper = IngestFileHelper(app.config)
    url = commons_file_helper.ensureTrailingSlashURL(app.config['ENTITY_WEBSERVICE_URL']) + 'entities/' + upload_uuid
    h = request.headers
    resp = requests.get(url, headers=request.headers)
    if resp.status_code >= 300:
        return Response(resp.text, resp.status_code)
    upload = resp.json()
    upload_path = ingest_helper.get_upload_directory_absolute_path(None, upload['group_uuid'], upload_uuid)
    if not os.path.exists(upload_path):
        return Response(f"upload directory does not exist: {upload_path}", 500)
    mock_cfg_path = commons_file_helper.ensureTrailingSlash(upload_path) + "mock_run.json"
    if not os.path.exists(mock_cfg_path):
        return Response(f"mock configuration json file does not exist: {mock_cfg_path}")
    
    print(upload_path)


# This is for development only
if __name__ == '__main__':
    try:
        port = 8000
        app.run(port=port, host='0.0.0.0')
    finally:
        pass
