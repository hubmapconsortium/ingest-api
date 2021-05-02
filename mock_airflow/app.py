import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '../src/'))
from ingest_file_helper import IngestFileHelper
from flask import Flask, jsonify, abort, request, session, redirect, json, Response

app = Flask(__name__, instance_path=os.path.dirname(__file__)), instance_relative_config=True)
#use the ingest-api config
app.config.from_pyfile('../src/instance/app.cfg')

# Default endpoint for testing with gateway
@app.route('/', methods = ['GET'])
def index():
    return "Hello! This is HuBMAP Mock Service.  Use for testing and local development purposes only."

@app.route('/uploads/<upload_uuid>/validate', methods = ['PUT'])
def upload_validate(upload_uuid):
    ingest_helper = IngestFileHelper(app.config)    
    
