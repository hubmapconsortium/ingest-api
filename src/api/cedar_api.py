import requests
from requests.auth import HTTPBasicAuth
from flask import Flask, current_app, request, json, Response
import logging

logger = logging.getLogger(__name__)

class CEDARApi: 
    
    def __init__(self):
        hubmap_APIkey = current_app.config['CEDAR_API_KEY'] 
        self.auth = HTTPBasicAuth('apiKey', hubmap_APIkey)            
        self.ssl_verification_enabed = False
        
    # Schema Versions Retrieval
    def get_schema_details(self, schema_id: str) -> object:
        logger.debug(f"======get_schema_details: {schema_id}======")
        cedar_versions_url = current_app.config['CEDAR_API_URL']+schema_id+"/versions"
        response = requests.get(
            url=f"{cedar_versions_url}",
            headers={
                'Accept': 'application/json',
                'Authorization': 'apiKey '+current_app.config['CEDAR_API_KEY'],
                },
            verify=self.ssl_verification_enabed
        )
        return response.json()


class CEDARApiException(Exception):
    
    def __init__(self, message, error_code=None):
        super().__init__(message)
        self.error_code = error_code