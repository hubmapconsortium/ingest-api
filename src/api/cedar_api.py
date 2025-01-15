import requests
from requests.auth import HTTPBasicAuth
from flask import Flask, current_app, request, json, Response
import logging

logger = logging.getLogger(__name__)


# DataCite REST API Guide:
# https://support.datacite.org/reference/dois-2
class CEDARApi: # @MAX Best Practice when the Noun of the API (or other caps acro) is also caps? 


    def __init__(self):
        # SWITCH TO ENV VARS
        # hubmap_APIkey = "a92e621d1ced5925cbaa0c823a85f13492f86f57e78523035b51f3205eada386"
        hubmap_APIkey = current_app.config['CEDAR_API_KEY'] 
        self.auth = HTTPBasicAuth('apiKey', hubmap_APIkey)            
        self.ssl_verification_enabed = False # @MAX Needed
        
        
    # Schema Versions Retrieval
    # curl -X GET --header 'Accept: application/json' --header  'Authorization: apiKey a92e621d1ced5925cbaa0c823a85f13492f86f57e78523035b51f3205eada386' 'https://resource.metadatacenter.org/templates/https%3A%2F%2Frepo.metadatacenter.org%2Ftemplates%2F [94dae6f8-0756-4ab0-a47b-138e446a9501 ]/versions'

    def get_schema_details(self, schema_id: str) -> object:
        logger.debug(f"======get_schema_details: {schema_id}======")
        cedar_api_url = "https://resource.metadatacenter.org/templates/"
        cedar_repo_url = "https%3A%2F%2Frepo.metadatacenter.org%2Ftemplates%2F"+schema_id
        cedar_versions_url = cedar_api_url+cedar_repo_url+"/versions"
        response = requests.get(
            url=f"{cedar_versions_url}",
            headers={
                'Accept': 'application/json',
                'Authorization': 'apiKey '+current_app.config['CEDAR_API_KEY'],
                },
            verify=self.ssl_verification_enabed
        )
        response_JSON = response.json()
        return response.json()
    
        # return Response(response.text, response.status_code)
        # return response

    # # @MAX: Best practice: Should I limit this to ONLY the Calls going in and out, and meddle with
    # # the data in the main code? Or is it ok to have some pre-processing here?
    # def get_schema_versions(self, schema_id: str) -> object:
    #     logger.debug(f"======get_schema_versions: {schema_id}======")

    #     schema_details = get_schema_details(schema_id)
        
    #     return response

class CEDARApiException(Exception):
    
    def __init__(self, message, error_code=None):
        super().__init__(message)
        self.error_code = error_code