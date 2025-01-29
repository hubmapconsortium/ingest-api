import logging
from pathlib import Path
from flask import Flask, request,jsonify, json, Response
import csv
from api.cedar_api import CEDARApi, CEDARApiException


from hubmap_commons.hubmap_const import HubmapConst

from TSV_helper import TSVError, tsv_reader_wrapper

# Set logging format and level (default is warning)
# All the API logging is forwarded to the uWSGI server and gets written into the log file `uwsgi-ingest-api.log`
# Log rotation is handled via logrotate on the host system with a configuration file
# Do NOT handle log file and rotation via the Python logging to avoid issues with multi-worker processes
logging.basicConfig(format='[%(asctime)s] %(levelname)s in %(module)s: %(message)s', level=logging.DEBUG,
                    datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger(__name__)


class VersionHelper:
    
    #returns the metadata_schema_id of the specified (by path argument) file
    # - if the metadata_schema_id column is not found, returns None
    # - returns the message "File does not exist" with the specified path 
    #   in the case that the specified file does not exist
    # - returns the message "File has no data rows" with the specified path
    #   in the case that the file doesn't contain any rows of tsv data
    # - returns the message "Expected a TSV, but found a directory" with the specified
    #   path for the case that a directory was passed in instead of a file
    # - throws a TSVError exception if the file is not a TSV file
    @staticmethod
    def get_schema_id(path: Path, encoding: str) -> object:
        message = None
        if not Path(path).exists():
            message = {"File does not exist": f"{path}"}
            raise TSVError(message)
        try:
            rows = tsv_reader_wrapper(path, str)
            if not rows:
                message = {"File has no data rows": f"{path}"}
            first_row = rows[0]
            if not 'metadata_schema_id' in first_row:
                return None
            schema_id = first_row['metadata_schema_id']
            return schema_id 
       
        except IsADirectoryError:
            message = {"Expected a TSV, but found a directory": f"{path}"}
            # raise TSVError(message)
        except TSVError as e:
             raise TSVError(e)
        
        
    def get_latest_published_schema(schema_id: str, ) -> object:
        latest_published_schema = ""
        #  API Time
        CEDAR_API = CEDARApi()
        try:
            schema_details = CEDAR_API.get_schema_details(schema_id)
            if 'resources' not in schema_details:
                return jsonify({"error": f"Error occurred while gathering schemas for schema id {schema_id}. {schema_details['errorMessage']}"}), 500
            for schema in schema_details['resources']:
                if schema["isLatestVersion"]:
                    latest_published_schema = schema["@id"].strip("https://repo.metadatacenter.org/templates/")
                break
            return latest_published_schema

        except CEDARApiException as e:
            logger.exception(f"Exception while gathering schemas for schema id {schema_id}. {e}")
            return Response(
                f"Error occurred while gathering schemas for schema id {schema_id}: " + str(e), 500
            )
        


