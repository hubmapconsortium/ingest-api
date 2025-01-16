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
            else:
                first_row = rows[0]
                if "metadata_schema_id" not in first_row:
                    message = {"metadata_schema_id not found in header": f"{path}"}
                    raise TSVError(message)
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
        


