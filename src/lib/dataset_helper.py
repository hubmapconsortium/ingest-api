import json
import logging
import os
import sys
from collections.abc import Iterable
from pathlib import Path
from shutil import copy2
from typing import Optional, Union

import requests
from flask import Response, jsonify
from hubmap_commons import neo4j_driver
from hubmap_commons.exceptions import HTTPException
from hubmap_commons.hm_auth import AuthHelper

# Local modules
from hubmap_commons.hubmap_const import HubmapConst
from hubmap_sdk import EntitySdk

from lib.file_upload_helper import UploadFileHelper
from lib.ingest_file_helper import IngestFileHelper


class DatasetHelper:
    def __init__(self, config):
        self.appconfig = config
        self.logger = logging.getLogger('ingest.service')
        self.auth_helper_instance = AuthHelper.configured_instance(config['APP_CLIENT_ID'], config['APP_CLIENT_SECRET'])
        self.ingest_helper = IngestFileHelper(config)

        # The new neo4j_driver (from commons package) is a singleton module
        # This neo4j_driver_instance will be used for application-specifc neo4j queries
        # as well as being passed to the schema_manager
        try:
            self.neo4j_driver_instance = neo4j_driver.instance(self.appconfig['NEO4J_SERVER'],
                                                               self.appconfig['NEO4J_USERNAME'],
                                                               self.appconfig['NEO4J_PASSWORD'])

            self.logger.info("Initialized neo4j_driver module successfully :)")
        except Exception:
            msg = "Failed to initialize the neo4j_driver module"
            # Log the full stack trace, prepend a line with our message
            self.logger.exception(msg)

    def get_group_uuid_by_dataset_uuid(self, uuid):
        with self.neo4j_driver_instance.session() as session:
            # query Neo4j db to get the group_uuid
            stmt = "match (d:Dataset {uuid:'" + uuid.strip() + "'}) return d.group_uuid as group_uuid"
            records = session.run(stmt)
            # this assumes there is only one result returned, but we use the for loop
            # here because standard list (len, [idx]) operators don't work with
            # the neo4j record list object
            count = 0
            group_uuid = None
            for record in records:
                count = count + 1
                group_uuid = record.get('group_uuid', None)
                if group_uuid is None:
                    return Response(f"Unable to process submit.  group_uuid not found on entity:{uuid}", 400)
            if count == 0:
                return Response(f"Dataset with uuid:{uuid} not found.", 404)
            return group_uuid

    def get_datasets_by_uuid(self, uuids: Union[str, Iterable], fields: Union[dict, Iterable, None] = None) -> Optional[list]:
        """Get the datasets from the neo4j database with the given uuids.

        Parameters
        ----------
        uuids : Union[str, Iterable]
            The uuid(s) of the datasets to get.
        fields : Union[dict, Iterable, None], optional
            The fields to return for each dataset. If None, all fields are returned.
            If a dict, the keys are the database fields to return and the values are the names to return them as.
            If an iterable, the fields to return. Defaults to None.

        Returns
        -------
        Optional[List[neo4j.Record]]:
            The dataset records with the given uuids, or None if no datasets were found.
            The specified fields are returned for each dataset.

        Raises
        ------
        ValueError
            If fields is not a dict, an iterable, or None.
        """

        if isinstance(uuids, str):
            uuids = [uuids]
        if not isinstance(uuids, list):
            uuids = list(uuids)

        if fields is None or len(fields) == 0:
            return_stmt = 'd'
        elif isinstance(fields, dict):
            return_stmt = ', '.join([f'd.{field} AS {name}' for field, name in fields.items()])
        elif isinstance(fields, Iterable):
            return_stmt = ', '.join([f'd.{field} AS {field}' for field in fields])
        else:
            raise ValueError("fields must be a dict or an iterable")

        with self.neo4j_driver_instance.session() as session:
            length = len(uuids)
            query = (
                "MATCH (d:Dataset) WHERE d.uuid IN $uuids AND d.entity_type = 'Dataset' "
                "RETURN " + return_stmt
            )
            records = session.run(query, uuids=uuids).fetch(length)
            if records is None or len(records) == 0:
                return None

            return records

    def set_dataset_status(self, uuids: Union[str, Iterable], status: str) -> Optional[list]:
        """Set the status of the datasets with the given uuids in the neo4j database.

        Parameters
        ----------
        uuids : Union[str, Iterable]
            The uuid(s) of the datasets to set the status of.
        status : str
            The status to set for the datasets.

        Returns
        -------
        Optional[List[neo4j.Record]]:
            The dataset records with the given uuids, or None if no datasets were found.
            Each record contains the 'uuid' of the dataset.
        """

        if not isinstance(uuids, list):
            uuids = list(uuids)

        with self.neo4j_driver_instance.session() as session:
            length = len(uuids)
            query = (
                "MATCH (d:Dataset) WHERE d.uuid IN $uuids AND d.entity_type = 'Dataset' "
                "SET d.status = $status RETURN d.uuid AS uuid"
            )
            records = session.run(query, uuids=uuids, status=status).fetch(length)
            if records is None or len(records) == 0:
                return None

            return records

    def update_ingest_status_title_thumbnail(self, app_config: object, request_json: object,
                                             request_headers: object, entity_api: EntitySdk,
                                             file_upload_helper_instance: UploadFileHelper) -> object:
        dataset_uuid = request_json['dataset_id'].strip()

        # Headers for calling entity-api via PUT to update Dataset.status
        extra_headers = {
            'Content-Type': 'application/json',
            'X-SenNet-Application': 'ingest-api'
        }

        # updated_ds is the dict returned by ingest-pipeline, not the complete entity information
        # Note: 'dataset_id' is in request_json but not in the resulting updated_ds
        # request_json['thumbnail_file_abs_path'] is converted to updated_ds['ingest_metadata']['thumbnail_file_abs_path']
        updated_ds = self.get_dataset_ingest_update_record(request_json)

        self.logger.debug('=======get_dataset_ingest_update_record=======')
        self.logger.debug(updated_ds)

        # For thumbnail image handling if ingest-pipeline finds the file
        # and sends the absolute file path back
        try:
            thumbnail_file_abs_path = updated_ds['ingest_metadata']['thumbnail_file_abs_path']

            self.logger.debug("=======thumbnail_file_abs_path found=======")

            # Generate a temp file id and copy the source file to the temp upload dir
            temp_file_id = file_upload_helper_instance.get_temp_file_id()
            file_upload_temp_dir = file_upload_helper_instance.upload_temp_dir

            try:
                self.handle_thumbnail_file(thumbnail_file_abs_path,
                                                     entity_api,
                                                     dataset_uuid,
                                                     extra_headers,
                                                     temp_file_id,
                                                     file_upload_temp_dir)

                # Now add the thumbnail file by making a call to entity-api
                # And the entity-api will execute the trigger method defined
                # for the property 'thumbnail_file_to_add' to commit this
                # file via ingest-api's /file-commit endpoint, which treats
                # the temp file as uploaded file and moves it to the generated file_uuid
                # dir under the upload dir: /hive/hubmap/hm_uploads/<file_uuid> (for PROD)
                # and also creates the symbolic link to the assets
                updated_ds['thumbnail_file_to_add'] = {
                    'temp_file_id': temp_file_id
                }
            except requests.exceptions.RequestException as e:
                msg = e.response.text
                self.logger.exception(msg)

                # Due to the use of response.raise_for_status() in schema_manager.create_hubmap_ids()
                # we can access the status codes from the exception
                return Response(msg, e.response.status_code)
        except KeyError:
            self.logger.info(f"No existing thumbnail file found for the dataset uuid {dataset_uuid}")
            pass

        # Applying extra headers once more in case an exception occurs in handle_thumbnail_file and its is not changed
        entity_api.header.update(extra_headers)
        try:
            entity = entity_api.update_entity(dataset_uuid, updated_ds)
        except HTTPException as e:
            err_msg = f"Error while updating the dataset status using EntitySdk.update_entity() status code: {e.status_code} message: {e.description}"
            self.logger.error(err_msg)
            self.logger.error("Sent: " + json.dumps(updated_ds))
            return Response(e.description, e.status_code)

        # The PUT call returns the latest dataset...
        lastest_dataset = entity

        self.logger.debug('=======lastest_dataset before title update=======')
        self.logger.debug(lastest_dataset)

        # By this point, the response code can only be 200
        return jsonify({'result': lastest_dataset}), 200

    def handle_thumbnail_file(self, thumbnail_file_abs_path: str, entity_api: EntitySdk, dataset_uuid: str,
                              extra_headers: dict, temp_file_id: str, file_upload_temp_dir: str):
        # Delete the old thumbnail file from Neo4j before updating with new one
        # First retrieve the exisiting thumbnail file uuid
        try:
            entity = entity_api.get_entity_by_id(dataset_uuid)
        # All exceptions that occur in EntitySdk are HTTPExceptions
        except HTTPException as e:
            err_msg = f"Failed to query the dataset of uuid {dataset_uuid} while calling EntitySdk.get_entities() status code:{e.status_code}  message:{e.description}"
            self.logger.error(err_msg)
            # Bubble up the error message
            raise requests.exceptions.RequestException(err_msg)

        entity_dict = vars(entity)

        self.logger.debug('=======EntitySdk.get_entity_by_id() resulting entity_dict=======')
        self.logger.debug(entity_dict)

        # Easier to ask for forgiveness than permission (EAFP)
        # Rather than checking key existence at every level
        try:
            thumbnail_file_uuid = entity_dict['thumbnail_file']['file_uuid']

            # To remove the existing thumbnail file, just pass the file uuid as a string
            put_data = {
                'thumbnail_file_to_remove': thumbnail_file_uuid
            }
            entity_api.header.update(extra_headers)
            try:
                entity = entity_api.update_entity(dataset_uuid, put_data)
            # All exceptions that occur in EntitySdk are HTTPExceptions
            except HTTPException as e:
                err_msg = f"Failed to remove the existing thumbnail file for dataset of uuid {dataset_uuid} while calling EntitySdk.put_entities() status code:{e.status_code}  message:{e.description}"
                self.logger.error(err_msg)
                # Bubble up the error message
                raise requests.exceptions.RequestException(err_msg)

            self.logger.info(f"Successfully removed the existing thumbnail file of the dataset uuid {dataset_uuid}")
        except KeyError:
            self.logger.info(f"No existing thumbnail file found for the dataset uuid {dataset_uuid}")
            pass

        entity_dict = vars(entity)

        self.logger.debug('=======EntitySdk.update_entity() resulting entity_dict=======')
        self.logger.debug(entity_dict)

        # Create the temp file dir under the temp uploads for the thumbnail
        # /hive/hubmap/hm_uploads_tmp/<temp_file_id> (for PROD)
        temp_file_dir = os.path.join(file_upload_temp_dir, temp_file_id)

        try:
            Path(temp_file_dir).mkdir(parents=True, exist_ok=True)
        except Exception as e:
            self.logger.exception(
                f"Failed to create the thumbnail temp upload dir {temp_file_dir} for thumbnail file attched to Dataset {dataset_uuid}")

        # Then copy the source thumbnail file to the temp file dir
        # shutil.copy2 is identical to shutil.copy() method
        # but it also try to preserves the file's metadata
        copy2(thumbnail_file_abs_path, temp_file_dir)

    def get_dataset_ingest_update_record(self, json_data):
        """ expect something like this:
        #{'dataset_id' : '4d3eb2a87cda705bde38495bb564c8dc', 'status': '<status>', 'message': 'the process ran', 'metadata': [maybe some metadata stuff], 'thumbnail_file_abs_path': 'full file path'}
        files: [{ "relativePath" : "/path/to/file/example.txt",
           "type":"filetype",
           "size":filesize,
           "checksum":"file-checksum"
         }]
         """

        if 'dataset_id' not in json_data:
            raise ValueError('cannot find dataset_id')

        # Note: `dataset_id` is not being returned!
        update_record = {}

        if 'status' not in json_data:
            raise ValueError('cannot find status')
        if json_data['status'] not in HubmapConst.DATASET_STATUS_OPTIONS:
            raise ValueError('"' + json_data['status'] + '" is not a valid status')
        update_record['status'] = json_data['status']

        # if 'files' in json_data:
        #    file_data = json_data['files']
        #    update_record[HubmapConst.DATASET_INGEST_FILE_LIST_ATTRIBUTE] = file_data
        if 'message' not in json_data:
            raise ValueError('cannot find "message" parameter')
        update_record['pipeline_message'] = json_data['message']
        update_status = update_record['status'].lower().strip()
        if update_status == 'error' or update_status == 'invalid' or update_status == 'new':
            return update_record
        metadata = None
        if not 'metadata' in json_data:
            raise ValueError('top level metadata field required')

        metadata = json_data['metadata']
        if 'files_info_alt_path' in metadata:
            metadata['files'] = self.get_file_list(metadata['files_info_alt_path'])

        if 'overwrite_metadata' in json_data and json_data['overwrite_metadata'] == False:
            raise ValueError("overwrite_metadata set to False, merging of metadata is not supported on update")

        # we can get the antibodies or contributors fields at multiple levels
        # find them and move them to the top
        antibodies = None
        contributors = None
        if 'antibodies' in json_data:
            antibodies = json_data['antibodies']
        if 'contributors' in json_data:
            contributors = json_data['contributors']

        if 'metadata' in metadata:
            meta_lvl2 = metadata['metadata']
            if 'antibodies' in meta_lvl2:
                if antibodies is None:
                    antibodies = meta_lvl2['antibodies']
                    meta_lvl2.pop('antibodies')
                else:
                    raise ValueError('antibodies array included twice in request data')
            if 'contributors' in meta_lvl2:
                if contributors is None:
                    contributors = meta_lvl2['contributors']
                    meta_lvl2.pop('contributors')
                else:
                    raise ValueError('contributors array included twice in request data')
            if 'metadata' in meta_lvl2:
                meta_lvl3 = meta_lvl2['metadata']
                if 'antibodies' in meta_lvl3:
                    if antibodies is None:
                        antibodies = meta_lvl3['antibodies']
                        meta_lvl3.pop('antibodies')
                    else:
                        raise ValueError('antibodies array included twice in request data')
                if 'contributors' in meta_lvl3:
                    if contributors is None:
                        contributors = meta_lvl3['contributors']
                        meta_lvl3.pop('contributors')
                    else:
                        raise ValueError('contributors array included twice in request data')

                # while we're here if we have that second level of metadata, move it up one level
                # but first save anything else at the same level an put it in
                # an attribute named 'extra_metadata"
                extra_meta = {}
                for key in meta_lvl2.keys():
                    if not key == 'metadata':
                        extra_meta[key] = meta_lvl2[key]
                if extra_meta:
                    metadata['extra_metadata'] = extra_meta

                metadata['metadata'] = meta_lvl3

        update_record[HubmapConst.DATASET_INGEST_METADATA_ATTRIBUTE] = metadata

        if not antibodies is None:
            update_record['antibodies'] = antibodies
        if not contributors is None:
            update_record['contributors'] = contributors
            contacts = []
            for contrib in contributors:
                if 'is_contact' in contrib:
                    v = contrib['is_contact']
                    if self.__is_true(val=v):
                        contacts.append(contrib)
            if len(contacts) > 0:
                update_record['contacts'] = contacts

        # For thumbnail image handling
        if 'thumbnail_file_abs_path' in json_data:
            update_record['thumbnail_file_abs_path'] = json_data['thumbnail_file_abs_path']

        return update_record

    def __is_true(self, val):
        if val is None: return False
        if isinstance(val, str):
            uval = val.upper().strip()
            if uval in ['TRUE', 'T', '1', 'Y', 'YES']:
                return True
            else:
                return False
        elif isinstance(val, int) and val == 1:
            return True
        else:
            return False

    def get_file_list(self, orig_file_path):
        f = None
        try:
            # join the incoming file path with the WORKFLOW_SCRATCH location
            file_path = os.path.join(self.appconfig['WORKFLOW_SCRATCH'], orig_file_path)
            with open(file_path) as f:
                data = json.load(f)
                if 'files' in data:
                    return data['files']
                else:
                    raise ValueError('Cannot find the \'files\' attribute in: ' + file_path)
        except json.JSONDecodeError as jde:
            print('Cannot decode JSON in file: ' + file_path)
            raise
        except FileNotFoundError as fnfe:
            print('Cannot find file: ' + file_path)
            raise
        except PermissionError as pe:
            print('Cannot access file: ' + file_path)
            raise
        except:
            print('A general error occurred: ', sys.exc_info()[0])
            raise
        finally:
            if f != None:
                f.close()

    # Determines if a dataset is Primary. If the list returned from the neo4j query is empty, the dataset is not primary
    def dataset_is_primary(self, dataset_uuid):
        with self.neo4j_driver_instance.session() as neo_session:
            q = (
                f"MATCH (ds:Dataset {{uuid: '{dataset_uuid}'}})-[:WAS_GENERATED_BY]->(:Activity)-[:USED]->(s:Sample) RETURN ds.uuid")
            result = neo_session.run(q).data()
            if len(result) == 0:
                return False
            return True

    def create_ingest_payload(self, dataset):
        provider = self.auth_helper_instance.getGroupDisplayName(group_uuid=dataset['group_uuid'])
        full_path = self.ingest_helper.get_dataset_directory_absolute_path(dataset, dataset['group_uuid'], dataset['uuid'])
        return {
            "submission_id": f"{dataset['uuid']}",
            "process": "SCAN.AND.BEGIN.PROCESSING",
            "full_path": full_path,
            "provider": provider,
        }
