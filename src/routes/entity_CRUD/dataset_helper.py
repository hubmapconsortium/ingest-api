from collections.abc import Iterable
from typing import Optional, Union
import logging
from hubmap_commons.hm_auth import AuthHelper
from hubmap_commons import neo4j_driver
from routes.entity_CRUD.ingest_file_helper import IngestFileHelper

logger = logging.getLogger(__name__)

class DatasetHelper:
    confdata = {}

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
            logger.info(f"get_datasets_by_uuid: query: {query}")
            result = session.run(query, uuids=uuids)
            records: list = [ dict(i) for i in result ]
            logger.info(f"get_datasets_by_uuid: result.len: {len(records)}; records: {records}")
            # I'm assuming that this works for SenNet, but I am not sure why (driver versions?!).
            # It appears that the neo4j Result object does not have a .fetch(n) method so I returned
            # a list of dictionaries.
            # records = result.fetch(length)
            if records is None or len(records) == 0:
                return None

            return records[:length]

    def create_ingest_payload(self, dataset):
        full_path = self.ingest_helper.get_dataset_directory_absolute_path(dataset, dataset['group_uuid'], dataset['uuid'])
        return {
            "submission_id": f"{dataset['uuid']}",
            "process": "SCAN.AND.BEGIN.PROCESSING",
            "full_path": full_path,
            "provider": f"{dataset['group_name']}"
        }
