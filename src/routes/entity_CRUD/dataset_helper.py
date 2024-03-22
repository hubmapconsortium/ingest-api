from collections.abc import Iterable
from typing import Optional, Union


class DatasetHelper:

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
            records = session.run(query, uuids=uuids).fetch(length)
            if records is None or len(records) == 0:
                return None

            return records
