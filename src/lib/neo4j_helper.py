from typing import Iterable, List, Optional, Union
from neo4j import Driver, Record

neo4j_driver_instance = None


class Neo4jHelper:
    @staticmethod
    def set_instance(neo4j):
        global neo4j_driver_instance
        neo4j_driver_instance = neo4j

    @staticmethod
    def get_instance():
        global neo4j_driver_instance
        return neo4j_driver_instance

    @staticmethod
    def close():
        # Specify as module-scope variable
        global neo4j_driver_instance

        if isinstance(neo4j_driver_instance, Driver):
            neo4j_driver_instance.close()
            neo4j_driver_instance = None
        else:
            raise TypeError(
                "The private module variable '_driver' is not a neo4j.Driver object"
            )

    @staticmethod
    def run_query(query, as_dict: bool = False, **kwargs) -> List[Record]:
        if not isinstance(neo4j_driver_instance, Driver):
            raise TypeError(
                "The private module variable '_driver' is not a neo4j.Driver object"
            )

        with neo4j_driver_instance.session() as session:
            result = session.run(query, **kwargs)
            if as_dict:
                return result.data()
            return [Record(record) for record in result]

    @staticmethod
    def get_entities_by_uuid(uuids: Union[str, Iterable], fields: Union[dict, Iterable, None] = None) -> Optional[list]:
        """Get the entities from the neo4j database with the given uuids.

        Parameters
        ----------
        uuids : Union[str, Iterable]
            The uuid(s) of the entities to get.
        fields : Union[dict, Iterable, None], optional
            The fields to return for each entity. If None, all fields are returned.
            If a dict, the keys are the database fields to return and the values are the names to return them as.
            If an iterable, the fields to return. Defaults to None.

        Returns
        -------
        Optional[List[neo4j.Record]]:
            The entity records with the given uuids, or None if no datasets were found.
            The specified fields are returned for each entity.

        Raises
        ------
        TypeError
            If the neo4j.Driver object is not set.
        ValueError
            If fields is not a dict, an iterable, or None.
        """
        if not isinstance(neo4j_driver_instance, Driver):
            raise TypeError(
                "The private module variable '_driver' is not a neo4j.Driver object"
            )
        if isinstance(uuids, str):
            uuids = [uuids]
        if not isinstance(uuids, list):
            uuids = list(uuids)

        if fields is None or len(fields) == 0:
            return_stmt = 'e'
        elif isinstance(fields, dict):
            return_stmt = ', '.join([f'e.{field} AS {name}' for field, name in fields.items()])
        elif isinstance(fields, Iterable):
            return_stmt = ', '.join([f'e.{field} AS {field}' for field in fields])
        else:
            raise ValueError("fields must be a dict or an iterable")

        with neo4j_driver_instance.session() as session:
            length = len(uuids)
            query = "MATCH (e:Entity) WHERE e.uuid IN $uuids RETURN " + return_stmt
            records = session.run(query, uuids=uuids).fetch(length)
            if records is None or len(records) == 0:
                return None

            return records
