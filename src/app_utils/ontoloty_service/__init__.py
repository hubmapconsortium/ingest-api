from typing import List
from neo4j import GraphDatabase


class OntologyService:

    def __init__(self, uri, user, password):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self):
        self.driver.close()

    def get_lab_processed_data_types(self) -> List[str]:
        query: str = "MATCH (c:Code {CodeID:'HUBMAP C004007'})<-[:CODE]-(p:Concept)-[:inverse_provided_by]->" \
                     "(p2:Concept)-[:has_data_type]->(p3:Concept)-[:PREF_TERM]-(tlab)" \
                     " RETURN tlab.name AS lab_processed_data_types"
        with self.driver.session() as session:
            resp = session.run(query)
            data: List[dict] = resp.data()
            return [e['lab_processed_data_types'] for e in data]


if __name__ == "__main__":
    on = OntologyService("bolt://34.234.131.112:7688", "neo4j", "change_this_to_the_real_thing")
    lab_processed_data_types: List[str] = on.get_lab_processed_data_types()
    print(lab_processed_data_types)
    on.close()
