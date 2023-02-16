from hubmap_commons import neo4j_driver
from hubmap_commons.hm_auth import AuthHelper
from hubmap_sdk import EntitySdk, Dataset
from datacite_doi_helper_object import DataCiteDoiHelper
import re
import logging

logger = logging.getLogger(__name__)


# In coordination with ingest-api task #290, query all data to find all previously published lab derived
# datasets (Dataset.status == 'Published' and Dataset.data_types contains a lab derived data type) and
# generate a DOIs for them. After generating the DOIs for these datasets fill in their doi_url and
# registered_doi fields.

# data_types appears to be a string masquerading as an array of strings
# MATCH (e:Dataset) WHERE e.status = 'Published' AND e.data_types =~ '(?i).*([\'\"]sc_rna_seq_snare_lab[\'\"]|[\'\"]sc_atac_seq_snare_lab[\'\"]|[\'\"]seqFish_lab_processed[\'\"]).*' AND e.doi_url IS NULL RETURN e.data_types, count(*) order by e.data_types
# From Bill:
# match (pds:Dataset)-[:ACTIVITY_INPUT]->(:Activity)-[:ACTIVITY_OUTPUT]->(ds:Dataset) where ds.data_types contains '_lab' return distinct ds.uuid
def generate_doids_for_all_published(neo4j_driver_instance, entity_instance, token) -> None:
    datacite_doi_helper: DataCiteDoiHelper = DataCiteDoiHelper()
    with neo4j_driver_instance.session() as neo_session:
        q = "match (pds:Dataset)-[:ACTIVITY_INPUT]->(:Activity)-[:ACTIVITY_OUTPUT]->(ds:Dataset)" \
            " where ds.data_types contains '_lab'" \
            " return distinct ds.uuid"
        for record in neo_session.run(q):
            dataset_uuid: str = record.get('ds.uuid')
            entity: Dataset = entity_instance.get_entity_by_id(dataset_uuid)
            entity_dict: dict = vars(entity)
            # create_dataset_draft_doi will blowup if these fields are not present in the record...
            required_fields: list =\
                ['entity_type', 'status', 'hubmap_id', 'uuid', 'title', 'contacts', 'contributors']
            missing_fields: list = []
            for field in required_fields:
                if field not in entity_dict:
                    missing_fields.append(field)
            if len(missing_fields) != 0:
                logger.error(f"Dataset associated with uuid '{dataset_uuid}' is missing required field(s): {', '.join(missing_fields)}")
            else:
                logger.info(f'Creating DOI for Dataset.uuid: {dataset_uuid}')
                try:
                    datacite_doi_helper.create_dataset_draft_doi(entity_dict, check_publication_status=False)
                except Exception as e:
                    logger.error("Error occurred while trying to create a draft doi for{dataset_uuid}. {e}")
                    continue
                try:
                    # This will make the draft DOI created above 'findable' and
                    # will update the Dataset doi_url and registered_doi fields.
                    datacite_doi_helper.move_doi_state_from_draft_to_findable(entity_dict, token)
                except Exception as e:
                    logger.error(f"Error occurred while trying to change doi draft state to findable doi for{dataset_uuid}. {e}")
                    continue


def read_confdata(conf_file: str) -> dict:
    confdata: dict = {}
    with open(conf_file) as f:
        for line in f.readlines():
            line = line.strip().rstrip('/n')
            if len(line) == 0 or line[0] == '#':
                continue
            sline = line.split('=')
            var: str = sline[0].strip()
            val: str = re.sub("[\"\']", "", sline[1].strip())
            confdata[var] = val
    return confdata


if __name__ == '__main__':
    confdata: dict = read_confdata('instance/app_dev.cfg')

    neo4j_driver_instance = None
    try:
        neo4j_driver_instance = \
            neo4j_driver.instance(confdata['NEO4J_SERVER'],
                                  confdata['NEO4J_USERNAME'],
                                  confdata['NEO4J_PASSWORD'])
        auth_helper = AuthHelper.create(confdata['APP_CLIENT_ID'], confdata['APP_CLIENT_SECRET'])
        token: str = auth_helper.getProcessSecret()
        entity_instance = EntitySdk(token=token, service_url=confdata['ENTITY_WEBSERVICE_URL'])

        generate_doids_for_all_published(neo4j_driver_instance, entity_instance, token)
    finally:
        if neo4j_driver_instance is not None:
            neo4j_driver_instance.close()
