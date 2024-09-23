import logging

from hubmap_commons.hubmap_const import HubmapConst

# Set logging format and level (default is warning)
# All the API logging is forwarded to the uWSGI server and gets written into the log file `uwsgi-ingest-api.log`
# Log rotation is handled via logrotate on the host system with a configuration file
# Do NOT handle log file and rotation via the Python logging to avoid issues with multi-worker processes
logging.basicConfig(format='[%(asctime)s] %(levelname)s in %(module)s: %(message)s', level=logging.DEBUG,
                    datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger(__name__)

class SampleHelper:

    @staticmethod
    def get_ingest_group_list(driver, uuid):
        sibling_return_list = []
        try:
            with driver.session() as session:
                stmt = "MATCH (e:{ENTITY_NODE_NAME} {{ {UUID_ATTRIBUTE}: '{uuid}' }})<-[:{ACTIVITY_OUTPUT_REL}]-(a:{ACTIVITY_NODE_NAME}) OPTIONAL MATCH (a:{ACTIVITY_NODE_NAME})-[:{ACTIVITY_OUTPUT_REL}]->(sibling:{ENTITY_NODE_NAME}) RETURN sibling.{UUID_ATTRIBUTE} AS sibling_uuid, sibling.{LAB_IDENTIFIER_ATTRIBUTE} AS sibling_hubmap_identifier, sibling.{LAB_TISSUE_ID} AS sibling_lab_tissue_id, sibling.{RUI_LOCATION_ATTR} AS sibling_rui_location".format(
                    UUID_ATTRIBUTE=HubmapConst.UUID_ATTRIBUTE, ENTITY_NODE_NAME=HubmapConst.ENTITY_NODE_NAME, 
                    uuid=uuid, ACTIVITY_NODE_NAME=HubmapConst.ACTIVITY_NODE_NAME, LAB_IDENTIFIER_ATTRIBUTE='submission_id',
                    ACTIVITY_OUTPUT_REL=HubmapConst.ACTIVITY_OUTPUT_REL, LAB_TISSUE_ID =HubmapConst.LAB_SAMPLE_ID_ATTRIBUTE, RUI_LOCATION_ATTR=HubmapConst.RUI_LOCATION_ATTRIBUTE)
                for record in session.run(stmt):
                    sibling_record = {}
                    sibling_record['uuid'] = record.get('sibling_uuid')
                    sibling_record['submission_id'] = record.get('sibling_hubmap_identifier')
                    if record.get('sibling_lab_tissue_id') != None:
                        sibling_record['lab_tissue_id'] = record.get('sibling_lab_tissue_id')
                    if record.get('sibling_rui_location') != None:
                        sibling_record['rui_location'] = record.get('sibling_rui_location')
                    sibling_return_list.append(sibling_record)
                return sibling_return_list
        except (ConnectionError, ValueError, AttributeError) as err:
            msg = f"An unexpected error occurred with uuid={uuid}."
            logger.error(f"{msg}: {str(err)}")
            raise Exception(msg + " See logs.")
        except Exception as e:
            msg = f"An unexpected exception occurred with uuid={uuid}."
            logger.exception(msg)
            raise Exception(msg + " See logs.")
