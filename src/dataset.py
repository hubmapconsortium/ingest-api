import requests
from neo4j.exceptions import TransactionError
import sys
import os
import urllib.parse
from pprint import pprint
import shutil
import json
import traceback
import logging
import threading

from ingest_file_helper import IngestFileHelper

# Suppress InsecureRequestWarning warning when requesting status on https with ssl cert verify disabled
from requests.packages.urllib3.exceptions import InsecureRequestWarning

from hubmap_commons.uuid_generator import UUID_Generator
from hubmap_commons.hm_auth import AuthHelper, AuthCache
from hubmap_commons.autherror import AuthError
from hubmap_commons.file_helper import linkDir, unlinkDir, mkDir
from hubmap_commons import file_helper
from hubmap_commons.exceptions import HTTPException

# Should be deprecated but still in use
from hubmap_commons.hubmap_const import HubmapConst 

# The new neo4j_driver module from commons
from hubmap_commons import neo4j_driver


requests.packages.urllib3.disable_warnings(category = InsecureRequestWarning)

# Set logging fromat and level (default is warning)
# All the API logging is forwarded to the uWSGI server and gets written into the log file `uwsgo-entity-api.log`
# Log rotation is handled via logrotate on the host system with a configuration file
# Do NOT handle log file and rotation via the Python logging to avoid issues with multi-worker processes
logging.basicConfig(format='[%(asctime)s] %(levelname)s in %(module)s: %(message)s', level=logging.DEBUG, datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger(__name__)

class Dataset(object):
    '''
    classdocs
    '''
    confdata = {}

    @classmethod
    
    def __init__(self, config): 
        self.confdata = config

        # The new neo4j_driver (from commons package) is a singleton module
        # This neo4j_driver_instance will be used for application-specifc neo4j queries
        # as well as being passed to the schema_manager
        try:
            self.neo4j_driver_instance = neo4j_driver.instance(config['NEO4J_SERVER'], 
                                                          config['NEO4J_USERNAME'], 
                                                          config['NEO4J_PASSWORD'])

            logger.info("Initialized neo4j_driver module successfully :)")
        except Exception:
            msg = "Failed to initialize the neo4j_driver module"
            # Log the full stack trace, prepend a line with our message
            logger.exception(msg)

    # Create derived dataset
    @classmethod
    def create_derived_datastage(self, nexus_token, json_data):
        global logger
        
        # check the incoming UUID to make sure they exist
        source_datasets = json_data['source_dataset_uuid']
        if isinstance(source_datasets, list):
            source_uuid = source_datasets[0].strip()
        else:
            source_uuid = source_datasets.strip()
        if source_uuid == None or len(source_uuid) == 0:
            raise ValueError('Error: source_dataset_uuid must be set to create a derived dataset')
        
        bearer_header = 'Bearer ' + nexus_token
        auth_header = {'Authorization': bearer_header}

        get_url = file_helper.ensureTrailingSlashURL(self.confdata['ENTITY_WEBSERVICE_URL']) + 'entities/' + source_uuid.strip()        
        response = requests.get(get_url, headers = auth_header, verify = False)
        if response.status_code != 200:
            raise HTTPException("Error retrieving source dataset " + source_uuid, response.status_code)
        source_ds = response.json()
        

        # Create the Entity Metadata node
        # Don't use None, it'll throw TypeError: 'NoneType' object does not support item assignment
        new_ds = {}

        # Use the dataset name from input json
        # Need to use constant instead of hardcoding later
        new_ds['title'] = json_data['derived_dataset_name']
        # Also use the dataset data types array from input json and store as string in metadata attribute
        new_ds['data_types'] = json_data['derived_dataset_types']
        new_ds['direct_ancestor_uuids'] = [source_uuid]
        new_ds['group_uuid'] = source_ds['group_uuid']
        #new_ds['group_name'] = source_ds['group_name']

        
        # Set the 'phi' attribute with default value as "no"
        new_ds['contains_human_genetic_sequences'] = False
        # Set the default status to New
        #new_ds['status'] = 'New'
        #new_ds['data_access_level'] = 'consortium'

        post_url = file_helper.ensureTrailingSlashURL(self.confdata['ENTITY_WEBSERVICE_URL']) + 'entities/dataset'
        app_header = {'X-Hubmap-Application': 'ingest-api'}
        # Merge the auth_header and app_header for creating new Dataset
        response = requests.post(post_url, json=new_ds, headers = {**auth_header, **app_header}, verify = False)
        if response.status_code != 200:
            raise HTTPException("Error creating derived dataset: " + response.text, response.status_code)

        ds = response.json()
        file_help = IngestFileHelper(self.confdata)
        sym_path = os.path.join(str(self.confdata['HUBMAP_WEBSERVICE_FILEPATH']),ds['uuid'])

        new_directory_path = file_help.get_dataset_directory_absolute_path(new_ds, new_ds['group_uuid'], ds['uuid'])   
        new_path = IngestFileHelper.make_directory(new_directory_path, sym_path)

        try:
            x = threading.Thread(target=file_help.set_dir_permissions, args=['consortium', new_path])
            x.start()
        except Exception as e:
            logger = logging.getLogger('ingest.service')
            logger.error(e, exc_info=True)


        response_data = {
            'derived_dataset_uuid': ds['uuid'],
            'group_uuid': ds['group_uuid'],
            'group_display_name': ds['group_name'],
            'full_path': new_path
        }

        return response_data



    @classmethod
    def get_writeable_flag(self, token, writeable_uuid_list, current_record):
        authcache = None
        if AuthHelper.isInitialized() == False:
            authcache = AuthHelper.create(self.confdata['APP_CLIENT_ID'], self.confdata['APP_CLIENT_SECRET'])
        else:
            authcache = AuthHelper.instance()
        userinfo = None
        userinfo = authcache.getUserInfo(token, True)
        role_list = AuthCache.getHMRoles()
        
        data_curator_uuid = role_list['hubmap-data-curator']['uuid']
        is_data_curator = False
        for role_uuid in userinfo['hmroleids']:
            if role_uuid == data_curator_uuid:
                    is_data_curator = True
                    break
        # the data curator role overrules the group level write rules
        if is_data_curator == True:
            if current_record['metadata_properties']['status'] in [HubmapConst.DATASET_STATUS_QA]:
                return True
            else:
                return False

        # perform two checks:
        # 1. make sure the user has write access to the record's group
        # 2. make sure the record has a status that is writable
        if current_record['metadata_properties']['provenance_group_uuid'] in writeable_uuid_list:
            if current_record['metadata_properties']['status'] in [HubmapConst.DATASET_STATUS_NEW, HubmapConst.DATASET_STATUS_ERROR, HubmapConst.DATASET_STATUS_REOPENED]:
                return True
        
        return False

        
            
        #print(str(userinfo) + ' is curator: ' + str(is_data_curator))
    

    @classmethod
    def change_status(self, driver, headers, uuid, oldstatus, newstatus, formdata, group_uuid):
        if str(oldstatus).upper() == str(HubmapConst.DATASET_STATUS_PUBLISHED).upper() and str(newstatus).upper() == str(HubmapConst.DATASET_STATUS_REOPENED).upper():
            self.reopen_dataset(driver, headers, uuid, formdata, group_uuid)
        elif str(oldstatus).upper() == str(HubmapConst.DATASET_STATUS_QA).upper() and str(newstatus).upper() == str(HubmapConst.DATASET_STATUS_PUBLISHED).upper():
            self.publishing_process(driver, headers, uuid, group_uuid, HubmapConst.DATASET_STATUS_PUBLISHED)
        elif str(oldstatus).upper() == str(HubmapConst.DATASET_STATUS_PUBLISHED).upper() and str(newstatus).upper() == str(HubmapConst.DATASET_STATUS_UNPUBLISHED).upper():
            self.publishing_process(driver, headers, uuid, group_uuid, HubmapConst.DATASET_STATUS_UNPUBLISHED)
        else:
            self.modify_dataset(driver, headers, uuid, formdata, group_uuid)
     

    @classmethod
    def get_dataset_ingest_update_record(self, json_data):
        """ expect something like this:
        #{'dataset_id' : '4d3eb2a87cda705bde38495bb564c8dc', 'status': '<status>', 'message': 'the process ran', 'metadata': [maybe some metadata stuff], 'thumbnail_image_abs_path': 'full file path'} 
        files: [{ "relativePath" : "/path/to/file/example.txt",
           "type":"filetype",
           "size":filesize,
           "checksum":"file-checksum"
         }]
         """
        
        # For thumbnail image handling
        if 'thumbnail_file_abs_path' in json_data:
            update_record['thumbnail_file_abs_path'] = json_data['thumbnail_file_abs_path']

        if 'dataset_id' not in json_data:
            raise ValueError('cannot find dataset_id')
        update_record = {}

        if 'status' not in json_data:
            raise ValueError('cannot find status')
        if json_data['status'] not in HubmapConst.DATASET_STATUS_OPTIONS:
            raise ValueError('"' + json_data['status'] + '" is not a valid status')                              
        update_record['status'] = json_data['status']

        #if 'files' in json_data:
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
        
        #we can get the antibodies or contributors fields at multiple levels
        #find them and move them to the top
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
                
                #while we're here if we have that second level of metadata, move it up one level
                #but first save anything else at the same level an put it in 
                #an attribute named 'extra_metadata"
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
            
        return update_record

    @classmethod
    def get_file_list(self, orig_file_path):
        f = None
        try:
            # join the incoming file path with the WORKFLOW_SCRATCH location
            file_path = os.path.join(self.confdata['WORKFLOW_SCRATCH'], orig_file_path)
            with open(file_path) as f:
                data = json.load(f)
                if 'files' in data:
                    return data['files']
                else:
                    raise ValueError('Cannot find the \'files\' attribute in: ' + file_path)
        except json.JSONDecodeError as jde:
            print ('Cannot decode JSON in file: ' + file_path)
            raise            
        except FileNotFoundError as fnfe:
            print ('Cannot find file: ' + file_path)
            raise
        except PermissionError as pe:
            print ('Cannot access file: ' + file_path)
            raise
        except:
            print ('A general error occurred: ', sys.exc_info()[0])
            raise            
        finally:
            if f != None:
                f.close()    

        

    @classmethod
    def set_status(self, driver, uuid, new_status):
        with driver.session() as session:
            tx = None
            try:
                tx = session.begin_transaction()
                stmt = f"match (e:Entity {{uuid:'{uuid}'}}) set e.status = '{new_status}'"
                print ("EXECUTING DATASET UPDATE: " + stmt)
                tx.run(stmt)
                tx.commit()
                return uuid
            except TransactionError as te: 
                print ('A transaction error occurred: ', te.value)
                tx.rollback()
            except:
                print ('A general error occurred: ')
                for x in sys.exc_info():
                    print (x)
                tx.rollback()
    
    

    @classmethod
    def get_globus_file_path(self, group_name, dataset_uuid):
        start_dir = str(self.confdata['GLOBUS_ENDPOINT_FILEPATH'])
        ret_dir = os.path.join(start_dir, group_name, dataset_uuid)
        return ret_dir
    
    @classmethod
    def get_access_level(self, nexus_token, driver, metadata_info):
        incoming_sourceUUID_string = None
        if 'source_uuids' in metadata_info:
            incoming_sourceUUID_string = str(metadata_info['source_uuids']).strip()
        elif 'source_uuid' in metadata_info:
            incoming_sourceUUID_string = str(metadata_info['source_uuid']).strip()
        if incoming_sourceUUID_string == None or len(incoming_sourceUUID_string) == 0:
            raise ValueError('Error: sourceUUID must be set to determine access level')
        source_UUID_Data = []
        uuid_list = []
        donor_list = []
        ug = UUID_Generator(self.confdata['UUID_WEBSERVICE_URL'])
        try:
            incoming_sourceUUID_list = []
            if str(incoming_sourceUUID_string).startswith('['):
                incoming_sourceUUID_list = eval(incoming_sourceUUID_string)
            else:
                incoming_sourceUUID_list.append(incoming_sourceUUID_string)
            for sourceID in incoming_sourceUUID_list:
                hmuuid_data = ug.getUUID(nexus_token, sourceID)
                if len(hmuuid_data) != 1:
                    raise ValueError("Could not find information for identifier" + sourceID)
                source_UUID_Data.append(hmuuid_data)
                uuid_list.append(hmuuid_data[0]['hm_uuid'])
            donor_list = Dataset.get_donor_by_specimen_list(driver, uuid_list)
        except:
            raise ValueError('Unable to resolve UUID for: ' + incoming_sourceUUID_string)
        
        is_dataset_genomic_sequence = False
        is_donor_open_consent = False
        is_dataset_protected_data = False
        is_dataset_published = False
        
        #set the is_donor_open_consent flag
        #if any of the donors contain open consent, then
        #set the flag to True
        for donor in donor_list:
            if HubmapConst.DONOR_OPEN_CONSENT in donor:
                if donor[HubmapConst.DONOR_OPEN_CONSENT] == True:
                    is_donor_open_consent = True
        
        if HubmapConst.DATASET_STATUS_ATTRIBUTE in metadata_info:
            is_dataset_published = metadata_info[HubmapConst.DATASET_STATUS_ATTRIBUTE] == HubmapConst.DATASET_STATUS_PUBLISHED
        
        if HubmapConst.DATASET_IS_PROTECTED in metadata_info:
            is_dataset_protected_data = str(metadata_info[HubmapConst.DATASET_IS_PROTECTED]).lower() == 'true'
        
        # NOTE: this should be changed to HubmapConst.DATASET_CONTAINS_GENOMIC_DATA in the future
        if HubmapConst.HAS_PHI_ATTRIBUTE in metadata_info:
            is_dataset_genomic_sequence = str(metadata_info[HubmapConst.HAS_PHI_ATTRIBUTE]).lower() == 'yes'
        
        if is_dataset_protected_data == True:
            return HubmapConst.ACCESS_LEVEL_PROTECTED
        
        if is_dataset_genomic_sequence == True and is_donor_open_consent == False:
            return HubmapConst.ACCESS_LEVEL_PROTECTED
        
        if is_dataset_protected_data == False and is_dataset_published == False:
            return HubmapConst.ACCESS_LEVEL_CONSORTIUM
        
        if is_dataset_protected_data == False and is_dataset_published == True and is_dataset_genomic_sequence == False:
            return HubmapConst.ACCESS_LEVEL_PUBLIC
        
        # this is the default access level
        return HubmapConst.ACCESS_LEVEL_PROTECTED
    
    
    
    @staticmethod
    def get_datasets_by_donor(driver, donor_uuid_list):
        donor_return_list = []
        try:
            donor_return_list = Dataset.get_datasets_by_type(driver, 'Donor', donor_uuid_list)
            return donor_return_list
        except ConnectionError as ce:
            print('A connection error occurred: ', str(ce.args[0]))
            raise ce
        except ValueError as ve:
            print('A value error occurred: ', ve.value)
            raise ve
        except:
            print('A general error occurred: ')
            traceback.print_exc()

    @staticmethod
    def get_datasets_by_sample(driver, sample_uuid_list):
        donor_return_list = []
        try:
            donor_return_list = Dataset.get_datasets_by_type(driver, 'Sample', sample_uuid_list)
            return donor_return_list
        except ConnectionError as ce:
            print('A connection error occurred: ', str(ce.args[0]))
            raise ce
        except ValueError as ve:
            print('A value error occurred: ', ve.value)
            raise ve
        except:
            print('A general error occurred: ')
            traceback.print_exc()


    @classmethod
    def get_dataset_directory(self, dataset_uuid, group_display_name = None, data_access_level = None):
        conn = None
        driver = None
        try:
            if group_display_name == None and data_access_level == None:
                dataset = Dataset.get_dataset(self.neo4j_driver_instance, dataset_uuid)
                data_access_level = dataset[HubmapConst.DATA_ACCESS_LEVEL]
                group_display_name = dataset[HubmapConst.PROVENANCE_GROUP_NAME_ATTRIBUTE]

            file_path_root_dir = self.confdata['GLOBUS_PROTECTED_ENDPOINT_FILEPATH']
            if data_access_level == HubmapConst.ACCESS_LEVEL_CONSORTIUM:
                file_path_root_dir = self.confdata['GLOBUS_CONSORTIUM_ENDPOINT_FILEPATH']
            # the public path removes the group directory:
            elif data_access_level == HubmapConst.ACCESS_LEVEL_PUBLIC:
                file_path_root_dir = self.confdata['GLOBUS_PUBLIC_ENDPOINT_FILEPATH']
                new_path = str(os.path.join(file_path_root_dir, dataset_uuid))
                return new_path            
            new_path = str(os.path.join(file_path_root_dir, group_display_name, dataset_uuid))
            return new_path
        except ConnectionError as ce:
            print('A connection error occurred: ', str(ce.args[0]))
            raise ce
        except ValueError as ve:
            print('A value error occurred: ', ve.value)
            raise ve
        except:
            print('A general error occurred: ')
            traceback.print_exc()
        finally:
            if conn != None:
                conn.close()
            if driver != None:
                if driver.closed() == False:
                    driver.close()



def build_globus_url_for_directory(transfer_endpoint_uuid,new_directory):
    encoded_path = urllib.parse.quote(str(new_directory))
    ret_string = 'https://app.globus.org/file-manager?origin_id={endpoint_uuid}&origin_path={new_path}'.format(endpoint_uuid=transfer_endpoint_uuid, new_path=encoded_path)
    return ret_string


def copy_directory(oldpath, newpath):
    try:
        #os.makedirs(newpath)
        ret_path = shutil.copy(oldpath, newpath)
    except: 
        raise 
    return ret_path


def convert_dataset_status(raw_status):
    new_status = ''
    # I need to convert the status to what is found in the HubmapConst file
    if str(raw_status).upper() == str(HubmapConst.DATASET_STATUS_NEW).upper():
        new_status = HubmapConst.DATASET_STATUS_NEW
    elif str(raw_status).upper() == str(HubmapConst.DATASET_STATUS_INVALID).upper():
        new_status = HubmapConst.DATASET_STATUS_INVALID
    elif str(raw_status).upper() == str(HubmapConst.DATASET_STATUS_VALID).upper():
        new_status = HubmapConst.DATASET_STATUS_VALID
    elif str(raw_status).upper() == str(HubmapConst.DATASET_STATUS_PUBLISHED).upper():
        new_status = HubmapConst.DATASET_STATUS_PUBLISHED
    elif str(raw_status).upper() == str(HubmapConst.DATASET_STATUS_REOPENED).upper():
        new_status = HubmapConst.DATASET_STATUS_REOPENED
    elif str(raw_status).upper() == str(HubmapConst.DATASET_STATUS_LOCKED).upper():
        new_status = HubmapConst.DATASET_STATUS_LOCKED
    elif str(raw_status).upper() == str(HubmapConst.DATASET_STATUS_NEW).upper():
        new_status = HubmapConst.DATASET_STATUS_NEW
    elif str(raw_status).upper() == str(HubmapConst.DATASET_STATUS_UNPUBLISHED).upper():
        new_status = HubmapConst.DATASET_STATUS_UNPUBLISHED
    elif str(raw_status).upper() == str(HubmapConst.DATASET_STATUS_QA).upper():
        new_status = HubmapConst.DATASET_STATUS_QA
    elif str(raw_status).upper() == str(HubmapConst.DATASET_STATUS_ERROR).upper():
        new_status = HubmapConst.DATASET_STATUS_ERROR
    elif str(raw_status).upper() == str(HubmapConst.DATASET_STATUS_PROCESSING).upper():
        new_status = HubmapConst.DATASET_STATUS_PROCESSING
    elif str(raw_status).upper() == str(HubmapConst.DATASET_STATUS_HOLD).upper():
        new_status = HubmapConst.DATASET_STATUS_HOLD
    return new_status

if __name__ == "__main__":
    NEO4J_SERVER = 'bolt://localhost:7687'
    NEO4J_USERNAME = 'neo4j'
    NEO4J_PASSWORD = '123'

    nexus_token = 'AgNkroqO86BbgjPxYk9Md20r8lKJ04WxzJnqrm7xWvDKg1lvgbtgCwnxdYBNYw85OkGmoo1wxPb4GMfjO8dakf24g7'
    
    #driver = conn.get_driver()
    
    UUID_WEBSERVICE_URL = 'http://localhost:5001/hmuuid'

    conf_data = {'NEO4J_SERVER' : NEO4J_SERVER, 'NEO4J_USERNAME': NEO4J_USERNAME, 
                 'NEO4J_PASSWORD': NEO4J_PASSWORD, 'UUID_WEBSERVICE_URL' : UUID_WEBSERVICE_URL,
                 'GLOBUS_PUBLIC_ENDPOINT_FILEPATH' : '/hive/hubmap-dev/public',
                 'GLOBUS_CONSORTIUM_ENDPOINT_FILEPATH': '/hive/hubmap-dev/consortium',
                 'GLOBUS_PROTECTED_ENDPOINT_FILEPATH': '/hive/hubmap-dev/lz',
                 'GLOBUS_BASE_FILE_USER_NAME' : 'hive_base',
                 'GLOBUS_ADMIN_FILE_USER_NAME' : 'hive_admin',
                 'GLOBUS_GENOMIC_DATA_FILE_GROUP_NAME' : 'genomic_temp',
                 'GLOBUS_CONSORTIUM_FILE_GROUP_NAME' : 'consort_temp'
                 }
    dataset = Dataset(conf_data)
    
    group_display_name = 'IEC Testing Group'
    consort_dataset_uuid = '909e2600643f8a6f5b60be9d7a7755ac_consort'
    protected_dataset_uuid = '48fb4423ea9c2b8aaf3c4f0be5ac1c98_protected'
    public_dataset_uuid = 'a9175b3b41ef3cb88afa0cb1fff0f4e7_public'
    dataset_uuid = 'b17694503bcbdd2458d3e96373ce9fbc'
    
    file_path_test = dataset.get_dataset_directory(dataset_uuid)
    print("File path no params: " +  file_path_test)

    file_path_test = dataset.get_dataset_directory(dataset_uuid, 'Bla Bla', HubmapConst.ACCESS_LEVEL_PROTECTED)
    print("File path protected: " +  file_path_test)

    file_path_test = dataset.get_dataset_directory(dataset_uuid, 'Bla Bla', HubmapConst.ACCESS_LEVEL_CONSORTIUM)
    print("File path consortium: " +  file_path_test)

    file_path_test = dataset.get_dataset_directory(dataset_uuid, 'Bla Bla', HubmapConst.ACCESS_LEVEL_PUBLIC)
    print("File path public: " +  file_path_test)
   
    #dataset.set_dir_permissions(HubmapConst.ACCESS_LEVEL_CONSORTIUM, consort_dataset_uuid, group_display_name)
    #dataset.set_dir_permissions(HubmapConst.ACCESS_LEVEL_PROTECTED, protected_dataset_uuid, group_display_name)
    #dataset.set_dir_permissions(HubmapConst.ACCESS_LEVEL_PUBLIC, public_dataset_uuid, group_display_name)

    #dataset.set_dir_permissions(HubmapConst.ACCESS_LEVEL_CONSORTIUM, public_dataset_uuid, group_display_name)

    
    """
    
    sample_uuid_with_dataset = '909e2600643f8a6f5b60be9d7a7755ac'
    collection_uuid_with_dataset = '48fb4423ea9c2b8aaf3c4f0be5ac1c98'
    donor_uuid_with_dataset = 'a9175b3b41ef3cb88afa0cb1fff0f4e7'
    
    datasets_for_collection = Dataset.get_datasets_by_collection(driver, collection_uuid_with_dataset)
    print("Collections: " + str(datasets_for_collection))
    
    datasets_for_donor = Dataset.get_datasets_by_donor(driver, [donor_uuid_with_dataset])
    print("Donor: " + str(datasets_for_donor))

    datasets_for_sample = Dataset.get_datasets_by_sample(driver, [sample_uuid_with_dataset])
    print("Sample: " + str(datasets_for_sample))
    """
    
    
    """
    protected_dataset_uuid = '62c461245ee413fc5eed0f1f31853139'
    consortium_dataset_uuid = 'f1fc56fe8e39a9c05328d905d1c4498e'
    open_consent_dataset_uuid = 'd22bdd1ed6908894dbfd4e17c668112e'
    
    protected_dataset_info = Dataset.get_dataset(driver, protected_dataset_uuid)
    consortium_dataset_info = Dataset.get_dataset(driver, consortium_dataset_uuid)
    open_consent_dataset_info = Dataset.get_dataset(driver, open_consent_dataset_uuid)
    
    
    print("Protected uuid: " + protected_dataset_uuid)
    access_level = dataset.get_access_level(nexus_token, driver, protected_dataset_info)
    print ("Access level : " + str(access_level))

    print("Consortium uuid: " + consortium_dataset_uuid)
    access_level = dataset.get_access_level(nexus_token, driver, consortium_dataset_info)
    print ("Access level : " + str(access_level))

    print("Open consent uuid: " + open_consent_dataset_uuid)
    access_level = dataset.get_access_level(nexus_token, driver, open_consent_dataset_info)
    print ("Access level : " + str(access_level))
    """

