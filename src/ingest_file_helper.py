import os
import logging
import threading
import subprocess
import shutil
from hubmap_commons.hubmap_const import HubmapConst
from hubmap_commons.hm_auth import AuthHelper
from hubmap_commons.exceptions import HTTPException
from hubmap_commons import file_helper

class IngestFileHelper:
#    @staticmethod
#    def save_file(file, directory, create_folder=False):
#        if not os.path.exists(directory):
#            if create_folder is False:
#                raise ValueError('Error: cannot find path: ' + directory)

#        try:
#            pathlib.Path(directory).mkdir(parents=True, exist_ok=True)
#            file.save(os.path.join(directory, file.filename))
#            return str(os.path.join(directory, file.filename))
#        except OSError as oserr:
#            pprint(oserr)
 
    def __init__(self, config):
        self.appconfig = config
        self.logger = logging.getLogger('ingest.service')
        self.auth_helper = AuthHelper.configured_instance(config['APP_CLIENT_ID'], config['APP_CLIENT_SECRET'] )
        
    @staticmethod
    def make_directory(new_file_path, symbolic_file_path=None):
        os.makedirs(new_file_path)
        # make a sym link too
        if symbolic_file_path != None:
            os.symlink(new_file_path, symbolic_file_path, True)
        return new_file_path

    def get_dataset_directory_absolute_path(self, dataset_record, group_uuid, dataset_uuid):
        if dataset_record['contains_human_genetic_sequences']:
            access_level = 'protected'
        elif not 'data_access_level' in dataset_record:
            access_level = 'consortium'
        else:
            access_level = dataset_record['data_access_level']

        published = False
        if 'status' in dataset_record and dataset_record['status'] == 'Published':
            published = True

        return self.__dataset_directory_absolute_path(access_level, group_uuid, dataset_uuid, published)

    def __dataset_directory_absolute_path(self, access_level, group_uuid, dataset_uuid, published):
        grp_name = AuthHelper.getGroupDisplayName(group_uuid)
        if access_level == 'protected':
            base_dir = self.appconfig['GLOBUS_PROTECTED_ENDPOINT_FILEPATH']
            abs_path = str(os.path.join(base_dir, grp_name, dataset_uuid))
        elif published or access_level == 'public':
            base_dir = self.appconfig['GLOBUS_PUBLIC_ENDPOINT_FILEPATH']
            abs_path = str(os.path.join(base_dir, dataset_uuid))
        else:
            base_dir = self.appconfig['GLOBUS_CONSORTIUM_ENDPOINT_FILEPATH']
            abs_path = str(os.path.join(base_dir, grp_name, dataset_uuid))
        
        return abs_path
    
    def dataset_asset_directory_absolute_path(self, dataset_uuid):
        return file_helper.ensureTrailingSlashURL(self.appconfig['HUBMAP_WEBSERVICE_FILEPATH']) + dataset_uuid

    def create_dataset_directory(self, dataset_record, group_uuid, dataset_uuid):
        if dataset_record['contains_human_genetic_sequences']:
            access_level = 'protected'
        else:
            access_level = 'consortium'
            
        new_directory_path = self.get_dataset_directory_absolute_path(dataset_record, group_uuid, dataset_uuid)
        IngestFileHelper.make_directory(new_directory_path, None)
        try:
            if dataset_record['contains_human_genetic_sequences']:
                access_level = 'protected'
            else:
                access_level = 'consortium'
            x = threading.Thread(target=self.set_dir_permissions, args=[access_level, new_directory_path])
            x.start()
        except Exception as e:
            self.logger.error(e, exc_info=True)
    
    def get_upload_directory_absolute_path(self, upload_record, group_uuid, upload_uuid):
        grp_name = AuthHelper.getGroupDisplayName(group_uuid)
        base_dir = self.appconfig['GLOBUS_PROTECTED_ENDPOINT_FILEPATH']
        abs_path = str(os.path.join(base_dir, grp_name, upload_uuid))
        return abs_path
    
    def create_upload_directory(self, upload_record, group_uuid, upload_uuid): 
        # repli. w/ uploads
        access_level = 'protected'
        new_directory_path = self.get_upload_directory_absolute_path(upload_record, group_uuid, upload_uuid)
        IngestFileHelper.make_directory(new_directory_path, None)
        try:
            x = threading.Thread(target=self.set_dir_permissions, args=['protected', new_directory_path])
            x.start()
        except Exception as e:
            self.logger.error(e, exc_info=True)
            
    def set_dir_permissions(self, access_level, file_path, published = False, trial_run = False):
        acl_text = None
        if not published:
            if access_level == HubmapConst.ACCESS_LEVEL_PROTECTED:
                acl_text = 'u::rwx,g::r-x,o::---,m::rwx,u:{hive_user}:rwx,u:{admin_user}:rwx,g:{seq_group}:r-x,d:user::rwx,d:user:{hive_user}:rwx,d:user:{admin_user}:rwx,d:group:{seq_group}:r-x,d:group::r-x,d:mask::rwx,d:other:---'.format(
                    hive_user=self.appconfig['GLOBUS_BASE_FILE_USER_NAME'],admin_user=self.appconfig['GLOBUS_ADMIN_FILE_USER_NAME'],
                    seq_group=self.appconfig['GLOBUS_GENOMIC_DATA_FILE_GROUP_NAME'])
            if access_level == HubmapConst.ACCESS_LEVEL_CONSORTIUM:
                acl_text = 'u::rwx,g::r-x,o::---,m::rwx,u:{hive_user}:rwx,u:{admin_user}:rwx,g:{consortium_group}:r-x,d:user::rwx,d:user:{hive_user}:rwx,d:user:{admin_user}:rwx,d:group:{consortium_group}:r-x,d:group::r-x,d:mask::rwx,d:other:---'.format(
                    hive_user=self.appconfig['GLOBUS_BASE_FILE_USER_NAME'],admin_user=self.appconfig['GLOBUS_ADMIN_FILE_USER_NAME'],
                    seq_group=self.appconfig['GLOBUS_GENOMIC_DATA_FILE_GROUP_NAME'],
                    consortium_group=self.appconfig['GLOBUS_CONSORTIUM_FILE_GROUP_NAME'])
            if access_level == HubmapConst.ACCESS_LEVEL_PUBLIC:
                acl_text = 'u::rwx,g::r-x,o::r-x,m::rwx,u:{hive_user}:rwx,u:{admin_user}:rwx,d:user::rwx,d:user:{hive_user}:rwx,d:user:{admin_user}:rwx,d:group::r-x,d:mask::rwx,d:other:r-x'.format(
                    hive_user=self.appconfig['GLOBUS_BASE_FILE_USER_NAME'],admin_user=self.appconfig['GLOBUS_ADMIN_FILE_USER_NAME'],
                    seq_group=self.appconfig['GLOBUS_GENOMIC_DATA_FILE_GROUP_NAME'],
                    consortium_group=self.appconfig['GLOBUS_CONSORTIUM_FILE_GROUP_NAME'])
        else:
            if access_level == HubmapConst.ACCESS_LEVEL_PROTECTED:
                acl_text = 'u::r-x,g::r-x,o::---,m::rwx,u:{hive_user}:r-x,u:{admin_user}:r-x,g:{seq_group}:r-x,d:user::r-x,d:user:{hive_user}:r-x,d:user:{admin_user}:r-x,d:group:{seq_group}:r-x,d:group::r-x,d:mask::r-x,d:other:---'.format(
                    hive_user=self.appconfig['GLOBUS_BASE_FILE_USER_NAME'],admin_user=self.appconfig['GLOBUS_ADMIN_FILE_USER_NAME'],
                    seq_group=self.appconfig['GLOBUS_GENOMIC_DATA_FILE_GROUP_NAME'])
            if access_level == HubmapConst.ACCESS_LEVEL_CONSORTIUM:
                acl_text = 'u::r-x,g::r-x,o::---,m::r-x,u:{hive_user}:r-x,u:{admin_user}:r-x,g:{consortium_group}:r-x,d:user::r-x,d:user:{hive_user}:r-x,d:user:{admin_user}:r-x,d:group:{consortium_group}:r-x,d:group::r-x,d:mask::r-x,d:other:---'.format(
                    hive_user=self.appconfig['GLOBUS_BASE_FILE_USER_NAME'],admin_user=self.appconfig['GLOBUS_ADMIN_FILE_USER_NAME'],
                    seq_group=self.appconfig['GLOBUS_GENOMIC_DATA_FILE_GROUP_NAME'],
                    consortium_group=self.appconfig['GLOBUS_CONSORTIUM_FILE_GROUP_NAME'])
            if access_level == HubmapConst.ACCESS_LEVEL_PUBLIC:
                acl_text = 'u::r-x,g::r-x,o::r-x,m::r-x,u:{hive_user}:r-x,u:{admin_user}:r-x,d:user::r-x,d:user:{hive_user}:r-x,d:user:{admin_user}:rwx,d:group::r-x,d:mask::r-x,d:other:r-x'.format(
                    hive_user=self.appconfig['GLOBUS_BASE_FILE_USER_NAME'],admin_user=self.appconfig['GLOBUS_ADMIN_FILE_USER_NAME'],
                    seq_group=self.appconfig['GLOBUS_GENOMIC_DATA_FILE_GROUP_NAME'],
                    consortium_group=self.appconfig['GLOBUS_CONSORTIUM_FILE_GROUP_NAME'])
            
        # apply the permissions
        # put quotes around the path since it often contains spaces
        facl_command = "setfacl" + ' -R -b' +  ' --set=' + acl_text + " '" + file_path + "'"
        self.logger.info("Executing command: " + facl_command)
        if not trial_run:
            subprocess.Popen(['setfacl','-R', '-b', '--set=' + acl_text, file_path ])
        else:
            print(facl_command)
        return facl_command

    def move_dataset_files_for_publishing(self, uuid, group_uuid, dataset_access_level, trial_run = False):
        from_path = self.__dataset_directory_absolute_path(dataset_access_level, group_uuid, uuid, False)
        if not os.path.isdir(from_path):
            raise HTTPException(f"{uuid}: path not found to dataset will not publish, path is {from_path}", 500)
        data_access_level = 'protected'
        if not dataset_access_level == 'protected': data_access_level = 'public'
        to_path = self.__dataset_directory_absolute_path(data_access_level, group_uuid, uuid, True)
        if not trial_run:
            shutil.move(from_path, to_path)
        else:
            print(f"mv {from_path} {to_path}")
                    
        return None
            
    def set_dataset_permissions(self, dataset_uuid, group_uuid, dataset_access_level, published, trial_run = False):
        file_path = self.__dataset_directory_absolute_path(dataset_access_level, group_uuid, dataset_uuid, published)
        return self.set_dir_permissions(dataset_access_level, file_path, published, trial_run = trial_run)
    
    def relink_to_public(self, dataset_uuid):
        lnk_path = self.appconfig['HUBMAP_WEBSERVICE_FILEPATH']
        lnk_path = lnk_path.strip()
        if lnk_path[-1] == '/': lnk_path = lnk_path[:-1]
        lnk_path = self.dataset_asset_directory_absolute_path(dataset_uuid)
        pub_path = file_helper.ensureTrailingSlashURL(self.appconfig['GLOBUS_PUBLIC_ENDPOINT_FILEPATH']) + dataset_uuid
        try:
            os.unlink(lnk_path)
        except:
            print("Error unlinking " + lnk_path)
            
        if os.path.exists(pub_path):
            file_helper.linkDir(pub_path, lnk_path)
        
