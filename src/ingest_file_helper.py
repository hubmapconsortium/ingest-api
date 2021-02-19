import os
import logging
import threading
import subprocess
from hubmap_commons.hubmap_const import HubmapConst
from hubmap_commons.hm_auth import AuthHelper
from hubmap_commons import file_helper as commons_file_helper

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

    def create_dataset_directory(self, dataset_record):
        new_directory_path = str(os.path.join(self.appconfig['GLOBUS_PUBLIC_ENDPOINT_FILEPATH'], dataset_record['local_directory_rel_path']))
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
    
    def set_dir_permissions(self, access_level, file_path):
        acl_text = None
        if access_level == HubmapConst.ACCESS_LEVEL_PROTECTED:
            acl_text = 'u::rwx,g::r-x,o::---,m::rwx,u:{hive_user}:rwx,u:{admin_user}:rwx,g:{seq_group}:r-x,d:user::rwx,d:user:{hive_user}:rwx,d:user:{admin_user}:rwx,d:group:{seq_group}:r-x,d:group::r-x,d:mask::rwx,d:other:---'.format(
                hive_user=self.appconfig['GLOBUS_BASE_FILE_USER_NAME'],admin_user=self.confdata['GLOBUS_ADMIN_FILE_USER_NAME'],
                seq_group=self.appconfig['GLOBUS_GENOMIC_DATA_FILE_GROUP_NAME'])
        if access_level == HubmapConst.ACCESS_LEVEL_CONSORTIUM:
            acl_text = 'u::rwx,g::r-x,o::---,m::rwx,u:{hive_user}:rwx,u:{admin_user}:rwx,g:{consortium_group}:r-x,d:user::rwx,d:user:{hive_user}:rwx,d:user:{admin_user}:rwx,d:group:{consortium_group}:r-x,d:group::r-x,d:mask::rwx,d:other:---'.format(
                hive_user=self.appconfig['GLOBUS_BASE_FILE_USER_NAME'],admin_user=self.confdata['GLOBUS_ADMIN_FILE_USER_NAME'],
                seq_group=self.appconfig['GLOBUS_GENOMIC_DATA_FILE_GROUP_NAME'],
                consortium_group=self.confdata['GLOBUS_CONSORTIUM_FILE_GROUP_NAME'])
        if access_level == HubmapConst.ACCESS_LEVEL_PUBLIC:
            acl_text = 'u::rwx,g::r-x,o::r-x,m::rwx,u:{hive_user}:rwx,u:{admin_user}:rwx,d:user::rwx,d:user:{hive_user}:rwx,d:user:{admin_user}:rwx,d:group::r-x,d:mask::rwx,d:other:r-x'.format(
                hive_user=self.appconfig['GLOBUS_BASE_FILE_USER_NAME'],admin_user=self.confdata['GLOBUS_ADMIN_FILE_USER_NAME'],
                seq_group=self.appconfig['GLOBUS_GENOMIC_DATA_FILE_GROUP_NAME'],
                consortium_group=self.appconfig['GLOBUS_CONSORTIUM_FILE_GROUP_NAME'])
        # apply the permissions
        # put quotes around the path since it often contains spaces
        self.logger.info("Executing command:" + 'setfacl' + ' -R -b' +  ' --set=' + acl_text + " '" + file_path + "'")
        subprocess.Popen(['setfacl','-R', '-b', '--set=' + acl_text, file_path ])

            
        
