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
    excluded_protected_exts = [".fastq", ".fastq.gz", ".bam"]
    
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

        return self.dataset_directory_absolute_path(access_level, group_uuid, dataset_uuid, published)

    def get_dataset_directory_relative_path(self, dataset_record, group_uuid, dataset_uuid):
        if dataset_record['contains_human_genetic_sequences']:
            access_level = 'protected'
        elif not 'data_access_level' in dataset_record:
            access_level = 'consortium'
        else:
            access_level = dataset_record['data_access_level']

        published = False
        if 'status' in dataset_record and dataset_record['status'] == 'Published':
            published = True

        return self.__dataset_directory_relative_path(access_level, group_uuid, dataset_uuid, published)

    def get_upload_directory_relative_path(self, group_uuid, upload_uuid):
        return self.__dataset_directory_relative_path('protected', group_uuid, upload_uuid, False)
   
    def dataset_directory_absolute_path(self, access_level, group_uuid, dataset_uuid, published):
        grp_name = AuthHelper.getGroupDisplayName(group_uuid)
        if access_level == 'protected':
            base_dir = self.appconfig['GLOBUS_PROTECTED_ENDPOINT_FILEPATH']
            abs_path = str(os.path.join(base_dir, grp_name, dataset_uuid))
        elif published:
            base_dir = self.appconfig['GLOBUS_PUBLIC_ENDPOINT_FILEPATH']
            abs_path = str(os.path.join(base_dir, dataset_uuid))
        else:
            base_dir = self.appconfig['GLOBUS_CONSORTIUM_ENDPOINT_FILEPATH']
            abs_path = str(os.path.join(base_dir, grp_name, dataset_uuid))
        
        return abs_path

    def __dataset_directory_relative_path(self, access_level, group_uuid, dataset_uuid, published):
        grp_name = AuthHelper.getGroupDisplayName(group_uuid)
        if access_level == 'protected':
            endpoint_id = self.appconfig['GLOBUS_PROTECTED_ENDPOINT_UUID']
            rel_path = file_helper.ensureBeginningSlashURL(str(os.path.join(self.appconfig['PROTECTED_DATA_SUBDIR'], grp_name, dataset_uuid)))
        elif published:
            endpoint_id = self.appconfig['GLOBUS_PUBLIC_ENDPOINT_UUID']
            rel_path = file_helper.ensureBeginningSlashURL(str(os.path.join(self.appconfig['PUBLIC_DATA_SUBDIR'], dataset_uuid)))
        else:
            endpoint_id = self.appconfig['GLOBUS_CONSORTIUM_ENDPOINT_UUID']
            rel_path = file_helper.ensureBeginningSlashURL(str(os.path.join(self.appconfig['CONSORTIUM_DATA_SUBDIR'], grp_name, dataset_uuid)))

        return {"rel_path":rel_path, "globus_endpoint_uuid":endpoint_id}

    def dataset_asset_directory_absolute_path(self, dataset_uuid):
        return file_helper.ensureTrailingSlashURL(self.appconfig['HUBMAP_WEBSERVICE_FILEPATH']) + dataset_uuid

    def create_dataset_directory(self, dataset_record, group_uuid, dataset_uuid):
        if dataset_record['contains_human_genetic_sequences']:
            access_level = 'protected'
            asset_link_dir = None
        else:
            access_level = 'consortium'
            #if the dataset is consortium level provide the path in the assets directory
            #to link it to, if protected don't link into assets directory (above set to None)
            asset_link_dir = os.path.join(str(self.appconfig['HUBMAP_WEBSERVICE_FILEPATH']), dataset_record['uuid'])
            
        new_directory_path = self.get_dataset_directory_absolute_path(dataset_record, group_uuid, dataset_uuid)
        IngestFileHelper.make_directory(new_directory_path, asset_link_dir)
        try:
            if dataset_record['contains_human_genetic_sequences']:
                access_level = 'protected'
            else:
                access_level = 'consortium'
            x = threading.Thread(target=self.set_dir_permissions, args=[access_level, new_directory_path])
            x.start()
        except Exception as e:
            self.logger.error(e, exc_info=True)
    
    def get_upload_directory_absolute_path(self, group_uuid, upload_uuid):
        grp_name = AuthHelper.getGroupDisplayName(group_uuid)
        base_dir = self.appconfig['GLOBUS_PROTECTED_ENDPOINT_FILEPATH']
        abs_path = str(os.path.join(base_dir, grp_name, upload_uuid))
        return abs_path
    
    def create_upload_directory(self, group_uuid, upload_uuid): 
        new_directory_path = self.get_upload_directory_absolute_path(group_uuid, upload_uuid)
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
                acl_text = 'u::r-x,g::r-x,o::---,m::r-x,u:{hive_user}:r-x,u:{admin_user}:r-x,g:{seq_group}:r-x,d:user::r-x,d:user:{hive_user}:r-x,d:user:{admin_user}:r-x,d:group:{seq_group}:r-x,d:group::r-x,d:mask::r-x,d:other:---'.format(
                    hive_user=self.appconfig['GLOBUS_BASE_FILE_USER_NAME'],admin_user=self.appconfig['GLOBUS_ADMIN_FILE_USER_NAME'],
                    seq_group=self.appconfig['GLOBUS_GENOMIC_DATA_FILE_GROUP_NAME'])
            if access_level == HubmapConst.ACCESS_LEVEL_CONSORTIUM:
                acl_text = 'u::r-x,g::r-x,o::---,m::r-x,u:{hive_user}:r-x,u:{admin_user}:r-x,g:{consortium_group}:r-x,d:user::r-x,d:user:{hive_user}:r-x,d:user:{admin_user}:r-x,d:group:{consortium_group}:r-x,d:group::r-x,d:mask::r-x,d:other:---'.format(
                    hive_user=self.appconfig['GLOBUS_BASE_FILE_USER_NAME'],admin_user=self.appconfig['GLOBUS_ADMIN_FILE_USER_NAME'],
                    seq_group=self.appconfig['GLOBUS_GENOMIC_DATA_FILE_GROUP_NAME'],
                    consortium_group=self.appconfig['GLOBUS_CONSORTIUM_FILE_GROUP_NAME'])
            if access_level == HubmapConst.ACCESS_LEVEL_PUBLIC:
                acl_text = 'u::r-x,g::r-x,o::r-x,m::r-x,u:{hive_user}:r-x,u:{admin_user}:r-x,d:user::r-x,d:user:{hive_user}:r-x,d:user:{admin_user}:r-x,d:group::r-x,d:mask::r-x,d:other:r-x'.format(
                    hive_user=self.appconfig['GLOBUS_BASE_FILE_USER_NAME'],admin_user=self.appconfig['GLOBUS_ADMIN_FILE_USER_NAME'],
                    seq_group=self.appconfig['GLOBUS_GENOMIC_DATA_FILE_GROUP_NAME'],
                    consortium_group=self.appconfig['GLOBUS_CONSORTIUM_FILE_GROUP_NAME'])
            
        # apply the permissions
        # put quotes around the path since it often contains spaces
        facl_command = "setfacl" + ' -R -b' + ' --set=' + acl_text + " '" + file_path + "'"
        self.logger.info("Executing command: " + facl_command)
        if not trial_run:
            subprocess.Popen(['setfacl','-R', '-b', '--set=' + acl_text, file_path ])
        else:
            print(facl_command)
        return facl_command

    def dataset_directory_absolute_path_published(self, dataset_access_level, group_uuid, uuid):
        data_access_level = 'protected'
        if not dataset_access_level == 'protected': data_access_level = 'public'
        return self.dataset_directory_absolute_path(data_access_level, group_uuid, uuid, True)

    def move_dataset_files_for_publishing(self, uuid, group_uuid, dataset_access_level, trial_run = False, is_component = False, components_primary_path = None):
        rVal = ""
        if is_component and (components_primary_path is None or components_primary_path == ""):
            raise HTTPException(f"{uuid} component dataset does not have a specified primary dataset path", 500)
        from_path = self.dataset_directory_absolute_path(dataset_access_level, group_uuid, uuid, False)
        if not os.path.isdir(from_path):
            raise HTTPException(f"{uuid}: path not found to dataset will not publish, path is {from_path}", 500)
        to_path = self.dataset_directory_absolute_path_published(dataset_access_level, group_uuid, uuid)
        if not trial_run and not is_component:
            shutil.move(from_path, to_path)
        elif is_component:
            rVal = f'unlink "{from_path}"; ln -s "{components_primary_path}" "{to_path}";'
        else:
            print(f"mv {from_path} {to_path}")
        return rVal

    def set_dataset_permissions(self, dataset_uuid, group_uuid, dataset_access_level, published, trial_run = False):
        file_path = self.dataset_directory_absolute_path(dataset_access_level, group_uuid, dataset_uuid, published)
        return self.set_dir_permissions(dataset_access_level, file_path, published, trial_run = trial_run)
    
    def relink_to_public(self, dataset_uuid, is_component = False, components_primary_path = None):
        rVal = None
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
            if not is_component:
                file_helper.linkDir(pub_path, lnk_path)
            else:
                rVal = f'ln -s "{components_primary_path}" "{pub_path}"'
        
        return rVal
    
    def copy_protected_files_to_public(self, dataset: dict) -> tuple[str, str]:
            src_dir = self.get_dataset_directory_absolute_path(
                dataset,
                dataset["group_uuid"],
                dataset["uuid"],
            )
            dst_dir = os.path.join(self.appconfig["GLOBUS_PUBLIC_ENDPOINT_FILEPATH"], dataset["uuid"])
            if not os.path.exists(src_dir):
                raise Exception(f"Protected dataset directory {src_dir} does not exist")
            if os.path.exists(dst_dir):
                raise Exception(f"Public dataset directory {dst_dir} already exists")
    
            # Create the public dataset directory
            os.makedirs(dst_dir, mode=0o755, exist_ok=True)  # rwxr-xr-x
    
            # Recursively copy files from protected to public, exclude specific file types
            for root, _, files in os.walk(src_dir):
                rel_path = os.path.relpath(root, src_dir)
                dst_root = os.path.join(dst_dir, rel_path) if rel_path != "." else dst_dir
                os.makedirs(dst_root, mode=0o755, exist_ok=True)
                for file in files:
                    if not any(file.endswith(ext) for ext in self.excluded_protected_exts):
                        src_file = os.path.join(root, file)
                        dst_file = os.path.join(dst_root, file)
                        shutil.copy2(src_file, dst_file)
                        os.chmod(dst_file, 0o444)  # r--r--r--
    
            # Make sequence-data-removed-README.txt file in the top-level public directory
            readme_path = os.path.join(dst_dir, "sequence-data-removed-README.txt")
            with open(readme_path, "w") as f:
                portal_url = file_helper.ensureTrailingSlashURL(self.appconfig["PORTAL_URL"])
                dataset_url = f"{portal_url}browse/dataset/{dataset['uuid']}"
                readme_txt = (
                     "The data in this directory is incomplete because the full sequence data has been removed.\r\n\r\n"
                     f"To get the complete data visit: {dataset_url}\r\n"
                     " - Consortium members with access: Use the Globus link on that page.\r\n"
                     " - Public users and Consortium members without access: Follow the instructions on that page to get the data from dbGap.\r\n\r\n"
                     "Please note: The data will only be available on dbGap an unknown time after Consortium publication.\r\n"
                )
                f.write(readme_txt)
            os.chmod(readme_path, 0o444)  # r--r--r--
    
            # Set directory permissions. we need to do this after copy to avoid permission issues.
            for root, _, files in os.walk(dst_dir):
                os.chmod(root, 0o555)  # r-xr-xr-x
            return src_dir, dst_dir
