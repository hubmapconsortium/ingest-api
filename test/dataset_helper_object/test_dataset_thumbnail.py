import os

import hubmap_sdk
import requests
from pyfakefs.fake_filesystem_unittest import TestCase
from unittest.mock import patch

# Local modules
from dataset_helper_object import DatasetHelper
from hubmap_sdk import EntitySdk
from file_upload_helper import UploadFileHelper


#
# Running the tests... At the top level directory type 'nose2 --verbose --log-level debug`
#
# WARNING: ONLY methods beginning with "test_" will be considered tests by 'nose2' :-(
# 
# Use test classes derived from fake_filesystem_unittest.TestCase
class TestDatasetThumbnail(TestCase):

    @patch('dataset_helper_object.DatasetHelper.__init__', return_value=None)
    def setUp(self, mock_dataset_helper_object_init):
        # We are telling the DatasetHelper.__init__ to do nothing
        # but we got a real instance of DatasetHelper
        # Doing this to avoid the app.cfg being loaded in the fake file system
        self.dataset_helper = DatasetHelper()
        self.entity_api = EntitySdk("", "")
        
        self.thumbnail_file_abs_path = '/hive/hubmap/data/public/University of Florida TMC/e69fb303e035192a0ee38a34e4b25024/extra/thumbnail.jpg'
        self.dataset_uuid = 'e69fb303e035192a0ee38a34e4b25024'
        self.temp_file_id = '40bc92d7eb4a77988f274f2e6862d42a'
        self.file_upload_temp_dir = '/hive/hubmap/hm_uploads_tmp'
        self.extra_headers = {
            'Content-Type': 'application/json', 
            'X-Hubmap-Application': 'ingest-api'
        }

        # pyfakefs will automatically find all real file functions and modules, 
        # and stub these out with the fake file system functions and modules
        self.setUpPyfakefs()

        # Create thumbnail file on the fake file system
        self.fs.create_file(self.thumbnail_file_abs_path)

if __name__ == "__main__":
    import nose2
    nose2.main()
