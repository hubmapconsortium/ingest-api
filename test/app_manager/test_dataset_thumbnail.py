import os
import requests
from pyfakefs.fake_filesystem_unittest import TestCase
from unittest.mock import patch

# Local modules
from dataset_helper_object import DatasetHelper
from api.entity_api import EntityApi
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
        self.entity_api = EntityApi("", "")

        self.dataset_dict = {'thumbnail_file_abs_path': '/hive/hubmap/data/public/University of Florida TMC/e69fb303e035192a0ee38a34e4b25024/extra/thumbnail.jpg'}
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
        orig_file_path = self.dataset_dict['thumbnail_file_abs_path']
        self.fs.create_file(orig_file_path)


    @patch('dataset_helper_object.EntityApi.get_entities')
    @patch('dataset_helper_object.EntityApi.put_entities')
    def test_dataset_with_existing_thumbnail_file(self, mock_put_entities, mock_get_entities):
        def resp1():
            r = requests.Response()
            r.status_code = 200
            r.json = lambda: {'thumbnail_file': {'filename': 'thumbnail.jpg', 'file_uuid': 'fc95dd0faaf2cfc4786d89bf7b074485'}, 'title': "CX_19-002_lymph-node_R2", 'uuid': 'e69fb303e035192a0ee38a34e4b25024'}
            return r
        mock_get_entities.side_effect = [resp1()]

        def resp2():
            r = requests.Response()
            r.status_code = 200
            r.json = lambda: {'title': "CX_19-002_lymph-node_R2", 'uuid': 'e69fb303e035192a0ee38a34e4b25024'}
            return r
        mock_put_entities.side_effect = [resp2()]

        updated_dataset_dict =\
            self.dataset_helper.handle_thumbnail_file(self.dataset_dict, 
                                                      self.entity_api, 
                                                      self.dataset_uuid, 
                                                      self.extra_headers,
                                                      self.temp_file_id, 
                                                      self.file_upload_temp_dir)

        mock_get_entities.assert_called()
        mock_put_entities.assert_called()

        # Verify resulting value
        self.assertFalse('thumbnail_file_abs_path' in updated_dataset_dict)
        self.assertTrue('thumbnail_file_to_add' in updated_dataset_dict)
        self.assertEquals(updated_dataset_dict['thumbnail_file_to_add']['temp_file_id'], self.temp_file_id)

        temp_file_path = os.path.join(self.file_upload_temp_dir, self.temp_file_id, 'thumbnail.jpg')
        self.assertTrue(os.path.exists(temp_file_path))


    @patch('dataset_helper_object.EntityApi.get_entities')
    @patch('dataset_helper_object.EntityApi.put_entities')
    def test_dataset_without_existing_thumbnail_file(self, mock_put_entities, mock_get_entities):
        def resp1():
            r = requests.Response()
            r.status_code = 200
            r.json = lambda: {'title': "CX_19-002_lymph-node_R2", 'uuid': 'e69fb303e035192a0ee38a34e4b25024'}
            return r
        mock_get_entities.side_effect = [resp1()]

        updated_dataset_dict =\
            self.dataset_helper.handle_thumbnail_file(self.dataset_dict, 
                                                      self.entity_api, 
                                                      self.dataset_uuid, 
                                                      self.extra_headers,
                                                      self.temp_file_id, 
                                                      self.file_upload_temp_dir)

        mock_get_entities.assert_called()
        # No existing thumbnail, thus no removal via PUT
        mock_put_entities.assert_not_called()

        # Verify resulting value
        self.assertFalse('thumbnail_file_abs_path' in updated_dataset_dict)
        self.assertTrue('thumbnail_file_to_add' in updated_dataset_dict)
        self.assertEquals(updated_dataset_dict['thumbnail_file_to_add']['temp_file_id'], self.temp_file_id)

        temp_file_path = os.path.join(self.file_upload_temp_dir, self.temp_file_id, 'thumbnail.jpg')
        self.assertTrue(os.path.exists(temp_file_path))


if __name__ == "__main__":
    import nose2
    nose2.main()
