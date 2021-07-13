import os
import requests
from pyfakefs.fake_filesystem_unittest import TestCase
from unittest.mock import patch, MagicMock

# Local modules
from dataset_helper_object import DatasetHelper
from api.entity_api import EntityApi


#
# Running the tests... At the top level directory type 'nose2 --verbose --log-level debug`
#
# WARNING: ONLY methods beginning with "test_" will be considered tests by 'nose2' :-(
# 
# Use test classes derived from fake_filesystem_unittest.TestCase
class TestDatasetThumbnail(TestCase):

    def setUp(self):
        # pyfakefs will automatically find all real file functions and modules, 
        # and stub these out with the fake file system functions and modules
        self.setUpPyfakefs()
        self.dataset_helper = DatasetHelper()
        self.entity_api = EntityApi("", "")

    @patch('dataset_helper_object.copy2')
    @patch('dataset_helper_object.Path.mkdir')
    @patch('dataset_helper_object.EntityApi.get_entities')
    @patch('dataset_helper_object.EntityApi.put_entities')
    def test_dataset_thumbnail_file_handling(self, mock_put_entities, mock_get_entities, mock_mkdir, mock_copy2):
        dataset_dict = {'thumbnail_file_abs_path': '/hive/hubmap/data/public/University of Florida TMC/e69fb303e035192a0ee38a34e4b25024/extra/thumbnail.jpg'}
        dataset_uuid = 'e69fb303e035192a0ee38a34e4b25024'
        temp_file_id = '40bc92d7eb4a77988f274f2e6862d42a'
        file_upload_temp_dir = '/hive/hubmap/hm_uploads_tmp'
        extra_headers = {
            'Content-Type': 'application/json', 
            'X-Hubmap-Application': 'ingest-api'
        }

        def resp1():
            r = requests.Response()
            r.status_code = 200
            r.json = lambda: {'thumbnail_file': {'filename': 'thumbnail.jpg', 'file_uuid': 'fc95dd0faaf2cfc4786d89bf7b074485'}}
            return r
        mock_get_entities.side_effect = [resp1()]

        def resp2():
            r = requests.Response()
            r.status_code = 200
            r.json = lambda: {}
            return r
        mock_put_entities.side_effect = [resp2()]

        mock_mkdir = MagicMock()
        mock_copy2 = MagicMock()

        self.assertTrue('thumbnail_file' not in mock_put_entities.json())

        # Create fake file and verify existence
        orig_file_path = dataset_dict['thumbnail_file_abs_path']
        self.assertFalse(os.path.exists(orig_file_path))
        self.fs.create_file(orig_file_path)
        self.assertTrue(os.path.exists(orig_file_path))

        updated_dataset_dict =\
            self.dataset_helper.handle_thumbnail_file(dataset_dict, self.entity_api, dataset_uuid, extra_headers,
                                                      temp_file_id, file_upload_temp_dir)

        mock_get_entities.assert_called()
        mock_put_entities.assert_called()
        mock_put_entities.assert_called()
        # Verify resulting value
        self.assertFalse('thumbnail_file_abs_path' in updated_dataset_dict)
        self.assertTrue('thumbnail_file_to_add' in updated_dataset_dict)
        self.assertEquals(updated_dataset_dict['thumbnail_file_to_add']['temp_file_id'], temp_file_id)

        # Verify the thumbnail file is copied to the temp file dir
        # TODO: Joe: You are not really touching the file system so you can't verify that the file system changed. You could "mock" the response from os.path.join but I don't think that would be useful. You can only test for things that have happened.
        temp_file_path = os.path.join(file_upload_temp_dir, temp_file_id, 'thumbnail.jpg')
        #self.assertTrue(os.path.exists(temp_file_path))

        # Why failed? mock_get_entities.json() returns empty {}
        # TODO: Joe: It fails because you set it up to be called only once in the '.side_effect' here you are calling it a second time. But I have no clue as to why you would want to call it here. What is important is hat it get's called in the test and there is already an assert that passes for that earlier... Just delete this.
        #self.assertTrue('thumbnail_file' in mock_get_entities.json())

if __name__ == "__main__":
    import nose2
    nose2.main()
