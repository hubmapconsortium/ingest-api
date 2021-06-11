from flask import json
from dataset import Dataset
from src.dataset_helper_object import DatasetHelper


def update_ingest_status(app_config, request_json, request_headers, logger):
    dataset = Dataset(app_config)
    logger.info("++++++++++Calling /datasets/status")
    logger.info("++++++++++Request:" + json.dumps(request_json))
    # expecting something like this:
    # {'dataset_id' : '287d61b60b806fdf54916e3b7795ad5a', 'status': '<', 'message': 'the process ran', 'metadata': [maybe some metadata stuff]}
    updated_ds = dataset.get_dataset_ingest_update_record(request_json)

    if updated_ds['status'].upper() == 'QA':
        # Update the title
        bearer_token = request_headers['AUTHORIZATION'].strip()
        nexus_token = bearer_token[len('bearer '):].strip()
        dataset_helper = DatasetHelper()
        updated_ds['title'] = dataset_helper.generate_dataset_title(updated_ds, nexus_token)

    return updated_ds

