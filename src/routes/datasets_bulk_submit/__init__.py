from flask import Blueprint, current_app, jsonify
import logging
from threading import Thread
from utils.rest import abort_bad_req, abort_not_found, abort_internal_err
from lib.decorators import require_data_admin, require_json
from routes.datasets_bulk_submit.dataset_helper import DatasetHelper
from routes.datasets_bulk_submit.tasks import submit_datasets

datasets_bulk_submit_blueprint = Blueprint('datasets_bulk_submit', __name__)
logger = logging.getLogger(__name__)


@datasets_bulk_submit_blueprint.route('/datasets/bulk/submit', methods=['PUT'])
@require_data_admin(param='token')
@require_json(param='uuids')
def submit_datasets_from_bulk(uuids: list, token: str):
    if not isinstance(uuids, list) or len(uuids) == 0:
        abort_bad_req('A list of dataset uuids is required')

    dataset_helper: DatasetHelper = DatasetHelper(current_app.config)
    uuids = set(uuids)
    try:
        fields = {'uuid'}
        datasets = dataset_helper.get_datasets_by_uuid(uuids, fields)
    except Exception as e:
        logger.error(f'Error while submitting datasets: {str(e)}')
        abort_internal_err(str(e))

    if datasets is None:
        abort_not_found('No datasets found with any of the provided uuids')

    diff = uuids.difference({dataset['uuid'] for dataset in datasets})
    if len(diff) > 0:
        abort_not_found(f"No datasets found with the following uuids: {', '.join(diff)}")

    try:
        Thread(target=submit_datasets, args=[uuids, token, current_app.config]).start()
        logger.info(
            f'Started to submit datasets for processing with uuids: {uuids}'
        )
    except Exception as e:
        logger.error(f'Error while submitting datasets: {str(e)}')
        abort_internal_err(str(e))

    # return a 202 reponse with the accepted dataset uuids
    return jsonify(list(uuids)), 202
