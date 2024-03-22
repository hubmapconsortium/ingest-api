import logging
from lib.services import bulk_update_entities

logger = logging.getLogger(__name__)


def submit_datasets(dataset_uuids: list, token: str, config: dict):
    entity_api_url = config["ENTITY_WEBSERVICE_URL"]

    # change the status of the datasets to Processing using entity-api
    update_payload = {uuid: {"status": "Processing"} for uuid in dataset_uuids}
    update_status_res = bulk_update_entities(
        update_payload, token, entity_api_url=entity_api_url
    )

    # get the datasets that were successfully updated, log the ones that failed
    processing_datasets = [
        dataset["data"] for dataset in update_status_res.values() if dataset["success"]
    ]
    for uuid, res in update_status_res.items():
        if not res["success"]:
            logger.error(
                f"Failed to set dataset status to processing {uuid}: {res['data']}"
            )
    logger.info(f"Sending datasets to ingest-pipeline: {processing_datasets}")

    # # create the ingest_payload list
    # dataset_helper = DatasetHelper(config)
    # ingest_payload = [
    #     dataset_helper.create_ingest_payload(dataset) for dataset in processing_datasets
    # ]

    # # submit the datasets to the processing pipeline
    # ingest_pipline_url = (
    #     ensureTrailingSlashURL(config["INGEST_PIPELINE_URL"]) + "request_bulk_ingest"
    # )
    # try:
    #     ingest_res = requests.post(
    #         ingest_pipline_url,
    #         json=ingest_payload,
    #         headers={"Authorization": f"Bearer {token}"},
    #     )
    # except requests.exceptions.RequestException as e:
    #     ingest_res = None
    #     logger.error(f"Failed to submit datasets to pipeline: {e}")

    # if ingest_res and (ingest_res.status_code == 200 or ingest_res.status_code == 400):
    #     # assumes a 200/400 status code with json of the form
    #     # 200:
    #     # {
    #     #   "response": [
    #     #     {
    #     #       "ingest_id": "",
    #     #       "run_id": "",
    #     #       "submission_id": ""
    #     #     }, ...
    #     #   ]
    #     # }
    #     #
    #     # 400:
    #     # {
    #     #   "response": {
    #     #     "error": [
    #     #       {
    #     #         "message": "",
    #     #         "submission_id" : "",
    #     #       }, ...
    #     #     ],
    #     #     "success":[
    #     #       {
    #     #         "ingest_id": "",
    #     #         "run_id": "",
    #     #         "submission_id": "",
    #     #       }, ...
    #     #     ]
    #     #   }
    #     # }

    #     # update the datasets with the received info from the pipeline
    #     pipeline_result = ingest_res.json().get("response", {})
    #     update_payload = {
    #         s["submission_id"]: {
    #             "ingest_id": s["ingest_id"],
    #             "run_id": s["run_id"]
    #         }
    #         for s in pipeline_result.get("success", [])
    #     }
    #     error_payload = {
    #         e["submission_id"]: {
    #             "status": "Error",
    #             "pipeline_message": e["message"],
    #         }
    #         for e in pipeline_result.get("error", [])
    #     }
    #     update_payload.update(error_payload)

    #     update_res = bulk_update_entities(
    #         update_payload, token, entity_api_url=entity_api_url
    #     )

    #     # log the datasets that failed to update
    #     for uuid, res in update_res.items():
    #         if not res["success"]:
    #             logger.error(
    #                 f"Failed to set dataset ingest info or pipeline message {uuid}: "
    #                 f"{res['data']}"
    #             )

    # else:
    #     # request failed, update the datasets to error
    #     update_payload = {
    #         dataset["uuid"]: {
    #             "status": "Error",
    #             "pipeline_message": "Failed to submit to pipeline",
    #         }
    #         for dataset in processing_datasets
    #     }
    #     update_errored_res = bulk_update_entities(
    #         update_payload, token, entity_api_url=entity_api_url
    #     )

    #     # log the datasets that failed to update
    #     for uuid, res in update_errored_res.items():
    #         if not res["success"]:
    #             logger.error(
    #                 f"Failed to set status and pipeline message {uuid}: {res['data']}"
    #             )
