import logging
import time
from typing import Optional

import requests
from flask import current_app
from hubmap_commons.file_helper import removeTrailingSlashURL
from requests.adapters import HTTPAdapter, Retry

logger = logging.getLogger(__name__)


def bulk_update_entities(
    entity_updates: dict,
    token: str,
    total_tries: int = 3,
    throttle: float = 5,
    entity_api_url: Optional[str] = None,
) -> None:
    """Bulk update the entities in the entity-api.

    This function supports request throttling and retries.

    Parameters
    ----------
    entity_updates : dict
        The dictionary of entity updates. The key is the uuid and the value is the
        update dictionary.
    token : str
        The groups token for the request.
    total_tries : int, optional
        The number of total requests to be made for each update, by default 3.
    throttle : float, optional
        The time to wait between requests and retries, by default 5.
    entity_api_url : str, optional
        The url of the entity-api, by default None. If None, the url is taken from the
        current_app.config. Parameter is used for separate threads where current_app
        is not available.

    Returns
    -------
    dict
        The results of the bulk update. The key is the uuid of the entity. If
        successful, the value is a dictionary with "success" as True and "data" as the
        entity data. If failed, the value is a dictionary with "success" as False and
        "data" as the error message.
    """
    if entity_api_url is None:
        entity_api_url = current_app.config["ENTITY_WEBSERVICE_URL"]
    entity_api_url = removeTrailingSlashURL(entity_api_url)

    headers = {
        "Authorization": f"Bearer {token}",
        "X-Hubmap-Application": "ingest-api",
    }
    # create a session with retries
    session = requests.Session()
    session.headers = headers
    retries = Retry(
        total=total_tries,
        backoff_factor=throttle,
        status_forcelist=[500, 502, 503, 504],
    )
    session.mount(entity_api_url, HTTPAdapter(max_retries=retries))

    results = {}
    with session as s:
        for idx, (uuid, payload) in enumerate(entity_updates.items()):
            try:
                get_entity_data = {}
                res = s.put(
                    f"{entity_api_url}/entities/{uuid}", json=payload, timeout=15
                )

                if res.ok:
                    # Retrieve the entity details via a GET call - Hacked by Zhou 4/22/2024
                    get_res = s.get(
                        f"{entity_api_url}/entities/{uuid}", json=payload, timeout=15
                    )

                    get_entity_data = get_res.json()
                else:
                    get_entity_data = res.json().get("error")

                results[uuid] = {
                    "success": res.ok,
                    "data": get_entity_data
                }
            except requests.exceptions.RequestException as e:
                logger.error(f"Failed to update entity {uuid}: {e}")
                results[uuid] = {"success": False, "data": str(e)}

            if idx < len(entity_updates) - 1:
                time.sleep(throttle)

    return results
