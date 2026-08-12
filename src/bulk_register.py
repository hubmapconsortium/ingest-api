import os
import requests
import logging
from typing import Optional, Dict, Any
from hubmap_commons import file_helper as commons_file_helper
import mysql.connector
from flask import Flask
 
 
logger = logging.getLogger(__name__)
 
# Only using Flask for config importing
app = Flask(
    __name__,
    instance_path=os.path.join(os.path.abspath(os.path.dirname(__file__)), "instance"),
    instance_relative_config=True,
)
app.config.from_pyfile("app.cfg")
 
DB_CONFIG = {
    "host": app.config["MYSQL_HOST"],
    "port": int(app.config["MYSQL_PORT"]),
    "user": app.config["MYSQL_USER"],
    "password": app.config["MYSQL_PASSWORD"],
    "database": app.config["MYSQL_DATABASE"],
    "charset": "utf8mb4",
    "autocommit": False,
}
 
 
_connection = None


def _get_connection():
    global _connection
    if _connection is not None:
        try:
            _connection.ping(reconnect=True, attempts=3, delay=1)
            return _connection
        except mysql.connector.Error as e:
            logger.warning(f"MySQL ping/reconnect failed, opening a new connection: {e}")
    try:
        _connection = mysql.connector.connect(**DB_CONFIG)
        logger.info(
            f"MySQL connection established successfully to "
            f"{DB_CONFIG['host']}:{DB_CONFIG['port']}/{DB_CONFIG['database']}"
        )
    except mysql.connector.Error as e:
        logger.error(
            f"Failed to establish MySQL connection to "
            f"{DB_CONFIG['host']}:{DB_CONFIG['port']}/{DB_CONFIG['database']}: {e}"
        )
        raise
    return _connection
 
def _create_entity(entity_id: str, token: str, record: Optional[Dict[str, Any]], entity_type: str) -> str:
    """
    Create a single entity in entity-api and return its assigned UUID.
    """
    ENTITY_WEBSERVICE_URL = app.config["ENTITY_WEBSERVICE_URL"]
    url = commons_file_helper.ensureTrailingSlashURL(ENTITY_WEBSERVICE_URL) + f"entities/{entity_type}"
    headers = {"Authorization": "Bearer " + token}
    response = requests.post(url, headers=headers, json=record, verify=False)
    if response.status_code > 399:
        raise Exception(
            f"entity-api returned {response.status_code} for internal_id={entity_id}: {response.text}"
        )
    body = response.json()
    return body["uuid"], body.get("hubmap_id")
 
def _record_success(cursor, batch_id: str, internal_id: str, entity_uuid: str, hubmap_id: str) -> None:
    """
    Insert a successful job row.
    """
    cursor.execute(
        """
        INSERT INTO jobs (batch_id, internal_id, entity_uuid, hubmap_id, status)
        VALUES (%s, %s, %s, %s, 'success')
        """,
        (batch_id, internal_id, entity_uuid, hubmap_id),
    ) 
 
def _record_failure(cursor, batch_id: str, internal_id: str, error_detail: str) -> None:
    """
    Insert a failed job row.
    """
    cursor.execute(
        """
        INSERT INTO jobs (batch_id, internal_id, status, error_detail)
        VALUES (%s, %s, 'failed', %s)
        """,
        (batch_id, internal_id, error_detail),
    ) 
 
def _advance_batch(cursor, batch_id: str, succeeded: bool) -> None:
    """
    Increment the batch's success or failed count, then stamp completion if this
    was the final job in the batch.
    """
    if succeeded:
        cursor.execute(
            """
            UPDATE batches
               SET success_count = success_count + 1,
                   status = 'running'
             WHERE batch_id = %s
            """,
            (batch_id,),
        )
    else:
        cursor.execute(
            """
            UPDATE batches
               SET failed_count = failed_count + 1,
                   status = 'running'
             WHERE batch_id = %s
            """,
            (batch_id,),
        )
 
    cursor.execute(
        """
        UPDATE batches
           SET completed_at = NOW(),
               status = CASE
                            WHEN failed_count = 0 THEN 'success'
                            WHEN success_count = 0 THEN 'failed'
                            ELSE 'partial'
                        END
         WHERE batch_id = %s
           AND completed_at IS NULL
           AND success_count + failed_count = total_jobs
        """,
        (batch_id,),
    )
 
 
def register_entity_queued(
    entity_id: str,
    token: str,
    batch_id: Optional[str] = None,
    record: Optional[Dict[str, Any]] = None,
    entity_type: Optional[str] = None,
    temp_id: Optional[str] = None,
) -> None:
    """
    This is the entrypoint for the jobq workers
    """
    if batch_id is None:
        raise ValueError(
            f"register_entity_queued called without batch_id for entity_id={entity_id}"
        )

    internal_id = entity_id

    entity_uuid = None
    hubmap_id = None
    error_detail = None
    try:
        entity_uuid, hubmap_id = _create_entity(entity_id, token, record, entity_type)
        succeeded = True
    except Exception as e:
        succeeded = False
        error_detail = str(e)
        logger.warning(
            "Entity creation failed for batch_id=%s internal_id=%s: %s",
            batch_id, internal_id, error_detail,
        )

    conn = _get_connection()
    max_attempts = 5
    for attempt in range(1, max_attempts + 1):
        cursor = conn.cursor()
        try:
            if succeeded:
                _record_success(cursor, batch_id, internal_id, entity_uuid, hubmap_id)
            else:
                _record_failure(cursor, batch_id, internal_id, error_detail)

            _advance_batch(cursor, batch_id, succeeded)
            conn.commit()
            break
        except mysql.connector.Error as e:
            conn.rollback()
            if e.errno in (1213, 1205) and attempt < max_attempts:
                logger.warning(
                    "Deadlock/lock-timeout on DB write for batch_id=%s internal_id=%s "
                    "(attempt %d/%d), retrying: %s",
                    batch_id, internal_id, attempt, max_attempts, e,
                )
                cursor.close()
                time.sleep(0.1 * attempt)
                continue
            logger.exception(
                "DB write failed for batch_id=%s internal_id=%s operation=%s",
                batch_id, internal_id, "record+advance",
            )
            raise
        except Exception:
            conn.rollback()
            logger.exception(
                "Unexpected DB write failure for batch_id=%s internal_id=%s",
                batch_id, internal_id,
            )
            raise
        finally:
            cursor.close()
