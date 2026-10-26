import json
import logging
import math
import threading
import time
from datetime import date, datetime, timedelta, time as dt_time
from decimal import Decimal
from uuid import UUID
from zoneinfo import ZoneInfo

import duckdb
from flask import Blueprint, Response, current_app, request
from hubmap_commons.hm_auth import AuthHelper, secured

from app_utils.error import bad_request_error

usage_analytics_blueprint = Blueprint('usage_analytics', __name__)
logger = logging.getLogger(__name__)

# The nightly loaders are scheduled in Eastern time, so the blackout window is too.
# Using the zone name (not a fixed offset) keeps the window correct across daylight saving changes.
EASTERN = ZoneInfo('America/New_York')

# Defaults for the optional settings. Any of these can be overridden in instance/app.cfg.
# The only required setting is USAGE_ANALYTICS_DUCKDB_PATH, the absolute path of the DuckDB file.
DEFAULTS = {
    'USAGE_ANALYTICS_TIMEOUT_SECONDS': 60,
    'USAGE_ANALYTICS_MAX_ROWS': 100000,
    'USAGE_ANALYTICS_MEMORY_LIMIT': '4GB',
    'USAGE_ANALYTICS_THREADS': 4,
    # Per uWSGI worker process. uWSGI runs 16 processes, so the ceiling for the container is 16 times this.
    'USAGE_ANALYTICS_MAX_CONCURRENT_QUERIES': 2,
    'USAGE_ANALYTICS_MAX_QUERY_CHARS': 20000,
    # Same-day window in Eastern time, 24 hour HH:MM. A window that crosses midnight is not supported.
    # Set to same value to have no blackout/maintenance window.
    'USAGE_ANALYTICS_BLACKOUT_START': '02:15',
    'USAGE_ANALYTICS_BLACKOUT_END': '02:15',
}

# Created on first use, once per uWSGI worker process (see _get_semaphore).
_semaphore = None
_semaphore_lock = threading.Lock()


def _cfg(name):
    return current_app.config.get(name, DEFAULTS.get(name))


def _get_semaphore():
    global _semaphore
    if _semaphore is None:
        with _semaphore_lock:
            if _semaphore is None:
                _semaphore = threading.BoundedSemaphore(int(_cfg('USAGE_ANALYTICS_MAX_CONCURRENT_QUERIES')))
    return _semaphore


def _json_error(status, message, retry_after=None):
    headers = {}
    if retry_after is not None:
        headers['Retry-After'] = str(int(retry_after))
    return Response(json.dumps({'error': message}), status, mimetype='application/json', headers=headers)


def _json_default(value):
    # DuckDB returns Python date/datetime/Decimal/UUID/bytes objects that the json module cannot encode.
    # Flask's own provider would write datetimes in HTTP-date format, so the conversion is done here instead.
    if isinstance(value, (datetime, date, dt_time)):
        return value.isoformat()
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, timedelta):
        return value.total_seconds()
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value).hex()
    return str(value)


def _make_json_safe(value):
    # NaN and infinity have no JSON representation (Python's json module would write bare NaN/Infinity tokens,
    # which strict parsers reject), so they are returned as strings. Applied only when a response contains one.
    if isinstance(value, float):
        if math.isnan(value):
            return 'NaN'
        if math.isinf(value):
            return 'Infinity' if value > 0 else '-Infinity'
        return value
    if isinstance(value, (list, tuple)):
        return [_make_json_safe(item) for item in value]
    if isinstance(value, dict):
        return {key: _make_json_safe(item) for key, item in value.items()}
    return value


def _parse_hhmm(value):
    hours, minutes = str(value).split(':')
    return dt_time(int(hours), int(minutes))


def _seconds_until_blackout_ends(now=None):
    """
    Return the number of seconds until the nightly blackout window ends if the current Eastern time
    is inside the window, otherwise None.

    Parameters
    ----------
    now : datetime, optional
        A timezone-aware datetime in the Eastern zone. Defaults to the current time. Used by tests.
    """
    now = now or datetime.now(EASTERN)
    start = _parse_hhmm(_cfg('USAGE_ANALYTICS_BLACKOUT_START'))
    end = _parse_hhmm(_cfg('USAGE_ANALYTICS_BLACKOUT_END'))
    if start <= now.time() < end:
        end_today = now.replace(hour=end.hour, minute=end.minute, second=0, microsecond=0)
        return max(1, int((end_today - now).total_seconds()))
    return None


def _validate_single_select(sql):
    """
    Reject anything that is not exactly one SELECT statement. The parse happens on a throwaway in-memory
    connection, so a malformed request never touches the database file or its lock.
    """
    probe = duckdb.connect()
    try:
        statements = probe.extract_statements(sql)
    except duckdb.Error as e:
        bad_request_error(f"The SQL could not be parsed: {e}")
    finally:
        probe.close()
    if len(statements) != 1:
        bad_request_error("Exactly one SQL statement is required.")
    if str(statements[0].type) != 'StatementType.SELECT':
        bad_request_error("Only SELECT statements are allowed.")


def _requesting_user():
    # Used only for the audit log. A failure here must never break the request.
    try:
        user_info = AuthHelper.instance().getUserInfoUsingRequest(request, False)
        if isinstance(user_info, dict):
            return user_info.get('email') or user_info.get('sub') or 'unknown'
    except Exception:
        pass
    return 'unknown'


def _run_query(sql, db_path, user):
    max_rows = int(_cfg('USAGE_ANALYTICS_MAX_ROWS'))
    timeout_seconds = float(_cfg('USAGE_ANALYTICS_TIMEOUT_SECONDS'))
    started = time.monotonic()
    outcome = 'error'
    row_count = 0
    con = None
    timer = None
    try:
        # A new read-only connection for every request, closed in the finally block below. Nothing holds the
        # file open between requests, so the nightly loaders (which open it read-write) are not blocked.
        try:
            con = duckdb.connect(db_path, read_only=True, config={
                'threads': int(_cfg('USAGE_ANALYTICS_THREADS')),
                'memory_limit': str(_cfg('USAGE_ANALYTICS_MEMORY_LIMIT')),
                'enable_external_access': False,
            })
            # Stops the submitted SQL from changing the limits or turning external access back on.
            con.execute('SET lock_configuration = true')
        except duckdb.IOException as e:
            # Typically "Could not set lock on file ... Conflicting lock is held in ..." while a loader is writing.
            outcome = 'database_unavailable'
            logger.warning(f"Usage analytics database could not be opened: {e}")
            return _json_error(503, 'The usage analytics database is temporarily unavailable. Retry shortly.',
                               retry_after=60)

        # The timer interrupts the running query, including the fetch below, once the time limit is reached.
        timer = threading.Timer(timeout_seconds, con.interrupt)
        timer.daemon = True
        timer.start()

        result = con.execute(sql)
        column_names = [column[0] for column in result.description]
        column_types = [str(column[1]) for column in result.description]
        fetched = result.fetchmany(max_rows + 1)
        truncated = len(fetched) > max_rows
        rows = fetched[:max_rows]
        row_count = len(rows)
        elapsed_ms = int((time.monotonic() - started) * 1000)

        payload = {
            'columns': column_names,
            'column_types': column_types,
            'rows': rows,
            'row_count': row_count,
            'truncated': truncated,
            'max_rows': max_rows,
            'elapsed_ms': elapsed_ms,
            'notes': 'All timestamps in this database are UTC.',
        }
        outcome = 'truncated' if truncated else 'ok'
        try:
            body = json.dumps(payload, default=_json_default, allow_nan=False)
        except ValueError:
            # At least one NaN or infinity in the rows.
            payload['rows'] = _make_json_safe(rows)
            body = json.dumps(payload, default=_json_default, allow_nan=False)
        return Response(body, 200, mimetype='application/json')
    except duckdb.InterruptException:
        outcome = 'timeout'
        return _json_error(408, f"The query exceeded the {int(timeout_seconds)} second limit and was cancelled. "
                                f"Filter on a date range (download_date or request_date) to make it cheaper.")
    except duckdb.IOException as e:
        outcome = 'database_unavailable'
        logger.warning(f"Usage analytics database I/O error while running a query: {e}")
        return _json_error(503, 'The usage analytics database is temporarily unavailable. Retry shortly.',
                           retry_after=60)
    except duckdb.Error as e:
        # Syntax errors, unknown tables or columns, out of memory, blocked operations, and so on.
        outcome = 'query_error'
        logger.warning(f"Usage analytics query rejected due to DuckDB error: {e}")
        return _json_error(400, 'Invalid query or unsupported operation.')
    except Exception:
        outcome = 'server_error'
        logger.exception('Unexpected error while running a usage analytics query')
        return _json_error(500, 'Unexpected error while running the query. Check the logs.')
    finally:
        if timer is not None:
            timer.cancel()
        if con is not None:
            con.close()
        # Audit record: this endpoint can return personal data, so who ran what is kept in the log.
        elapsed_ms = int((time.monotonic() - started) * 1000)
        logger.info(f"usage-analytics query user={user} outcome={outcome} rows={row_count} "
                    f"elapsed_ms={elapsed_ms} sql={sql[:500]!r}")


"""
Run a read-only SQL query against the usage analytics DuckDB database.

The database holds file download events (file_download, hot_file_download) and API Gateway request
records (api_usage). It contains personal data (user emails, IP addresses, geolocation), and every
user with HuBMAP-read access can query all of it. Queries are logged.

Input
--------
POST request with a JSON body:
    query : str
        Exactly one SELECT statement. Required.

Returns
--------
200 JSON object:
    columns, column_types, rows (list of lists), row_count,
    truncated (true when the result was cut off at max_rows), max_rows, elapsed_ms, notes
400 invalid body, SQL that cannot be parsed or run, or a statement that is not a single SELECT
401/403 missing or invalid token, or no HuBMAP-read membership
408 the query ran longer than the time limit and was cancelled
429 too many queries are already running in this worker (Retry-After header)
503 the database is not configured, a loader is writing to it, or the nightly blackout window
    (about 2:15 to 3:30 AM Eastern) is in effect (Retry-After header)

All timestamps in the database are UTC. NaN and infinite floating point values are returned as the
strings "NaN", "Infinity" and "-Infinity", because JSON has no way to represent them.
"""
@usage_analytics_blueprint.route('/usage-analytics/query', methods=['POST'])
@secured(groups="HuBMAP-read")
def usage_analytics_query():
    db_path = _cfg('USAGE_ANALYTICS_DUCKDB_PATH')
    if not db_path:
        return _json_error(503, 'The usage analytics database is not configured on this server.')

    retry_after = _seconds_until_blackout_ends()
    if retry_after is not None:
        return _json_error(503, f"Usage analytics queries are unavailable during the nightly data load "
                                f"(about {_cfg('USAGE_ANALYTICS_BLACKOUT_START')} to "
                                f"{_cfg('USAGE_ANALYTICS_BLACKOUT_END')} Eastern).",
                           retry_after=retry_after)

    if not request.is_json:
        bad_request_error('A JSON body and the Content-Type header application/json are required.')
    body = request.get_json(silent=True)
    if not isinstance(body, dict) or not isinstance(body.get('query'), str) or not body['query'].strip():
        bad_request_error('The JSON body must contain a non-empty string "query".')
    sql = body['query'].strip()
    max_chars = int(_cfg('USAGE_ANALYTICS_MAX_QUERY_CHARS'))
    if len(sql) > max_chars:
        bad_request_error(f"The query is longer than the {max_chars} character limit.")

    _validate_single_select(sql)

    semaphore = _get_semaphore()
    if not semaphore.acquire(timeout=5):
        return _json_error(429, 'Too many usage analytics queries are running on this server. Retry shortly.',
                           retry_after=5)
    try:
        return _run_query(sql, db_path, _requesting_user())
    finally:
        semaphore.release()
