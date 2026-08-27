import logging
import json
from flask import Blueprint, request, current_app, jsonify
from stringcase import lowercase

from app_utils.error import internal_server_error
from utils.rest import abort_bad_req
from lib.decorators import require_data_admin, require_json, require_valid_token
import mysql.connector

logs_blueprint = Blueprint('logs', __name__)
logger = logging.getLogger(__name__)


@logs_blueprint.route('/logs', methods=['POST'])
@require_valid_token(param='token')
@require_json(param='log')
def create_log(log: dict):
    if not isinstance(log, dict):
        abort_bad_req('Must supply the log to be ingested.')

    app_name = log.get('app_name', 'ingest-ui')
    log_level = log.get('log_level', 'error')
    page_path = log.get('page_path')
    message = f"{log.get('message', '')}" # should be a string, but cast incase
    error_details = log.get('error_details')
    browser_info = log.get('browser_info')

    if len(message) <= 0:
        abort_bad_req('Must include a message to be logged')

    if error_details is not None and isinstance(error_details, dict):  # can be dict so cast to string
        error_details = json.dumps(error_details)

    if browser_info is not None and isinstance(browser_info, dict): # can be dict so cast to string
        browser_info = json.dumps(browser_info)

    if app_name not in ['ingest-ui', 'data-ingest-board']:
        abort_bad_req(f'Unsupported application {app_name}.')

    if log_level not in ['info', 'warn', 'error', 'fatal']:
        abort_bad_req(f'Unsupported log level {log_level}.')


    x_forwarded_for = request.headers.get('X-Forwarded-For')
    if x_forwarded_for:
        client_ip = x_forwarded_for.split(',')[0].strip()
    else:
        client_ip = request.remote_addr


    conn = get_mysql_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            INSERT INTO logs (app_name, log_level, page_path, message, error_details, client_ip, browser_info)
            VALUES (%s, %s, %s,  %s, %s, %s, %s)
            """,
            (app_name, log_level, page_path, message, error_details, client_ip, browser_info),
        )
        conn.commit()
    except Exception:
        conn.rollback()
        logger.exception(f"Failed to insert log row for app_name {app_name} {message} {error_details}")
        internal_server_error("Failed to create log record")
    finally:
        cursor.close()
        conn.close()

    return jsonify({'message': 'Logged successfully.'}), 200


@logs_blueprint.route('/logs/meta', methods=['GET'])
@require_valid_token(param='token')
def get_logs_count():
    # Valid token is required by the gateway
    where_column = request.args.get('column')
    where_value = request.args.get('value')

    valid_column_names = get_valid_column_names()

    if where_column is not None:
        if where_column not in valid_column_names:
            abort_bad_req(f'Not a valid column name "{where_column}".')
        try:
            if where_column == 'id':
                where_value = int(where_value)
        except ValueError:
            abort_bad_req(f'Not a valid column id {where_value}.')

    conn = None
    rows = []
    try:
        conn = get_mysql_connection()
        cursor = conn.cursor(dictionary=True)
        try:
            if where_column is not None and where_value is not None:
                cursor.execute(
                    f"""
                    SELECT count(*) as total_logs
                      FROM logs
                     WHERE `{where_column}` like %s
                    """,
                    (f"%{where_value}%"),
                )
            else:
                cursor.execute(
                    """
                    SELECT count(*) as total_logs
                      FROM logs 
                    """,
                )
            rows = cursor.fetchall()
        finally:
            cursor.close()
    except mysql.connector.Error:
        logger.exception(f"MySQL error while fetching logs count on {where_column} {where_value}")
        internal_server_error("Failed to retrieve logs. Please try again or contact support.")
    finally:
        if conn is not None:
            conn.close()
    result = rows[0] if len(rows) > 0 else {}
    return jsonify(result), 200

@logs_blueprint.route('/logs', methods=['GET'])
@require_data_admin(param='token')
def get_logs():
    # Valid token is required by the gateway
    where_column = request.args.get('column')
    where_value = request.args.get('value')
    order_by = request.args.get('order_by', 'id')
    order = request.args.get('order', 'desc')
    page_number = request.args.get('page', 1)
    max_limit = 10
    limit = request.args.get('limit', f'{max_limit}')
    try:
        page_number = int(page_number)
    except ValueError:
        page_number = 1
    try:
        limit = int(limit)
    except ValueError:
        limit = max_limit
    try:
        if where_column == 'id':
            where_value = int(where_value)
    except ValueError:
        abort_bad_req(f'Not a valid column id {where_value}.')

    offset = (page_number - 1) * limit

    if order is not None:
        if lowercase(order) not in ['desc', 'asc']:
            abort_bad_req(f'Not a valid order direction "{order}".')

    valid_column_names = get_valid_column_names()

    if order_by is not None:
        if order_by not in valid_column_names:
            abort_bad_req(f'Not a valid column name "{order_by}".')

    if where_column is not None:
        if where_column not in valid_column_names:
            abort_bad_req(f'Not a valid column name "{where_column}".')

    conn = None
    rows = []
    try:
        conn = get_mysql_connection()
        cursor = conn.cursor(dictionary=True)
        try:
            has_filter = where_column is not None and where_value is not None
            filter_query = f" WHERE `{where_column}` like %s " if has_filter else " "
            params = (f"%{where_value}%")  if has_filter else ()
            cursor.execute(
                f"""
                SELECT *
                  FROM logs
                 {filter_query}
                 ORDER BY {order_by} {order} LIMIT {limit} OFFSET {offset}
                """,
                params,
            )
            rows = cursor.fetchall()
        finally:
            cursor.close()
    except mysql.connector.Error as mysqlError:
        logger.exception(f"MySQL error while fetching logs on {where_column} {where_value}")
        internal_server_error("Failed to retrieve logs. Please try again or contact support.")
    finally:
        if conn is not None:
            conn.close()

    return jsonify(rows), 200

def get_valid_column_names():
    return ['app_name', 'message', 'log_level', 'id', 'page_path', 'browser_info', 'timestamp']

def get_mysql_connection():
    return mysql.connector.connect(
        host=current_app.config['MYSQL_HOST'],
        port=int(current_app.config['MYSQL_PORT']),
        user=current_app.config['MYSQL_USER'],
        password=current_app.config['MYSQL_PASSWORD'],
        database=current_app.config['MYSQL_DATABASE'],
        charset='utf8mb4',
        autocommit=False,
    )