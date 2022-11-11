import os
import redis
from rq import Worker, Queue, Connection
from hubmap_commons.hm_auth import AuthHelper
import logging
from flask import Flask
from worker.utils import thread_extract_cell_count_from_secondary_analysis_files_for_sample_uuid


logging.basicConfig(format='[%(asctime)s] %(levelname)s in %(module)s: %(message)s',
                    level=logging.DEBUG,
                    datefmt='%Y-%m-%d %H:%M:%S')

logger = logging.getLogger(__name__)

app = Flask(__name__,
            instance_path=os.path.join(os.path.abspath(os.path.dirname(__file__)), 'instance'),
            instance_relative_config=True)
app.config.from_pyfile('app.cfg')

client_id = app.config['APP_CLIENT_ID']
client_secret = app.config['APP_CLIENT_SECRET']
redis_url = app.config['REDIS_URL'].rstrip('/')

logger.info(f'redis_url: {redis_url}')

try:
    if AuthHelper.isInitialized() is False:
        auth_helper_instance = AuthHelper.create(client_id, client_secret)
        logger.info("Initialized AuthHelper class successfully :)")
except Exception:
    msg = "Failed to initialize the AuthHelper class"
    # Log the full stack trace, prepend a line with our message
    logger.exception(msg)

# Called from uwsgi.ini 'attach-daemon = python worker.py'
#
# On the container to check to see if the network is really there...
# $ yum install net-tools
# $ ifconfig -a
#
# $ yum install iputils (on ingest-api)
# $ docker exec ingest-api ping spatial-api -c2 (on OS X terminal)
# PING spatial-api (172.20.0.6) 56(84) bytes of data.
# 64 bytes from spatial-api.docker_hubmap (172.20.0.6): icmp_seq=1 ttl=64 time=0.253 ms
# 64 bytes from spatial-api.docker_hubmap (172.20.0.6): icmp_seq=2 ttl=64 time=0.246 ms
#
# See what containers are using the hubmap docker network...
# $ docker network inspect docker_hubmap
#
# Add the docker spatial-api to the netwprk that ingest-api and friends are using...
# $ docker network connect docker_hubmap spatial-api

listen = ['Cell Type Count Processing', 'default']
conn = redis.from_url(redis_url)
if __name__ == '__main__':
    with Connection(conn):
        worker = Worker(list(map(Queue, listen)))
        worker.work()
