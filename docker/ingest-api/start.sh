#!/bin/bash

# Start nginx in background
# 'daemon off;' is nginx configuration directive
nginx -g 'daemon off;' &

/usr/local/bin/python3.13 /usr/src/app/src/jobq_workers.py &

# Start uwsgi and keep it running in foreground
/usr/local/python3.13/bin/uwsgi --ini /usr/src/app/src/uwsgi.ini
