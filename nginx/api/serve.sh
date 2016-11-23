#!/usr/bin/env bash
# system.d entry point
source /services/api/.venv/bin/activate
cd /services/api
uwsgi --ini uwsgi.ini
