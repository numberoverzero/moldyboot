#!/usr/bin/env bash
# system.d entry point
source /services/console/.venv/bin/activate
cd /services/console
uwsgi --ini uwsgi.ini
