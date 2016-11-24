#!/usr/bin/env bash
# system.d entry point
source /.venvs/console/bin/activate
cd /services/console
uwsgi --ini uwsgi.ini
