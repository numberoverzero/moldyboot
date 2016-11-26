#!/usr/bin/env bash
# system.d entry point
source /.venvs/api/bin/activate
cd /services/api
python rq-worker.py
