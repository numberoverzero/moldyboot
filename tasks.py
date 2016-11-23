import json
import pathlib
import contextlib
import tempfile
import configparser
import os
import sys

import gaas

import paramiko
from invoke import task

API_DEPLOY_USER = "deploy"
API_HOST_IP = "138.197.232.23"
PROFILE_NAME = "api.moldyboot.com@prod.005"

HERE = os.path.abspath(os.path.dirname(__file__))
WHL_NAME = "gaas-{v}-py3-none-any.whl".format(v=gaas.__version__)


@task
def clean(ctx):
    patterns = ["build", "dist"]
    for pattern in patterns:
        ctx.run("rm -rf {}".format(pattern))


@task(pre=[clean])
def build(ctx):
    ctx.run("python setup.py bdist_wheel")


@task(pre=[build])
def deploy(ctx):
    dst = "/services/api/"

    print("Copying gaas.whl, server requirements, and credentials to host")
    copy_file("dist/" + WHL_NAME, dst + WHL_NAME)
    copy_file("nginx/api/requirements.txt", dst + "requirements.txt")
    with credentials_file(PROFILE_NAME) as file:
        copy_file(file.name, dst + ".credentials/aws")

    print("Copying server artifacts to host")
    copy_file("nginx/api/serve.sh", dst + "serve.sh")
    copy_file("nginx/api/server.py", dst + "server.py")
    copy_file("nginx/api/uwsgi.ini", dst + "uwsgi.ini")
    copy_file("nginx/api/api.moldyboot.com", dst + "api.moldyboot.com")
    print("If the systemd api.service has changed, you will need to manually copy it over.")

    in_venv = "source /services/api/.venv/bin/activate && "

    remote_commands(
        in_venv + "pip install -r/services/api/requirements.txt",
        in_venv + "pip install --upgrade " + dst + WHL_NAME,
        "sudo systemctl restart api",
    )


def copy_file(localpath, remotepath, hostname=API_HOST_IP, username=API_DEPLOY_USER):
    with ssh_client(hostname=hostname, username=username) as client:
        sftp = client.open_sftp()  # type: paramiko.SFTPClient
        sftp.put(localpath, remotepath, confirm=True)


def remote_commands(*commands, hostname=API_HOST_IP, username=API_DEPLOY_USER):
    with ssh_client(hostname=hostname, username=username) as client:
        for command in commands:
            print("EXECUTING: " + command)
            _, stdout, stderr = client.exec_command(command)
            stdout, stderr = stdout.read(), stderr.read()  # type: bytes
            stdout and (sys.stdout.write(stdout.decode("utf-8")), sys.stdout.flush())
            stderr and (sys.stderr.write(stderr.decode("utf-8")), sys.stderr.flush())


@contextlib.contextmanager
def credentials_file(profile_name):
    with pathlib.Path("~/.aws/config").expanduser().open() as credentials:
        config = configparser.ConfigParser()
        config.read_file(credentials)
        section_name = "profile " + profile_name
        config_values = dict(config[section_name])

    # config file uses "region", session kwarg uses "region_name"
    config_values["region_name"] = config_values.pop("region")

    with tempfile.NamedTemporaryFile(mode="w+", encoding="utf-8", delete=True) as file:
        json.dump(config_values, file, indent=4, sort_keys=True)
        file.seek(0)
        yield file


@contextlib.contextmanager
def ssh_client(**kwargs):
    client = paramiko.SSHClient()
    try:
        client.load_system_host_keys()
        client.connect(**kwargs)
        yield client
    finally:
        client.close()
