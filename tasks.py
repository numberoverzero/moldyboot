import json
import pathlib
import contextlib
import tempfile
import configparser
import os
import subprocess
import sys

import moldyboot

import paramiko
from invoke import task

API_DEPLOY_USER = "deploy"
API_HOST_IP = "138.197.232.23"
PROFILE_NAME = "api.moldyboot.com@prod.005"

HERE = os.path.abspath(os.path.dirname(__file__))
WHL_NAME = "moldyboot-{v}-py3-none-any.whl".format(v=moldyboot.__version__)


@task
def clean(ctx):
    patterns = ["build", "dist"]
    for pattern in patterns:
        ctx.run("rm -rf {}".format(pattern))


@task(pre=[clean])
def build(ctx):
    ctx.run("python setup.py bdist_wheel")


@task(pre=[build])
def deploy(ctx, nginx=True, ops=True, api=True, console=True):
    if nginx:
        deploy_nginx()
    if ops:
        deploy_ops()
    if api:
        deploy_api()
    if console:
        deploy_console()
    remote_commands("sudo service nginx restart")


def deploy_nginx():
    print("=" * 80)
    print("Deploying Nginx")
    print("-" * 80)
    copy_files(
        ("nginx/conf.nginx", "/etc/nginx/nginx.conf"),
        ("nginx/certs/origin-pull.pem", "/etc/nginx/certs/cloudflare/origin-pull.pem"),
        ("nginx/certs/x3-cross-signed.pem", "/etc/nginx/certs/letsencrypt/x3-cross-signed.pem")
    )


def deploy_ops():
    print("=" * 80)
    print("Deploying Ops Tools")
    print("-" * 80)
    dst = "/ops/"
    with credentials_file(PROFILE_NAME) as file:
        copy_files(
            (file.name, dst + ".credentials/aws"),
            ("nginx/ops/mb", dst + "mb"),
            ("dist/" + WHL_NAME, dst + WHL_NAME),
            ("requirements.txt", dst + "requirements.txt")
        )
    in_venv = "source /.venvs/ops/bin/activate && "
    remote_commands(
        in_venv + "pip install -r/ops/requirements.txt",
        in_venv + "pip install --upgrade " + dst + WHL_NAME,
    )


def deploy_api():
    print("=" * 80)
    print("Deploying API")
    print("-" * 80)

    dst = "/services/api/"
    with credentials_file(PROFILE_NAME) as file:
        copy_files(
            # shared files
            (file.name, dst + ".credentials/aws"),
            ("dist/" + WHL_NAME, dst + WHL_NAME),
            ("nginx/api/requirements.txt", dst + "requirements.txt"),

            # rq worker
            ("nginx/api/worker.sh", dst + "worker.sh"),
            ("nginx/api/rq-worker.py", dst + "rq-worker.py"),

            # https
            ("nginx/api/serve.sh", dst + "serve.sh"),
            ("nginx/api/server.py", dst + "server.py"),
            ("nginx/api/uwsgi.ini", dst + "uwsgi.ini"),
            ("nginx/api/api.moldyboot.com.nginx", dst + "api.moldyboot.com")
        )

    in_venv = "source /.venvs/api/bin/activate && "
    remote_commands(
        in_venv + "pip install -r/services/api/requirements.txt",
        in_venv + "pip install --upgrade " + dst + WHL_NAME,
        "sudo systemctl restart api",
        "sudo systemctl restart rq-worker",
    )


def deploy_console():
    print("=" * 80)
    print("Deploying Console")
    print("-" * 80)

    # console is in an adjacent project, ../moldyboot-console
    console_root = os.path.join(HERE, "..", "moldyboot-console")
    subprocess.run(["cd", str(console_root), "&&", "make" "production"])
    dst = "/services/console/"
    copy_files(
        (os.path.join(HERE, "nginx/console/console.moldyboot.com.nginx"), dst + "console.moldyboot.com"),
        (os.path.join(console_root, "dist", "server.tar.gz"), dst + "console.tar.gz")
    )

    remote_commands(
        ("mkdir -p " + dst + "static"),
        ("tar xf {} -C {}".format(dst + "console.tar.gz", dst + "static"))
    )


def copy_files(*files, hostname=API_HOST_IP, username=API_DEPLOY_USER):
    with ssh_client(hostname=hostname, username=username) as client:
        sftp = client.open_sftp()  # type: paramiko.SFTPClient
        for local, remote in files:
            print("cp {} >> {}".format(local, remote))
            sftp.put(local, remote, confirm=True)


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
