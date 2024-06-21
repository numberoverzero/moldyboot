import os
from setuptools import setup, find_packages
HERE = os.path.abspath(os.path.dirname(__file__))


def get_version():
    with open(os.path.join(HERE, "moldyboot/__init__.py")) as f:
        for line in f:
            if line.startswith("__version__"):
                return eval(line.split("=")[-1])

requirements = [
    "bcrypt==3.1.1",
    "bloop>=2.0",
    "boto3>=1.4",
    "click==6.6",
    "cryptography==42.0.8",
    "falcon==1.0.0",
    "falcon-cors==1.0.1",
    "httpie==3.2.2",
    "humanize==0.5.1",
    "pendulum==1.1.0",
    "pystache==0.6.5",
    "rq==0.6.0",
    "uritools==1.0.2"
]


if __name__ == "__main__":
    setup(
        name="moldyboot",
        version=get_version(),
        author="Joe Cross",
        author_email="joe.mcross@gmail.com",
        url="https://github.com/numberoverzero/moldyboot",
        include_package_data=True,
        packages=find_packages(exclude=["console", "tests*"]),
        install_requires=requirements,
    )
