""" Setup file """
import os
from setuptools import setup, find_packages
HERE = os.path.abspath(os.path.dirname(__file__))


def get_requirements():
    with open(os.path.join(HERE, "requirements.txt")) as f:
        return [line.strip() for line in f.readlines()]


if __name__ == "__main__":
    setup(
        name="gaas",
        author="Joe Cross",
        author_email="joe.mcross@gmail.com",
        url="https://github.com/numberoverzero/gaas",
        include_package_data=True,
        packages=find_packages(exclude=("tests", "docs", "examples")),
        install_requires=get_requirements(),
    )
