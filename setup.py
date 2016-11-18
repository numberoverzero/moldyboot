from setuptools import setup, find_packages


requirements = [
    "arrow==0.7.0",
    "bcrypt==2.0.0",
    "bloop==0.9.11",
    "boto3==1.3.1",
    "click==6.6",
    "cryptography==1.5.2",
    "falcon==1.0.0",
    "falcon-cors==1.0.1",
    "hiredis==0.2.0",
    "httpie==0.9.3",
    "humanize==0.5.1",
    "pystache==0.5.4",
    "pytest==2.9.2",
    "rq==0.6.0",
    "texas==0.5.2",
    "uritools==1.0.2"
]


if __name__ == "__main__":
    setup(
        name="gaas",
        author="Joe Cross",
        author_email="joe.mcross@gmail.com",
        url="https://github.com/numberoverzero/gaas",
        include_package_data=True,
        packages=find_packages(exclude=("tests", "docs", "examples")),
        install_requires=requirements,
    )
