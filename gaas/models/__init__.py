import bloop
import boto3

# TODO should be loaded from config
_session = boto3.session.Session(profile_name="gaas-integ")
engine = bloop.Engine(session=_session)
