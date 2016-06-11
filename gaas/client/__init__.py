import json
import requests
from pathlib import Path
from Crypto.PublicKey import RSA

from ..security.signatures import sign


def load_credentials(filename):
    path = Path(filename).expanduser()
    with path.open(mode="r") as file:
        return json.loads(file.read())


class Client:
    def __init__(self, credentials_file):
        self.endpoint = "http://127.0.0.1:8000"
        self.auth = SignedAuth(self)
        self.__credentials = load_credentials(credentials_file)
        self._refresh_key()

    def _refresh_key(self):
        self.key = RSA.generate(2048)
        data = {
            **self.__credentials,
            "public_key": self.key.publickey().exportKey("PEM").decode("utf-8")
        }
        resp = requests.post(self.endpoint + "/keys", json=data)
        resp.raise_for_status()
        self.key_id = resp.json()["key_id"]

    def _revoke_key(self):
        resp = requests.delete(self.endpoint + "/keys", auth=self.auth)
        resp.raise_for_status()

    def check_public(self):
        resp = requests.get(self.endpoint + "/keys", auth=self.auth)
        resp.raise_for_status()
        return resp.json()


class SignedAuth(requests.auth.AuthBase):
    def __init__(self, client: Client):
        self.client = client

    def __call__(self, request: requests.PreparedRequest):
        sign(
            request.method, request.path_url, request.headers, request.body,
            self.client.key, self.client.key_id)
        return request
