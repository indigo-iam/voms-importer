from VOMSAdmin.VOMSCommands import VOMSAdminProxy

import logging
import requests
import os


class VomsError(Exception):
    pass


class VomsService:
    def _load_x509_credentials(self) -> None:
        if not os.environ['X509_USER_PROXY']:
            raise VomsError("X509_USER_PROXY env variable is not set!")
        self._session = requests.Session()
        self._session.cert = os.environ['X509_USER_PROXY']

    def __init__(self, host, port, vo, protocol="https") -> None:
        self._host = host
        self._port = port
        self._protocol = protocol
        self._vo = vo
        self._load_x509_credentials()
