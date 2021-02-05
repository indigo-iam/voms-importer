import os
import logging


class IamError(Exception):
    pass


class IamService:

    def _load_token(self):
        if os.environ.has_key('BEARER_TOKEN'):
            logging.debug("Taking bearer token from BEARER_TOKEN env variable")
            self._token = os.environ['BEARER_TOKEN']
            return

        uid = os.getuid()
        bt_file = "/tmp/bt_u%d" % uid

        if os.path.exists(bt_file):
            with open(bt_file, 'r') as f:
                iam_bt = f.read().replace('\n', '')
            logging.debug("Taking bearer token from %s file", bt_file)
            self._token = iam_bt
            return

        raise IamError("Bearer token file not found at: %s" % bt_file)

    def get_group_from_id(self, group_id):
        pass

    def find_group_by_name(self, name):
        pass

    def create_group(self, group):
        pass

    def label_group_as_optional(self, group):
        pass

    def find_iam_user_by_voms_user(self, voms_user):
        pass

    def create_user_from_voms(self, voms_user):
        pass

    def add_user_label(self, iam_user, label):
        pass

    def add_user_to_group(self, iam_user, iam_group):
        pass

    def _base_url(self):
        return "%s://%s:%d" % (self._protocol, self._host, self._port)

    def __init__(self, host, port, protocol="https") -> None:
        self._host = host
        self._port = port
        self._protocol = protocol
        self._load_token()
