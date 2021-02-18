import argparse
import logging
import os
import sys
import uuid
import requests
import subprocess

from VOMSAdmin.VOMSCommands import VOMSAdminProxy

os.environ['SSL_CERT_DIR'] = '/etc/grid-security/certificates'


def convert_dn_rfc2253(dn):
    rfc_dn = subprocess.check_output(["dn_converter", dn]).replace("\n", "")
    return rfc_dn


def leaf_group_name(group):
    idx = group.rfind("/")
    if idx < 0:
        return group
    if idx == 0:
        return group[1:]
    if idx == len(group):
        return leaf_group_name(group[:-1])

    return group[idx+1:]


def fqan2iam_group_name(fqan):
    return fqan.replace("Role=", "")[1:]


def voms2iam_group_name(group):
    return group[1:]


def parent_group_name(group):
    idx = group.rfind("/")
    if idx < 0:
        return None
    return group[:idx]


class VomsError(Exception):
    pass


class VomsService:
    def __init__(self, host, port, vo, protocol="https"):
        self._host = host
        self._port = port
        self._protocol = protocol
        self._vo = vo
        self._load_x509_credentials()
        self._init_voms_admin_proxy()

    def _load_x509_credentials(self):
        if not os.environ['X509_USER_PROXY']:
            raise VomsError("X509_USER_PROXY env variable is not set!")
        self._session = requests.Session()
        self._session.cert = os.environ['X509_USER_PROXY']
        logging.debug(
            "Using proxy certificate from X509_USER_PROXY env variable")

    def _init_voms_admin_proxy(self):
        kw = {
            'host': self._host,
            'port': self._port,
            'vo': self._vo,
            'user_key': os.environ['X509_USER_PROXY'],
            'user_cert': os.environ['X509_USER_PROXY']
        }
        self._proxy = VOMSAdminProxy(None, **kw)

    def get_subgroups(self, group):
        subgroups = self._proxy.call_method("list-sub-groups", group)
        logging.debug("VOMS %s sugroups: %s", group, subgroups)
        return subgroups

    def get_root_groups(self):
        root_group = "/%s" % self._vo
        groups = self._proxy.call_method("list-sub-groups", root_group)
        groups.insert(0, root_group)
        logging.debug("VOMS root_groups: %s", groups)
        return groups

    def get_roles(self):
        roles = self._proxy.call_method("list-roles")
        logging.debug("VOMS roles: %s", roles)
        return roles

    def get_voms_users(self, start=None, pagesize=None):
        logging.debug(
            "Loading VOMS users (startIndex: %s, pageSize: %s)", start, pagesize)
        url = "https://%s:8443/voms/%s/apiv2/users" % (self._host, self._vo)

        r = self._session.get(
            url, params={'startIndex': start, 'pageSize': pagesize})
        r.raise_for_status()
        return r.json()


class IamError(Exception):
    pass


class IamService:

    def _build_authz_header(self):
        return {"Authorization": "Bearer %s" % self._token}

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

    def has_voms_group(self, voms_group):
        g = self.find_group_by_name(voms2iam_group_name(voms_group))
        if g is None:
            return False
        return True

    def find_group_by_name(self, group_name):

        url = "%s://%s:%d/iam/group/find/byname" % (
            self._protocol, self._host, self._port)
        params = {"name": group_name}
        r = self._s.get(url, params=params)
        r.raise_for_status()
        data = r.json()

        total_results = data['totalResults']
        if total_results == 0:
            return None
        if total_results == 1:
            return data['Resources'][0]
        else:
            raise IamError(
                "Multiple groups returned for name: %s" % group_name)

    def create_group_with_name(self, group_name):
        logging.info("Creating IAM group: %s", group_name)
        leaf_group = leaf_group_name(group_name)
        parent_group = parent_group_name(group_name)

        iam_parent_group = None
        if parent_group:
            iam_parent_group = self.find_group_by_name(parent_group)

            if not iam_parent_group:
                raise IamError("Expected IAM group not found! %s" %
                               parent_group)

        payload = {
            "displayName": leaf_group,
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group", "urn:indigo-dc:scim:schemas:IndigoGroup"]
        }

        if iam_parent_group:
            parent_payload = {
                "parentGroup": {
                    "value": iam_parent_group['id'],
                    "display": iam_parent_group['displayName'],
                    "$ref": iam_parent_group['meta']['location']
                }
            }
            payload['urn:indigo-dc:scim:schemas:IndigoGroup'] = parent_payload

        headers = self._build_authz_header()
        headers['Content-type'] = "application/scim+json"
        url = "%s://%s:%d/scim/Groups" % (self._protocol,
                                          self._host, self._port)
        r = self._s.post(url, headers=headers, json=payload)
        r.raise_for_status()
        logging.debug("IAM group created: %s", group_name)
        return self.find_group_by_name(group_name)

    def import_voms_role(self, voms_role):
        role_name = voms_role.replace("Role=", "")
        optional_group_name = "%s/%s" % (self._vo, role_name)

        logging.debug("Importing VOMS role: %s as optional group: %s",
                      voms_role, optional_group_name)
        iam_group = self.find_group_by_name(optional_group_name)

        if not iam_group:
            iam_group = self.create_group_with_name(optional_group_name)

        self.label_group_as_optional(iam_group)

    def import_voms_group(self, voms_group):
        logging.info("Importing VOMS group: %s", voms_group)
        group_name = voms2iam_group_name(voms_group)
        self.create_group_with_name(group_name)

    def label_group_as_optional(self, group):
        url = "%s://%s/iam/group/%s/labels" % (
            self._protocol, self._host, group['id'])

        role_label = {"name": "voms.role"}
        og_label = {"name": "wlcg.optional-group"}

        headers = {'Content-type': "application/json"}

        r = self._s.put(url, headers=headers, json=role_label)
        r.raise_for_status()

        r = self._s.put(url, headers=headers, json=og_label)
        r.raise_for_status()

    def find_user_by_email(self, email):
        url = "%s://%s:%d/iam/account/find/byemail" % (self._protocol,
                                                       self._host, self._port)
        params = {"email": email}
        r = self._s.get(url, params=params,
                        headers=self._build_authz_header())
        r.raise_for_status()
        data = r.json()

        if data['totalResults'] == 0:
            return None
        elif data['totalResults'] == 1:
            return data['Resources'][0]
        else:
            raise IamError(
                "Multiple IAM accounts found for email: %s" % email)

    def find_user_by_voms_user(self, voms_user):
        url = "%s://%s:%d/iam/account/find/bylabel" % (self._protocol,
                                                       self._host, self._port)

        params = {"name": "voms.%s.id" %
                  self._vo, "value": voms_user['id']}

        r = self._s.get(url, params=params)
        r.raise_for_status()
        data = r.json()

        if data['totalResults'] == 0:
            return None
        elif data['totalResults'] == 1:
            return data['Resources'][0]
        else:
            raise IamError(
                "Multiple IAM accounts found for label: %s" % voms_user['id'])

    def build_username(self, voms_user):
        surname_id = "%s.%d" % (voms_user['surname'], voms_user['id'])
        return surname_id.lower().replace(' ', '_')

    def create_user_from_voms(self, voms_user):
        url = "%s://%s/scim/Users" % (self._protocol, self._host)
        headers = {'Content-type': 'application/scim+json'}
        payload = {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User", "urn:indigo-dc:scim:schemas:IndigoUser"],
            "userName": self.build_username(voms_user),
            "active": True,
            "name": {
                "familyName": voms_user['surname'],
                "givenName": voms_user['name']
            },
            "emails": [{
                "value": voms_user['emailAddress'],
                "type": "work",
                "primary": True
            }]
        }

        r = self._s.post(url, headers=headers, json=payload)
        r.raise_for_status()
        iam_user = r.json()

        logging.debug("IAM user created: %s", iam_user)

        label = {
            "name": "voms.%s.id" % self._vo,
            "value": voms_user['id']
        }
        self.add_user_label(iam_user, label)

        return iam_user

    def link_certificate(self, iam_user, cert):
        url = "%s://%s/scim/Users/%s" % (self._protocol,
                                         self._host, iam_user['id'])
        payload = {
            'schemas': ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
            'operations': [
                {
                    'op': 'add',
                    'path': 'certificates',
                    'value': {
                        "urn:indigo-dc:scim:schemas:IndigoUser": {
                            "certificates": [cert]
                        }
                    }
                }]
        }
        headers = {'Content-type': 'application/scim+json'}
        r = self._s.patch(url, headers=headers, json=payload)
        r.raise_for_status()

    def set_user_attribute(self, iam_user, attribute):
        url = "%s://%s/iam/account/%s/attributes" % (self._protocol,
                                                     self._host, iam_user['id'])
        r = self._s.put(url, json=attribute)
        r.raise_for_status()

    def get_voms_id_label(self, iam_user):
        labels = self.get_user_labels(iam_user)
        if labels:
            for l in labels:
                if l['name'] == "voms.%s.id" % self._vo:
                    return l
            return None
        else:
            return None

    def get_user_labels(self, iam_user):
        label_url = "%s://%s/iam/account/%s/labels" % (self._protocol,
                                                       self._host, iam_user['id'])
        r = self._s.get(label_url)
        r.raise_for_status()
        return r.json()

    def add_user_label(self, iam_user, label):
        label_url = "%s://%s/iam/account/%s/labels" % (self._protocol,
                                                       self._host, iam_user['id'])

        r = self._s.put(label_url, json=label)
        r.raise_for_status()

    def add_user_to_group(self, iam_user, iam_group):
        logging.debug("Adding user %s to group %s", self.iam_user_str(
            iam_user), self.iam_group_str(iam_group))

        url = "%s://%s/scim/Groups/%s" % (self._protocol,
                                          self._host, iam_group['id'])
        payload = {
            'schemas': ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
            'operations': [
                {
                    'op': 'add',
                    'path': 'members',
                    'value': [{
                        'display': iam_user['displayName'],
                        'value': iam_user['id']
                    }]
                }]
        }
        headers = {'Content-type': 'application/scim+json'}

        r = self._s.patch(url, headers=headers, json=payload)
        r.raise_for_status()

    def iam_user_str(self, iam_user):
        return "%s (%s)" % (iam_user['displayName'], iam_user['id'])

    def iam_group_str(self, iam_group):
        return "%s (%s)" % (iam_group['displayName'], iam_group['id'])

    def import_voms_user(self, voms_user):
        user_desc = "%d - %s %s" % (voms_user['id'],
                                    voms_user['name'],
                                    voms_user['surname'])

        logging.debug("Importing VOMS user: %s", user_desc)

        if voms_user['suspended']:
            logging.info("Skipping suspended user %s", user_desc)
            return

        iam_user = self.find_user_by_voms_user(voms_user)

        if iam_user:
            logging.info(
                "IAM account matching VOMS id %s found. Will sync information on that account" % voms_user['id'])
        else:
            iam_user = self.find_user_by_email(voms_user['emailAddress'])

            if iam_user:
                voms_id_label = self.get_voms_id_label(iam_user)
                if not voms_id_label:
                    logging.warning("IAM account found matching VOMS user %s email: %s. Will import information on that account",
                                    user_desc, voms_user['emailAddress'])
                else:
                    logging.warning("IAM account found matching VOMS user %s email: %s AND matching formerly imported VOMS user account %s. Will import information on that account",
                                    user_desc, voms_user['emailAddress'], voms_id_label['value'])

        # IAM account not found for voms id or email, create one
        if not iam_user:
            iam_user = self.create_user_from_voms(voms_user)

        iam_user_str = self.iam_user_str(iam_user)
        logging.debug("Syncing group/role membership for user %s",
                      iam_user_str)

        for f in voms_user['fqans']:
            logging.debug("Importing %s membership in VOMS FQAN: %s",
                          iam_user_str, f)
            iam_group_name = fqan2iam_group_name(f)
            iam_group = self.find_group_by_name(iam_group_name)

            if not iam_group:
                iam_group = self.create_group_with_name(iam_group_name)

            self.add_user_to_group(iam_user, iam_group)
        # # FIXME: the script should also remove the user from groups where it doesn't belong anymore

        logging.debug("Syncing generic attributes for user %s",
                      iam_user_str)
        for a in voms_user['attributes']:
            logging.debug("Importing %s attribute %s",
                          iam_user_str, a)
            self.set_user_attribute(iam_user, a)

        cert_idx = 0
        for c in voms_user['certificates']:
            cert_idx = cert_idx + 1
            logging.debug("Importing certificate %s for user %s" %
                          (c, iam_user_str))
            if c['suspended']:
                logging.info('Skipping certificate %s as is suspended' % c)
                continue

            cert = {
                "label": "cert-%d" % cert_idx,
                "subjectDn": convert_dn_rfc2253(c['subjectString']),
                "issuerDn": convert_dn_rfc2253(c['issuerString'])
            }

            self.link_certificate(iam_user, cert)

    def _base_url(self):
        return "%s://%s:%d" % (self._protocol, self._host, self._port)

    def _init_session(self):
        self._s = requests.Session()
        self._s.headers.update(self._build_authz_header())

    def __init__(self, host, port, vo, protocol="https"):
        self._host = host
        self._port = port
        self._protocol = protocol
        self._vo = vo
        self._load_token()
        self._init_session()


class VomsImporter:
    def __init__(self, args):
        self._args = args

        self._voms_service = VomsService(
            host=args.voms_host, port=args.voms_port, vo=args.vo)

        self._iam_service = IamService(
            host=args.iam_host, port=args.iam_port, vo=args.vo, protocol=args.iam_protocol)
        self._import_id = uuid.uuid4()

    def visit_voms_groups(self, group, fn=None):
        if fn:
            fn(group)
        else:
            print(group)
        subgroups = self._voms_service.get_subgroups(group)
        if subgroups:
            for g in subgroups:
                self.visit_voms_groups(g, fn)

    def migrate_voms_group(self, group):
        if not self._iam_service.has_voms_group(group):
            self._iam_service.import_voms_group(group)

    def import_voms_groups(self):
        logging.debug("Importing VOMS groups")
        groups = self._voms_service.get_root_groups()
        self.visit_voms_groups(groups[0], self.migrate_voms_group)

    def import_voms_roles(self):
        logging.debug("Importing VOMS roles")
        roles = self._voms_service.get_roles()
        for r in roles:
            self._iam_service.import_voms_role(r)

    def import_voms_users(self):
        logging.debug("Importing VOMS users")
        r = self._voms_service.get_voms_users(pagesize=1)
        logging.debug("VOMS users count: %d", r['count'])
        start = 0
        pagesize = 100
        while True:
            r = self._voms_service.get_voms_users(
                pagesize=pagesize, start=start)
            for u in r['result']:
                self._iam_service.import_voms_user(u)
            if (r['startIndex']+r['pageSize'] < r['count']):
                start = r['startIndex'] + r['pageSize']
            else:
                break

    def run_import(self):
        logging.info("VOMS importer run id: %s", self._import_id)
        self.import_voms_groups()
        self.import_voms_roles()
        self.import_voms_users()


def error_and_exit(msg):
    print("%s", msg)
    sys.exit(1)


def init_argparse():
    parser = argparse.ArgumentParser(prog='vomsimporter')
    parser.add_argument('--debug', required=False, default=False,
                        action="store_true", dest="debug", help="Turns on debug logging")
    parser.add_argument('--vo', required=True, type=str,
                        help="The VO to be migrated", dest="vo")
    parser.add_argument('--voms-host', required=True, type=str,
                        help="The VOMS host", dest="voms_host")
    parser.add_argument('--voms-port', required=False, type=int,
                        help="The voms port", dest="voms_port", default=8443)
    parser.add_argument('--iam-host', required=True, type=str,
                        help="The IAM host", dest="iam_host")
    parser.add_argument('--iam-port', required=False, type=int,
                        help="The IAM port", dest="iam_port", default=443)
    parser.add_argument('--iam-protocol', required=False, type=str,
                        help="The protocol used to talk to IAM", dest="iam_protocol", default="https")
    return parser


def init_logging(args):
    level = logging.WARN
    if args.debug:
        level = logging.DEBUG

    logging.basicConfig(
        format="%(asctime)s %(levelname)s : %(message)s", level=level)


def main():
    parser = init_argparse()
    args = parser.parse_args()
    init_logging(args)
    logging.debug("Arguments: %s", args)
    importer = VomsImporter(args)
    importer.run_import()


if __name__ == '__main__':
    main()
