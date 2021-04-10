import argparse
import logging
import os
import sys
import uuid
import requests
import subprocess

from VOMSAdmin.VOMSCommands import VOMSAdminProxy

os.environ['SSL_CERT_DIR'] = '/etc/grid-security/certificates'
DN_CONVERTER_COMMAND = "dn_converter"


def convert_dn_rfc2253(dn):
    rfc_dn = subprocess.check_output(
        [DN_CONVERTER_COMMAND, dn]).replace("\n", "")
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


def fqan_is_role(fqan):
    return fqan.find("Role=") > 0


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

    def print_voms_accounts_sharing_email(self):
        logging.info("Looking for accounts sharing email addresses...")
        email_map = {}

        pagesize = 300
        start = 0
        while True:
            r = self.get_voms_users(
                pagesize=pagesize, start=start)

            logging.info("Processing %d VOMS users (out of %d)",
                         start, r['count'])

            for u in r['result']:
                if u['suspended']:
                    logging.debug("Skipping suspended account %s", u['id'])
                    continue

                if email_map.has_key(u['emailAddress']):
                    email_map[u['emailAddress']].append(u['id'])
                else:
                    email_map[u['emailAddress']] = [u['id']]

            if (r['startIndex']+r['pageSize'] < r['count']):
                start = r['startIndex'] + r['pageSize']
            else:
                break

        num_accounts_sharing_email = 0
        for k in email_map.keys():
            if len(email_map[k]) > 1:
                num_accounts_sharing_email = num_accounts_sharing_email + \
                    len(email_map[k])

        logging.info(
            "%d accounts found sharing email address with another account", num_accounts_sharing_email)

        for k in email_map.keys():
            if len(email_map[k]) > 1:
                logging.info("%s => voms user ids: %s", k, email_map[k])


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

        total_results = 0

        if data.has_key('totalResults'):
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

        logging.info("Importing VOMS role: %s as optional group: %s",
                     voms_role, optional_group_name)
        iam_group = self.find_group_by_name(optional_group_name)

        if not iam_group:
            iam_group = self.create_group_with_name(optional_group_name)
        else:
            logging.info("Optional group %s already present",
                         iam_group['displayName'])

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

        total_results = 0
        if data.has_key('totalResults'):
            total_results = data['totalResults']

        if total_results == 0:
            return None
        elif total_results == 1:
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
        user_id = "user.%d" % voms_user['id']

        if self._username_attr:
            for attr in voms_user['attributes']:
                if attr['name'] == self._username_attr:
                    return attr['value']
            logging.error("Attribute %s not found for user %s. Will fall back to default username %s",
                          self._username_attr, voms_user['id'], user_id)
            return user_id

        else:
            return user_id

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

    def add_cern_person_id_label(self, iam_user, person_id):
        label = {
            'prefix': 'hr.cern',
            'name': 'cern_person_id',
            'value': person_id
        }

        self.add_user_label(iam_user, label)

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

        logging.info("Importing VOMS user: %s", user_desc)

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

                    if self._merge_accounts:
                        logging.warning("IAM account found matching VOMS user %s email: %s AND matching formerly imported VOMS user account %s. Will import information on that account (--merge-accounts=True)",
                                        user_desc, voms_user['emailAddress'], voms_id_label['value'])
                    else:
                        logging.warning("IAM account found matching VOMS user %s email: %s AND matching formerly imported VOMS user account %s. Will NOT import information for this account (--merge-accounts=False)",
                                        user_desc, voms_user['emailAddress'], voms_id_label['value'])
                        return

        # IAM account not found for voms id or email, create one
        if not iam_user:
            iam_user = self.create_user_from_voms(voms_user)

        iam_user_str = self.iam_user_str(iam_user)
        logging.info("Syncing group/role membership for user %s",
                     iam_user_str)

        for f in voms_user['fqans']:
            logging.info("Importing %s membership in VOMS FQAN: %s",
                         iam_user_str, f)
            iam_group_name = fqan2iam_group_name(f)
            iam_group = self.find_group_by_name(iam_group_name)

            if not iam_group:
                iam_group = self.create_group_with_name(iam_group_name)

                if fqan_is_role(f):
                    self.label_group_as_optional(iam_group)

            self.add_user_to_group(iam_user, iam_group)
        # # FIXME: the script should also remove the user from groups where it doesn't belong anymore

        logging.info("Syncing generic attributes for user %s",
                     iam_user_str)
        for a in voms_user['attributes']:
            logging.debug("Importing %s attribute %s",
                          iam_user_str, a)
            self.set_user_attribute(iam_user, a)

        cert_idx = 0
        for c in voms_user['certificates']:
            cert_idx = cert_idx + 1
            logging.info("Importing certificate %s for user %s" %
                         (c, iam_user_str))
            if c['suspended']:
                logging.info('Skipping certificate %s as is suspended' % c)
                continue

            converted_subject = convert_dn_rfc2253(c['subjectString'])
            converted_issuer = convert_dn_rfc2253(c['issuerString'])

            if len(converted_subject) == 0:
                logging.error(
                    "DN conversion failed for subject %s, skipping certificate import", c['subjectString'])
                continue

            if len(converted_issuer) == 0:
                logging.error(
                    "DN conversion failed for issuer %s, skipping certificate import", c['issuerString'])
                continue

            logging.info("Converted certificate info: '%s', '%s'",
                         converted_subject, converted_issuer)
            cert = {
                "label": "cert-%d" % cert_idx,
                "subjectDn": convert_dn_rfc2253(c['subjectString']),
                "issuerDn": convert_dn_rfc2253(c['issuerString'])
            }

            self.link_certificate(iam_user, cert)

        if voms_user.has_key('cernHrId'):
            logging.info("Linking user %s to CERN person id %d",
                         iam_user_str, voms_user['cernHrId'])
            self.add_cern_person_id_label(iam_user, voms_user['cernHrId'])

            if self._link_cern_sso:
                cern_login = self.resolve_cern_login_from_attributes(voms_user)
                self.create_cern_sso_account_link(
                    voms_user, iam_user, cern_login)
            elif self._link_cern_sso_ldap:
                cern_login = self.resolve_cern_login_from_ldap(voms_user)
                self.create_cern_sso_account_link(
                    voms_user, iam_user, cern_login)

    def resolve_cern_login_from_ldap(self, voms_user):
        cern_login = subprocess.check_output(["resolve_cern_login", str(voms_user[
            'cernHrId']), self._ldap_host, self._ldap_port]).replace("\n", "").strip()

        if len(cern_login) == 0:
            logging.warn("CERN login resolution failed for personId %s", voms_user[
                'cernHrId'])
            return None

        logging.info("CERN login resolved via LDAP: personId %s => %s", voms_user[
            'cernHrId'], cern_login)
        return cern_login

    def resolve_cern_login_from_attributes(self, voms_user):
        nickname = None
        for attr in voms_user['attributes']:
            if attr['name'] == 'nickname':
                nickname = attr['value']

        if not nickname:
            logging.warn("No nickname defined for voms user %s -> No CERN SSO account link" %
                         voms_user['id'])
            return None

    def create_cern_sso_account_link(self, voms_user, iam_user, cern_login):
        url = "%s://%s/scim/Users/%s" % (self._protocol,
                                         self._host, iam_user['id'])

        oidc_id = {
            'issuer': 'https://auth.cern.ch/auth/realms/cern',
            'subject': cern_login
        }

        logging.info("Linking user %s to CERN SSO account %s",
                     iam_user['displayName'], oidc_id)

        payload = {
            'schemas': ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
            'operations': [
                {
                    'op': 'add',
                    'path': 'oidcIds',
                    'value': {
                        "urn:indigo-dc:scim:schemas:IndigoUser": {
                            "oidcIds": [oidc_id]
                        }
                    }
                }]
        }

        headers = {'Content-type': 'application/scim+json'}
        r = self._s.patch(url, headers=headers, json=payload)
        r.raise_for_status()

    def _base_url(self):
        return "%s://%s:%d" % (self._protocol, self._host, self._port)

    def _init_session(self):
        self._s = requests.Session()
        self._s.headers.update(self._build_authz_header())

    def __init__(self, host, port, vo, ldap_host, ldap_port, protocol="https", username_attr=None, link_cern_sso=False, link_cern_sso_ldap=False, merge_accounts=False):

        self._host = host
        self._port = port
        self._protocol = protocol
        self._vo = vo
        self._username_attr = username_attr
        self._link_cern_sso = link_cern_sso
        self._link_cern_sso_ldap = link_cern_sso_ldap
        self._ldap_host = ldap_host
        self._ldap_port = ldap_port
        self._merge_accounts = merge_accounts
        self._load_token()
        self._init_session()


class VomsImporter:
    def __init__(self, args):
        self._args = args

        self._voms_service = VomsService(
            host=args.voms_host, port=args.voms_port, vo=args.vo)

        self._iam_service = IamService(
            host=args.iam_host, port=args.iam_port, vo=args.vo, protocol=args.iam_protocol,
            username_attr=args.username_attr, link_cern_sso=args.link_cern_sso,
            link_cern_sso_ldap=args.link_cern_sso_ldap, ldap_host=args.cern_ldap_host, ldap_port=args.cern_ldap_port, merge_accounts=args.merge_accounts)

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
        else:
            logging.info("Group %s already present", group)

    def import_voms_groups(self):
        logging.info("Importing VOMS groups")
        groups = self._voms_service.get_root_groups()
        self.visit_voms_groups(groups[0], self.migrate_voms_group)

    def import_voms_roles(self):
        logging.info("Importing VOMS roles")
        roles = self._voms_service.get_roles()
        for r in roles:
            self._iam_service.import_voms_role(r)

    def import_voms_users(self):
        logging.info("Importing VOMS users")
        r = self._voms_service.get_voms_users(pagesize=1)

        start = self._args.start_index
        logging.info(
            "VOMS users count: %d. Starting from index %d", r['count'], start)
        pagesize = 100
        import_count = 0
        while True:
            r = self._voms_service.get_voms_users(
                pagesize=pagesize, start=start)
            for u in r['result']:
                self._iam_service.import_voms_user(u)
                import_count = import_count + 1
                logging.info("Import count: %d", import_count)
                if self._args.count > 0 and import_count >= self._args.count:
                    logging.info(
                        "Breaking after %d imported users as requested", import_count)
                    return
            if (r['startIndex']+r['pageSize'] < r['count']):
                start = r['startIndex'] + r['pageSize']
            else:
                break

    def print_voms_accounts_sharing_email(self):
        self._voms_service.print_voms_accounts_sharing_email()

    def run_import(self):
        logging.info("VOMS importer run id: %s", self._import_id)

        if not self._args.skip_duplicate_accounts_check:
            self.print_voms_accounts_sharing_email()

        if not self._args.skip_import:
            if not self._args.skip_groups_import:
                self.import_voms_groups()

            if not self._args.skip_roles_import:
                self.import_voms_roles()

            if not self._args.skip_users_import:
                self.import_voms_users()


def error_and_exit(msg):
    print("%s", msg)
    sys.exit(1)


def init_argparse():
    parser = argparse.ArgumentParser(prog='vomsimporter')
    parser.add_argument('--debug', required=False, default=False,
                        action="store_true", dest="debug", help="Turns on debug logging")
    parser.add_argument('--skip-duplicate-accounts-checks', required=False, default=False,
                        action="store_true", dest="skip_duplicate_accounts_check", help="Skips duplicate account checks")
    parser.add_argument('--skip-import', required=False, default=False,
                        action="store_true", dest="skip_import", help="Skips import")
    parser.add_argument('--skip-groups-import', required=False, default=False,
                        action="store_true", dest="skip_groups_import", help="Skips groups import")
    parser.add_argument('--skip-roles-import', required=False, default=False,
                        action="store_true", dest="skip_roles_import", help="Skips roles import")
    parser.add_argument('--skip-users-import', required=False, default=False,
                        action="store_true", dest="skip_users_import", help="Skips users import")
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
    parser.add_argument('--start-index', required=False, type=int,
                        help="Start from this index when syncing users", dest="start_index", default=0)
    parser.add_argument('--count', required=False, type=int,
                        help="Import at most 'count' user records", dest="count", default=-1)
    parser.add_argument('--username-attr', required=False, type=str,
                        help="Uses the VOMS GA passed as argument for building the username", dest="username_attr", default=None)
    parser.add_argument('--link-cern-sso', required=False,
                        help="Creates a CERN SSO account link from the 'nickname' VOMS GA", default=False, action="store_true", dest="link_cern_sso")
    parser.add_argument('--link-cern-sso-ldap', required=False,
                        help="Creates a CERN SSO account link resolving the CERN login using CERNs ldap", default=False, action="store_true", dest="link_cern_sso_ldap")
    parser.add_argument('--cern-ldap-host', required=False,
                        help="CERN ldap host", default="xldap.cern.ch", type=str, dest="cern_ldap_host")
    parser.add_argument('--cern-ldap-port', required=False,
                        help="CERN ldap port", default="389", type=str, dest="cern_ldap_port")
    parser.add_argument('--merge-accounts', required=False,
                        help="Merge account information for accounts sharing the email address", default=False, dest="merge_accounts")
    return parser


def init_logging(args):
    level = logging.INFO
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
