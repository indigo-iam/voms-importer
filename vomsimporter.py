#!/usr/bin/env python
import argparse
import logging
import os
import sys
import uuid
import requests
import subprocess
import csv
import ldap

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
    def __init__(self, host, port, vo, protocol="https", insecure=False):
        self._host = host
        self._port = port
        self._protocol = protocol
        self._vo = vo
        self._insecure = insecure
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

    def get_groups(self):
        ret = []

        groups = ["/%s" % self._vo]
        while len(groups) > 0:
            group = groups.pop()
            subgroups = self._proxy.call_method("list-sub-groups", group)
            if subgroups:
                for g in subgroups:
                    groups.append(g)
            ret.append(group)

        return ret

    def get_roles(self):
        roles = self._proxy.call_method("list-roles")
        logging.debug("VOMS roles: %s", roles)
        return roles

    def get_voms_users(self, start=None, pagesize=None):
        logging.debug(
            "Loading VOMS users (startIndex: %s, pageSize: %s)", start, pagesize)
        url = "https://%s:8443/voms/%s/apiv2/users" % (self._host, self._vo)

        r = self._session.get(
            url, params={'startIndex': start, 'pageSize': pagesize},
            verify = False if ( self._insecure ) else True,
            headers= {'X-VOMS-CSRF-GUARD': "y"})
        r.raise_for_status()
        return r.json()

    def get_voms_user(self, uid):
        logging.debug("Loading VOMS user by id: %d", uid)
        url = "https://%s:8443/voms/%s/apiv2/user-info" % (
            self._host, self._vo)
        r = self._session.get(url, params={'userId': uid},
                              headers= {'X-VOMS-CSRF-GUARD': "y"})
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

        if group_name in self._iam_groups:
            return self._iam_groups[group_name]

        url = "%s/iam/group/find/byname" % self._base_url()
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
            group = data['Resources'][0]
            self._iam_groups[group_name] = group
            return group
        else:
            raise IamError(
                "Multiple groups returned for name: %s" % group_name)

    def create_group_with_name(self, group_name):
        logging.info("Creating IAM group: %s", group_name)
        leaf_group = leaf_group_name(group_name)
        parent_group = parent_group_name(group_name)

        iam_parent_group = None
        if parent_group is not None:
            iam_parent_group = self.find_group_by_name(parent_group)

            if iam_parent_group is None:
                raise IamError("Expected IAM group not found! %s" %
                               parent_group)

        payload = {
            "displayName": leaf_group,
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group", "urn:indigo-dc:scim:schemas:IndigoGroup"]
        }

        if iam_parent_group is not None:
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
        url = "%s/scim/Groups" % self._base_url()
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

        if iam_group is None:
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
        url = "%s/iam/group/%s/labels" % (self._base_url(), group['id'])

        role_label = {"name": "voms.role"}
        og_label = {"name": "wlcg.optional-group"}

        headers = {'Content-type': "application/json"}

        r = self._s.put(url, headers=headers, json=role_label)
        r.raise_for_status()

        r = self._s.put(url, headers=headers, json=og_label)
        r.raise_for_status()

    def find_user_by_email(self, email):
        url = "%s/iam/account/find/byemail" % self._base_url()
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
        url = "%s/iam/account/find/bylabel" % self._base_url()

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

        if self._username_attr is not None:
            for attr in voms_user['attributes']:
                if attr['name'] == self._username_attr:
                    username = attr.get('value')
                    if username is not None and len(username) > 0:
                        return username
            logging.error("Attribute %s not found for user %s. Will fall back to default username %s",
                          self._username_attr, voms_user['id'], user_id)
            return user_id

        else:
            return user_id

    def create_user_from_voms(self, voms_user):
        url = "%s/scim/Users" % self._base_url()
        headers = {'Content-type': 'application/scim+json'}
        payload = {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User", "urn:indigo-dc:scim:schemas:IndigoUser"],
            "userName": self.build_username(voms_user),
            "active": not voms_user['suspended'],
            "name": {
                "familyName": voms_user['surname'],
                "givenName": voms_user['name']
            },
            "emails": [{
                "value": voms_user['emailAddress'],
                "type": "work",
                "primary": True
            }],
            "endTime": voms_user.get('endTime')
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
        url = "%s/scim/Users/%s" % (self._base_url(), iam_user['id'])
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
        try:
            r = self._s.patch(url, headers=headers, json=payload)
            r.raise_for_status()
        except requests.exceptions.RequestException as e:
            if e.response is None:
                logging.error("Error linking certificate: %s to account %s: %s",
                              cert, iam_user['id'], e)
            elif e.response.status_code == 409:
                logging.warning("Error linking certificate: %s to account %s: %s",
                                cert, iam_user['id'], e.response.content)
            else:
                logging.error("Error linking certificate: %s to account %s: %s",
                              cert, iam_user['id'], e.response.status_code)

    def synchronize_aup(self, iam_user, voms_user):
        url = "%s/iam/aup/signature/%s" % (self._base_url(), iam_user['id'])
        headers = self._build_authz_header()
        headers['Content-type'] = "application/json"
        payload = {
            'signatureTime': self.retrieve_aup_sign_time(voms_user)
        }
        try:
            r = self._s.patch(url, headers=headers, json=payload)
            r.raise_for_status()
        except requests.exceptions.RequestException as e:
            if e.response is None:
                logging.error("Failed AUP synchronization for account %s: %s",
                            iam_user['id'], e)
            else:
                logging.error("Failed AUP synchronization for account %s with error: %s",
                            iam_user['id'], e.response.content)

    def synchronize_activation(self, iam_user, voms_user):
        url = "%s/scim/Users/%s" % (self._base_url(), iam_user['id'])
        payload = {
            "schemas": [
                "urn:ietf:params:scim:api:messages:2.0:PatchOp"
            ],
            "operations": [
                {
                    "op": "replace",
                    "value": {
                        "active": not voms_user['suspended']
                    }
                }
            ]
        }
        headers = {'Content-type': 'application/scim+json'}

        try:
            if voms_user['suspended']:
                logging.info("Suspending the user: %s", voms_user['id'])
            else:
                logging.info("Activating the user: %s", voms_user['id'])
            r = self._s.patch(url, headers=headers, json=payload)
            r.raise_for_status()
        except requests.exceptions.RequestException as e:
            if e.response is None:
                logging.error("Failed synchronizing the activation status for account %s: %s",
                            iam_user['id'], e)
            else:
                logging.error("Failed synchronizing the activation status for account %s with error: %s",
                            iam_user['id'], e.response.content)

    def synchronize_end_time(self, iam_user, voms_user):
        logging.debug("Synchronizing end time for the user %s", self.iam_user_str(iam_user))

        url = "%s/iam/account/%s/endTime" % (self._base_url(), iam_user['id'])
        headers = self._build_authz_header()
        headers['Content-type'] = "application/json"
        payload = {
            'endTime': voms_user.get('endTime')
        }

        try:
            r = self._s.put(url, headers=headers, json=payload)
            r.raise_for_status()
        except requests.exceptions.RequestException as e:
            if e.response is None:
                logging.error("Failed end time synchronization for account %s: %s",
                            iam_user['id'], e)
            else:
                logging.error("Failed end time synchronization for account %s with error: %s",
                            iam_user['id'], e.response.content)

    def retrieve_aup_sign_time(self, voms_user):
        for aup in voms_user['aupAcceptanceRecords']:
            signatureTime = aup.get('lastAcceptanceDate')
            return signatureTime

    def set_user_attribute(self, iam_user, attribute):
        url = "%s/iam/account/%s/attributes" % (self._base_url(), iam_user['id'])
        r = self._s.put(url, json=attribute)
        r.raise_for_status()

    def get_voms_id_label(self, iam_user):
        labels = self.get_user_labels(iam_user)
        if labels is not None:
            for l in labels:
                if l['name'] == "voms.%s.id" % self._vo:
                    return l
            return None
        else:
            return None

    def get_user_labels(self, iam_user):
        label_url = "%s/iam/account/%s/labels" % (self._base_url(), iam_user['id'])
        r = self._s.get(label_url)
        r.raise_for_status()
        return r.json()

    def add_user_label(self, iam_user, label):
        label_url = "%s/iam/account/%s/labels" % (self._base_url(), iam_user['id'])

        r = self._s.put(label_url, json=label)
        r.raise_for_status()

    def add_skip_email_synch_label(self, iam_user):
        label = {
            'prefix': 'hr.cern',
            'name': 'skip-email-synch'
        }

        self.add_user_label(iam_user, label)

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

        url = "%s/scim/Groups/%s" % (self._base_url(), iam_group['id'])
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

    def remove_user_from_group(self, iam_user, iam_group):
        logging.debug("Removing user %s from group %s", self.iam_user_str(
            iam_user), self.iam_group_str(iam_group))

        url = "%s/scim/Groups/%s" % (self._base_url(), iam_group['id'])
        payload = {
            'schemas': ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
            'operations': [
                {
                    'op': 'remove',
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
        if self.has_email_override(voms_user['id']):
            overridden_email = self.email_override(voms_user['id'])
            logging.info("Overriding email for VOMS user: %d : %s => %s",
                         voms_user['id'], voms_user['emailAddress'], overridden_email)
            voms_user['emailAddress'] = overridden_email

        if voms_user['suspended']:
            if self._synchronize_activation_status:
                logging.info("Importing suspended user %s", user_desc)
            else:
                logging.info("Skipping suspended user %s", user_desc)
                return

        iam_user = self.find_user_by_voms_user(voms_user)

        if iam_user is not None:
            logging.info(
                "IAM account matching VOMS id %s found. Will sync information on that account" % voms_user['id'])
        else:
            iam_user = self.find_user_by_email(voms_user['emailAddress'])

            if iam_user is not None:
                voms_id_label = self.get_voms_id_label(iam_user)
                if voms_id_label is None:
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

        new_user = False
        # IAM account not found for voms id or email, create one
        if iam_user is None:
            logging.info(
                "No IAM account found matching VOMS user id %s found, will create a new one", voms_user['id'])
            iam_user = self.create_user_from_voms(voms_user)
            new_user = True

        self.synchronize_aup(iam_user, voms_user)

        if self._synchronize_activation_status and iam_user['active'] == voms_user['suspended']:
            self.synchronize_activation(iam_user, voms_user)

        if self._synchronize_activation_status:
            self.synchronize_end_time(iam_user, voms_user)

        iam_user_str = self.iam_user_str(iam_user)
        logging.info("Syncing group/role membership for user %s",
                     iam_user_str)

        if self.has_email_override(voms_user['id']):
            logging.info("User has email override, disable HR email sync")
            self.add_skip_email_synch_label(iam_user)

        iam_group_names = set()
        for f in voms_user['fqans']:
            logging.info("Importing %s membership in VOMS FQAN: %s",
                         iam_user_str, f)
            iam_group_name = fqan2iam_group_name(f)
            iam_group_names.add(iam_group_name)
            iam_group = self.find_group_by_name(iam_group_name)

            if iam_group is None:
                iam_group = self.create_group_with_name(iam_group_name)

                if fqan_is_role(f):
                    self.label_group_as_optional(iam_group)

            self.add_user_to_group(iam_user, iam_group)

        # remove the user from groups where it doesn't belong anymore
        if not new_user and self._voms_groups:
            # start with groups with longest display name, IAM automatically remove
            # subgroups and we don't want to trigger exception by calling
            # remove_user_from_group for missing group
            for iam_user_group in sorted(iam_user['groups'], key=lambda x: -len(x['display'])):
                iam_group_name = iam_user_group['display']
                if iam_group_name in iam_group_names:
                    continue

                if iam_group_name not in self._voms_groups:
                    # don't remove groups that doesn't come from VOMS
                    continue

                iam_group = self.find_group_by_name(iam_group_name)
                if iam_group is None: # this should not happen
                    continue

                self.remove_user_from_group(iam_user, iam_group)

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
                if self._synchronize_activation_status:
                    logging.info("Importing suspended certificate %s", c)
                else:
                    logging.info('Skipping certificate %s as is suspended' % c)
                    continue

            try:
                converted_subject = convert_dn_rfc2253(c['subjectString'])
                converted_issuer = convert_dn_rfc2253(c['issuerString'])
            except Exception as e:
                logging.warn(
                    "DN conversion failed with exception %s, skipping certificate import", e)
                continue

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

        if voms_user.get('cernHrId') is not None:
            logging.info("Linking user %s to CERN person id %d",
                         iam_user_str, voms_user['cernHrId'])
            self.add_cern_person_id_label(iam_user, voms_user['cernHrId'])

            if self._link_cern_sso:
                cern_login = self.resolve_cern_login_from_attributes(voms_user)
                self.create_cern_sso_account_link(iam_user, cern_login)
            elif self._link_cern_sso_ldap:
                cern_login = self.resolve_cern_login_from_ldap(voms_user)
                self.create_cern_sso_account_link(iam_user, cern_login)

    def resolve_cern_login_from_ldap(self, voms_user):
        cern_hr_id = voms_user.get('cernHrId')
        if cern_hr_id == None:
            return None

        lfilter = "(&(objectClass=user)(employeeType=Primary)(employeeID={0}))".format(cern_hr_id)

        ldap.set_option(ldap.OPT_REFERRALS, 0)
        l = ldap.initialize("ldap://{0}:{1}".format(self._ldap_host, self._ldap_port))

        try:
            l.simple_bind_s('','')

            r = l.search_s("DC=cern,DC=ch", ldap.SCOPE_SUBTREE, lfilter, [ 'cn' ])
            if len(r) == 0:
                logging.warn("CERN login resolution failed for personId %s",
                    cern_hr_id)
                return None

            dn, attrs = r[0]
            cern_login = attrs['cn'][0]
            logging.info("CERN login resolved via LDAP: personId %s => %s",
                cern_hr_id, cern_login)

            return cern_login

        except Exception as e:
            logging.error("CERN login resolved via LDAP failed: %s", str(e))

        finally:
            l.unbind()

        return None

    def resolve_cern_login_from_attributes(self, voms_user):
        nickname = None
        for attr in voms_user['attributes']:
            if attr['name'] == 'nickname':
                nickname = attr['value']

        if nickname is None:
            logging.warn("No nickname defined for voms user %s -> No CERN SSO account link" %
                         voms_user['id'])
            return None

        return nickname

    def create_cern_sso_account_link(self, iam_user, cern_login):
        if cern_login == None:
            logging.warning("Unable to link user %s to CERN SSO (not found)",
                iam_user['displayName'])
            return

        url = "%s/scim/Users/%s" % (self._base_url(), iam_user['id'])

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
        try:
            r.raise_for_status()
        except requests.exceptions.RequestException as e:
            if e.response is None:
                logging.error("CERN SSO link failed: %s", e)
            elif e.response.status_code == 409:
                logging.warning(
                    "CERN SSO link failed with a conflict error: %s", e.response.content)
            else:
                logging.error("CERN SSO link failed: %s", e.response.content)

    def _base_url(self):
        return "%s://%s:%d" % (self._protocol, self._host, self._port)

    def _init_session(self):
        self._s = requests.Session()
        self._s.headers.update(self._build_authz_header())

    def has_email_override(self, uid):
        return self._email_override.has_key(uid)

    def email_override(self, uid):
        return self._email_override[uid]

    def _load_email_override_csv_file(self, email_mapfile):
        self._email_override = {}
        logging.info(
            "Loading email override map file from: %s", email_mapfile)

        with open(email_mapfile) as csvfile:
            reader = csv.DictReader(
                csvfile, fieldnames=['id', 'email'], delimiter=';')

            for r in reader:
                logging.info("Adding email override for VOMS user id: %s => %s",
                             r['id'], r['email'])
                self._email_override[int(r['id'])] = r['email']

    def __init__(self, host, port, vo, ldap_host, ldap_port, protocol="https", username_attr=None, link_cern_sso=False, link_cern_sso_ldap=False, merge_accounts=False, email_mapfile=None, voms_groups=None, voms_roles=None, synchronize_activation_status=False):

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
        self._email_override = {}
        self._import_id_list = None
        self._iam_groups = {}
        self._synchronize_activation_status = synchronize_activation_status

        if email_mapfile is not None:
            self._load_email_override_csv_file(email_mapfile)

        self._voms_groups = None
        if voms_groups or voms_roles:
            self._voms_groups = set()
            if voms_groups:
                for g in voms_groups:
                    self._voms_groups.add(voms2iam_group_name(g))
                if voms_roles:
                    for g in voms_groups:
                        for r in voms_roles:
                            self._voms_groups.add(fqan2iam_group_name("{0}/{1}".format(g, r)))

        self._load_token()
        self._init_session()


class VomsImporter:
    def __init__(self, args):
        self._args = args

        self._voms_service = VomsService(
            host=args.voms_host, port=args.voms_port, vo=args.vo, insecure=args.insecure)

        voms_groups = None
        voms_roles = None
        if not args.skip_group_removal:
            if not args.skip_groups_import:
                voms_groups = self._voms_service.get_groups()
            if not args.skip_roles_import:
                voms_roles = self._voms_service.get_roles()

        self._iam_service = IamService(
            host=args.iam_host, port=args.iam_port, vo=args.vo, protocol=args.iam_protocol,
            username_attr=args.username_attr, link_cern_sso=args.link_cern_sso,
            link_cern_sso_ldap=args.link_cern_sso_ldap, ldap_host=args.cern_ldap_host, ldap_port=args.cern_ldap_port,
            merge_accounts=args.merge_accounts, email_mapfile=args.email_mapfile,
            voms_groups=voms_groups, voms_roles=voms_roles, synchronize_activation_status=args.synchronize_activation_status)

        self._import_id = uuid.uuid4()
        self._voms_user_ids = []

        if args.id_file is not None:
            self._load_id_file(args.id_file)

    def _load_id_file(self, id_file):
        logging.info(
            "Loading import id list from file: %s", id_file)

        with open(id_file) as idfile:
            reader = csv.DictReader(idfile, fieldnames=['id'])
            for r in reader:
                logging.info(
                    "Adding VOMS user id: %d to the import list", int(r['id']))
                self._voms_user_ids.append(int(r['id']))

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
        root_group = "/%s" % self._args.vo
        self.visit_voms_groups(root_group, self.migrate_voms_group)

    def import_voms_roles(self):
        logging.info("Importing VOMS roles")
        roles = self._voms_service.get_roles()
        for r in roles:
            self._iam_service.import_voms_role(r)

    def import_voms_users_list(self):
        logging.info("Importing VOMS users from user id list")
        import_count = 0
        for id in self._voms_user_ids:
            try:
                u = self._voms_service.get_voms_user(id)
                self._iam_service.import_voms_user(u)
                import_count = import_count + 1
                logging.info("Import count: %d", import_count)
                if self._args.count > 0 and import_count >= self._args.count:
                    logging.info(
                        "Breaking after %d imported users as requested", import_count)
                    return
            except Exception as e:
                logging.warning("Cannot import user %d: %s", id, e)

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
                try:
                    self._iam_service.import_voms_user(u)
                    import_count = import_count + 1
                    logging.info("Import count: %d", import_count)
                    if self._args.count > 0 and import_count >= self._args.count:
                        logging.info(
                            "Breaking after %d imported users as requested", import_count)
                        return
                except Exception as e:
                    logging.warning("Cannot import user %d: %s", u['id'], e)

            if (r['startIndex']+r['pageSize'] < r['count']):
                start = r['startIndex'] + r['pageSize']
            else:
                break

    def print_voms_accounts_sharing_email(self):
        logging.info("Looking for accounts sharing email addresses...")
        email_map = {}

        pagesize = 300
        start = 0
        while True:
            r = self._voms_service.get_voms_users(
                pagesize=pagesize, start=start)

            logging.info("Processing %d VOMS users (out of %d)",
                         start, r['count'])

            for u in r['result']:
                if u['suspended'] and not self._synchronize_activation_status:
                    logging.debug("Skipping suspended account %s", u['id'])
                    continue

                if self._iam_service.has_email_override(u['id']):
                    u['emailAddress'] = self._iam_service.email_override(
                        u['id'])

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
                if len(self._voms_user_ids) > 0:
                    self.import_voms_users_list()
                else:
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
    parser.add_argument('--skip-group-removal', required=False, default=False,
                        action="store_true", dest="skip_group_removal", help="Skips group removal")
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
    parser.add_argument('--insecure', required=False, default=False, action='store_true',
                        help="Disable SSL certificate verification when interacting with VOMS server")
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
    parser.add_argument('--email-mapfile', required=False,
                        help="File with 'vomsid;email@address' to allow duplicate email overwrite", default=None, dest="email_mapfile")

    parser.add_argument('--id-file', required=False,
                        help="Limits import to VOMS users matching whose id is listed in the file (one id per line).", default=None, dest="id_file")
    parser.add_argument('--synchronize-activation-status', required=False,
                        help="Activates or suspends existing users depending on their status on VOMS Admin", default=False, action="store_true", dest="synchronize_activation_status")
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
    try:
        importer = VomsImporter(args)
        importer.run_import()
    except Exception as e:
        logging.warning(e, exc_info=True)


if __name__ == '__main__':
    main()
