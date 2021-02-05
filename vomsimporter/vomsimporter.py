import argparse
import logging
import os
from os import environ
import sys
import requests
import uuid
from VOMSAdmin.VOMSCommands import VOMSAdminProxy
from functools import partial

environ['SSL_CERT_DIR'] = '/etc/grid-security/certificates'

ctx = {}

iam_service = None
voms_service = None


def visit_voms_groups(group, fn=None):
    global ctx
    if fn:
        fn(group)
    else:
        print(group)
    subgroups = get_voms_subgroups(group)
    if subgroups:
        for g in subgroups:
            visit_voms_groups(g, fn)


def get_voms_subgroups(group):
    global ctx
    subgroups = ctx['proxy'].call_method("list-sub-groups", group)
    logging.debug("%s sugroups: %s", group, subgroups)
    return subgroups


def get_voms_root_groups(vo):
    global ctx
    root_group = "/%s" % vo

    groups = ctx['proxy'].call_method("list-sub-groups", root_group)
    logging.debug("root_groups: %s", groups)
    groups.insert(0, root_group)

    return groups


def get_voms_roles(args):
    global ctx
    roles = ctx['proxy'].call_method("list-roles")
    logging.debug("roles: %s", roles)
    return roles


def init_voms_proxy(args):
    global ctx

    kw = {
        'host': args.host,
        'port': 8443,
        'vo': args.vo,
        'user_key': environ['X509_USER_PROXY'],
        'user_cert': environ['X509_USER_PROXY']
    }

    proxy = VOMSAdminProxy(args, **kw)
    ctx['proxy'] = proxy


def error_and_exit(msg):
    print("%s", msg)
    sys.exit(1)


def init_argparse():
    parser = argparse.ArgumentParser(prog='vomsimporter')
    parser.add_argument('--debug', required=False, default=False,
                        action="store_true", dest="debug", help="Turns on debug logging")
    parser.add_argument('--voms-host', required=True, type=str,
                        help="The VOMS host", dest="host")
    parser.add_argument('--iam-host', required=True, type=str,
                        help="The IAM host", dest="iam_host")
    parser.add_argument('--vo', required=True, type=str,
                        help="The VO to be migrated", dest="vo")
    return parser


def x509_credential_checks():
    global ctx

    if not environ['X509_USER_PROXY']:
        error_and_exit("X509_USER_PROXY env variable is not set!")
    # TODO: add support for plain X.509 credentials
    s = requests.Session()
    s.cert = environ['X509_USER_PROXY']
    ctx['voms_session'] = s


def check_voms_connection(args):
    global ctx
    s = ctx['voms_session']
    url = "https://%s:8443/voms/%s/apiv2/users" % (args.voms_host, args.vo)
    response = s.get(url)
    data = response.json()
    logging.info("data %s", data)


def print_arguments(args):
    logging.debug("Arguments: %s ", args)


def get_iam_groups(args):
    global ctx
    url = "https://%s/scim/Groups" % args.iam_host
    headers = {'Authorization': "Bearer %s" % ctx['bt']}
    r = requests.get(url, headers=headers)

    r.raise_for_status()
    groups = r.json()
    logging.debug("IAM groups: %s", groups)
    return r.json()


def init_logging(args):
    level = logging.WARN
    if args.debug:
        level = logging.DEBUG

    logging.basicConfig(
        format="%(asctime)s %(levelname)s : %(message)s", level=level)


def find_group(args, group_name):
    global ctx
    url = "https://%s/iam/group/search" % args.iam_host
    params = {"filter": group_name, "count": "1"}
    r = requests.get(url, params=params, headers=build_authz_header())
    r.raise_for_status()
    data = r.json()
    total_results = data['totalResults']
    if total_results == 0:
        return None
    if total_results == 1:
        return data['Resources'][0]
    else:
        for g in data['Resources']:
            if g['displayName'] == group_name:
                return g
        return None


def iam_has_voms_group(args, group):
    global ctx
    g = find_group(args, voms2iam_group_name(group))
    if g is None:
        return False
    return True


def build_authz_header():
    global ctx
    return {"Authorization": "Bearer %s" % ctx['bt']}


def leaf_group_name(group):
    idx = group.rfind("/")
    if idx < 0:
        return group
    if idx == 0:
        return group[1:]
    if idx == len(group):
        return leaf_group_name(group[:-1])

    return group[idx+1:]


def voms2iam_group_name(group):
    return group[1:]


def parent_group_name(group):
    idx = group.rfind("/")
    if idx < 0:
        return None
    return group[:idx]


def iam_create_group(args, group):
    global ctx
    logging.info("Creating IAM group for VOMS group: %s", group)
    url = "https://%s/iam/group" % args.iam_host

    group_name = voms2iam_group_name(group)
    leaf_group = leaf_group_name(group)
    parent_group = parent_group_name(group_name)
    iam_parent_group = None

    if parent_group:
        iam_parent_group = find_group(args, parent_group)
        if not iam_parent_group:
            error_and_exit("Expected IAM group not found! %s" % parent_group)

    payload = {'name': leaf_group}

    if iam_parent_group:
        parent_payload = {'uuid': iam_parent_group['id']}
        payload['parent'] = parent_payload

    headers = build_authz_header()
    headers['Content-type'] = "application/json"

    r = requests.post(url, headers=headers, json=payload)
    r.raise_for_status()
    logging.debug("IAM group created: %s", group_name)


def migrate_voms_group(args, group):

    if not iam_has_voms_group(args, group):
        iam_create_group(args, group)


def import_voms_groups(args):
    global ctx
    logging.debug("Importing VOMS groups")
    groups = get_voms_root_groups(args.vo)
    p = partial(migrate_voms_group, args)
    visit_voms_groups(groups[0], p)


def iam_set_optional_group(args, group):
    global ctx
    url = "https://%s/iam/group/%s/labels" % (args.iam_host, group['id'])
    role_label = {"name": "voms.role"}
    og_label = {"name": "wlcg.optional-group"}

    headers = build_authz_header()
    headers['Content-type'] = "application/json"

    r = requests.put(url, headers=headers, json=role_label)
    r.raise_for_status()

    r = requests.put(url, headers=headers, json=og_label)
    r.raise_for_status()


def import_voms_role(args, role):
    global ctx
    logging.debug("Importing VOMS role: %s", role)
    role_name = role[role.find('=')+1:]
    optional_group_name = "/%s/%s" % (args.vo, role_name)
    iam_group = find_group(args, voms2iam_group_name(optional_group_name))

    if not iam_group:
        iam_create_group(args, optional_group_name)

    iam_set_optional_group(args, iam_group)


def import_voms_roles(args):
    global ctx
    logging.debug("Importing VOMS roles")
    roles = get_voms_roles(args.vo)
    for r in roles:
        import_voms_role(args, r)


def get_voms_users(args, start=None, pagesize=None):
    global ctx
    logging.debug(
        "Loading VOMS users (startIndex: %s, pageSize: %s)", start, pagesize)
    url = "https://%s:8443/voms/%s/apiv2/users" % (args.host, args.vo)
    headers = {"X-VOMS-CSRF-GUARD": "y"}
    s = ctx['voms_session']
    r = s.get(url, params={'startIndex': start, 'pageSize': pagesize})
    r.raise_for_status()
    return r.json()


def find_iam_user_by_voms_user(args, voms_user):
    global ctx

    url = "https://%s/iam/account/find/bylabel" % args.iam_host
    params = {"name": "voms.%s.id" %
              args.vo, "value": voms_user['id']}

    r = requests.get(url, params=params, headers=build_authz_header())
    r.raise_for_status()
    data = r.json()

    if data['totalResults'] == 0:
        return None
    elif data['totalResults'] == 1:
        return data['Resources'][0]
    else:
        error_and_exit(
            "Multiple IAM accounts found for label: %s" % voms_user['id'])


def build_username(voms_user):
    username = "%s.%s.%d" % (
        voms_user['name'], voms_user['surname'], voms_user['id'])
    return username.lower().replace(' ', '_')


def iam_create_user(args, voms_user):
    global ctx
    url = "https://%s/scim/Users" % args.iam_host

    headers = build_authz_header()
    headers['Content-type'] = 'application/scim+json'

    payload = {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User", "urn:indigo-dc:scim:schemas:IndigoUser"],
        "userName": build_username(voms_user),
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
    r = requests.post(url, headers=headers, json=payload)
    r.raise_for_status()
    data = r.json()
    logging.debug("IAM user created: %s", data)

    iam_add_label_to_user(args, data, "voms.%s.id" %
                          args.vo, voms_user['id'])
    return data


def iam_add_label_to_user(args, iam_user, name, value):
    label_url = "https://%s/iam/account/%s/labels" % (
        args.iam_host, iam_user['id'])
    headers = build_authz_header()
    label = {"name": name, "value": value}
    r = requests.put(label_url, headers=headers, json=label)
    r.raise_for_status()


def import_voms_user(args, voms_user):
    global ctx

    user_desc = "%d - %s %s" % (voms_user['id'],
                                voms_user['name'],
                                voms_user['surname'])

    logging.debug("Importing VOMS user: %s", user_desc)

    if voms_user['suspended']:
        logging.info("Skipping suspended user %s", user_desc)
        return

    iam_user = find_iam_user_by_voms_user(args, voms_user)

    if not iam_user:
        iam_user = iam_create_user(args, voms_user)
    # sync fqans
    sync_fqans(args, voms_user, iam_user)


def iam_add_user_to_group(args, iam_user, iam_group):
    logging.debug("Adding user %s to group %s", iam_user, iam_group)
    url = "https://%s/scim/Groups/%s" % (args.iam_host, iam_group['id'])

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

    headers = build_authz_header()
    headers['Content-type'] = 'application/scim+json'

    r = requests.patch(url, headers=headers, json=payload)
    r.raise_for_status()


def fqan2iam_group_name(fqan):
    role_idx = fqan.find("Role=")
    if role_idx != -1:
        iam_group_name = fqan.replace("Role=", "/")[1:]
        return iam_group_name
    else:
        return fqan[1:]


def iam_get_group(args, group_id):
    url = "https://%s/scim/Groups/%s" % (args.iam_host, group_id)


def sync_fqans(args, voms_user, iam_user):
    logging.debug("Syncing group/role membership for user %s", iam_user)
    for f in voms_user['fqans']:
        logging.debug("Handling membership in %s", f)
        iam_group_name = fqan2iam_group_name(f)
        iam_group = find_group(args, iam_group_name)
        if not iam_group:
            error_and_exit("Expected IAM group not found! %s" % iam_group)
        iam_add_user_to_group(args, iam_user, iam_group)
    for ig in iam_user['groups']:


def import_voms_users(args):
    global ctx
    logging.debug("Importing VOMS users")
    r = get_voms_users(args, pagesize=1)
    logging.debug("VOMS users count: %d", r['count'])

    start = 0
    pagesize = 100
    while True:
        r = get_voms_users(args, pagesize=pagesize, start=start)
        for u in r['result']:
            import_voms_user(args, u)
        if (r['startIndex']+r['pageSize'] < r['count']):
            start = r['startIndex'] + r['pageSize']
        else:
            break


def main():
    global ctx
    parser = init_argparse()
    args = parser.parse_args()
    init_logging(args)
    print_arguments(args)
    x509_credential_checks()
    init_voms_proxy(args)
    ctx['import_task_id'] = uuid.uuid4()
    logging.info("Import task id: %s", ctx['import_task_id'])
    ctx['bt'] = load_iam_token()

    import_voms_groups(args)
    import_voms_roles(args)
    import_voms_users(args)


if __name__ == '__main__':
    main()
