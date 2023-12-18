import json
import requests
from flask import session, request
from portal import logger
from portal import app

# Read configurable tokens and endpoints from config file, values must be set
if "CONNECT_API_TOKEN" in app.config:
    CICONNECT_API_TOKEN = app.config["CONNECT_API_TOKEN"]
else:
    CICONNECT_API_TOKEN = "dummy-token"

if "CONNECT_API_ENDPOINT" in app.config:
    CICONNECT_API_ENDPOINT = app.config["CONNECT_API_ENDPOINT"]
else:
    CICONNECT_API_ENDPOINT = "localhost:18080"

if "REQUEST_MAX_TIMEOUT" in app.config:
    REQUEST_TIMEOUT = app.config["REQUEST_MAX_TIMEOUT"]
else:
    REQUEST_TIMEOUT = 10  # 10s

try:
    user_access_token = get_user_access_token(session)
    query = {"token": user_access_token}
except:
    query = {"token": CICONNECT_API_TOKEN}


def connect_name(group_name):
    """
    Returns string of root connect name, i.e. cms, osg, atlas, spt, etc.
    :param group_name: unix string name of group
    :return: string of connect name
    """
    return ".".join(group_name.split(".")[:2])


def query_status_code(query_response):
    if query_response.status_code == requests.codes.ok:
        query_return = query_response.json()["items"]
    else:
        query_return = []
    return query_return


def get_multiplex(json_obj):
    """
    Returns list of objects, containing multiplex information
    :param json_obj: json object containing query and request methods
    :return: [{state, name, state_set_by}]
    """
    multiplex = {}
    try:
        multiplex = requests.post(
            CICONNECT_API_ENDPOINT + "/v1alpha1/multiplex",
            params=query,
            json=json_obj,
            timeout=REQUEST_TIMEOUT,
        )
        multiplex = multiplex.json()
    except requests.exceptions.RequestException as e:
        logger.error("Did not get a valid response from the multiplex endpoint %s", e)
    return multiplex


#############################
#####       USER       ######
#############################


def get_user_info(session):
    """
    Returns object of user information
    :param session: user session to pull primary_identity
    :return: object {kind: User, apiVersion: v1alpha1, metadata: {access_token, unix_name}}
    """
    query = {"token": CICONNECT_API_TOKEN, "globus_id": session["primary_identity"]}

    user = requests.get(
        CICONNECT_API_ENDPOINT + "/v1alpha1/find_user",
        params=query,
        timeout=REQUEST_TIMEOUT,
    )
    user = user.json()
    return user


def get_user_group_memberships(session, unix_name):
    """
    Returns list of objects, containing group membership information
    :param session: user session to pull primary_identity
    :return: {query: {status: response, body: { apiVersion, kind, metadata: {} } }}
    """
    query = {"token": CICONNECT_API_TOKEN, "globus_id": session["primary_identity"]}

    users_group_memberships = requests.get(
        CICONNECT_API_ENDPOINT + "/v1alpha1/users/" + unix_name + "/groups",
        params=query,
        timeout=REQUEST_TIMEOUT,
    )
    users_group_memberships = users_group_memberships.json()["group_memberships"]
    return users_group_memberships


def get_user_group_status(unix_name, group_name, session):
    """
    Returns user's status in specific group
    :param unix_name: string unix name of user
    :group_name: string name of group
    :param session: user session to pull primary_identity
    :return: string
    """
    query = {"token": CICONNECT_API_TOKEN, "globus_id": session["primary_identity"]}

    user_status = requests.get(
        CICONNECT_API_ENDPOINT
        + "/v1alpha1/groups/"
        + group_name
        + "/members/"
        + unix_name,
        params=query,
        timeout=REQUEST_TIMEOUT,
    )
    user_status = user_status.json()["membership"]["state"]

    return user_status


def get_user_pending_project_requests(unix_name):
    """
    Returns user's status in root connect group
    :param unix_name: string user's unix name
    :param connect_group: string name of connect group
    :return: string (active, admin, nonmember)
    """
    query = {"token": CICONNECT_API_TOKEN}
    pending_project_requests = requests.get(
        CICONNECT_API_ENDPOINT + "/v1alpha1/users/" + unix_name + "/group_requests",
        params=query,
        timeout=REQUEST_TIMEOUT,
    )
    pending_project_requests = pending_project_requests.json()["groups"]
    return pending_project_requests


def get_user_connect_status(unix_name, connect_group):
    """
    Returns user's status in root connect group
    :param unix_name: string user's unix name
    :param connect_group: string name of connect group
    :return: string (active, admin, nonmember)
    """
    connect_status = requests.get(
        CICONNECT_API_ENDPOINT
        + "/v1alpha1/users/"
        + unix_name
        + "/groups/"
        + connect_group,
        params=query,
        timeout=REQUEST_TIMEOUT,
    )
    connect_status = connect_status.json()["membership"]["state"]
    return connect_status


def get_enclosing_group_status(group_name, unix_name):
    enclosing_group_name = ".".join(group_name.split(".")[:-1])
    if enclosing_group_name:
        enclosing_status = get_user_connect_status(unix_name, enclosing_group_name)
    else:
        enclosing_status = None
    return enclosing_status


def enclosing_admin_status(session, group_name):
    group_split = group_name.split(".")
    admin = False
    enclosing_group = group_split[0]

    while group_split and not admin:
        enclosing_group += ".{}".format(group_split.pop(0))
        if get_user_connect_status(session["unix_name"], enclosing_group) == "admin":
            admin = True
        else:
            enclosing_group
    return admin


#############################
#####       GROUP      ######
#############################


def get_group_info(group_name, session):
    """
    Returns group details
    :group_name: string name of group
    :return: dict object
    """
    access_token = get_user_access_token(session)
    query = {"token": access_token}
    group_info = requests.get(
        CICONNECT_API_ENDPOINT + "/v1alpha1/groups/" + group_name,
        params=query,
        timeout=REQUEST_TIMEOUT,
    )
    group_info = group_info.json()["metadata"]
    return group_info


def get_group_members(group_name, session):
    access_token = get_user_access_token(session)
    query = {"token": access_token}
    group_members = requests.get(
        CICONNECT_API_ENDPOINT + "/v1alpha1/groups/" + group_name + "/members",
        params=query,
        timeout=REQUEST_TIMEOUT,
    )
    group_members = group_members.json()["memberships"]
    return group_members


def get_group_members_emails(group_name):
    query = {"token": CICONNECT_API_TOKEN}

    group_members = get_group_members(group_name, session)
    multiplexJson = {}
    users_statuses = {}
    # Get detailed user information from list of users
    for user in group_members:
        unix_name = user["user_name"]
        user_state = user["state"]
        if user_state != "nonmember" and unix_name != "root":
            user_query = "/v1alpha1/users/" + unix_name + "?token=" + query["token"]
            multiplexJson[user_query] = {"method": "GET"}
            users_statuses[unix_name] = user_state

    # POST request for multiplex return
    multiplex = get_multiplex(multiplexJson)
    user_dict = {}
    group_user_dict = {}

    for user in multiplex:
        user_name = user.split("/")[3].split("?")[0]
        user_dict[user_name] = json.loads(multiplex[user]["body"])

    for user, info in user_dict.items():
        for group_membership in info["metadata"]["group_memberships"]:
            if group_membership["name"] == group_name:
                group_user_dict[user] = info

    return user_dict, users_statuses


def delete_group_entry(group_name, session):
    """
    Deletes group entry
    :group_name: string name of group
    :return:
    """
    access_token = get_user_access_token(session)
    query = {"token": access_token}

    r = requests.delete(
        CICONNECT_API_ENDPOINT + "/v1alpha1/groups/" + group_name,
        params=query,
        timeout=REQUEST_TIMEOUT,
    )
    return r


def get_subgroups(group_name, session):
    """
    Returns list of a group's subgroups
    :group_name: string name of group
    :param session: user session to pull primary_identity
    :return: list of dict objects
    """
    access_token = get_user_access_token(session)
    query = {"token": access_token}

    subgroups = requests.get(
        CICONNECT_API_ENDPOINT + "/v1alpha1/groups/" + group_name + "/subgroups",
        params=query,
        timeout=REQUEST_TIMEOUT,
    )
    subgroups = subgroups.json()["groups"]

    return subgroups


def update_user_group_status(group_name, unix_name, status, session):
    """
    Returns user's status in root connect group
    :param group_name: string name of group
    :param unix_name: string user's unix name
    :param status: string status to set (pending, active, admin, nonmember)
    :return:
    """
    access_token = get_user_access_token(session)
    query = {"token": access_token, "globus_id": session["primary_identity"]}

    put_query = {"apiVersion": "v1alpha1", "group_membership": {"state": status}}
    user_status = requests.put(
        CICONNECT_API_ENDPOINT
        + "/v1alpha1/groups/"
        + group_name
        + "/members/"
        + unix_name,
        params=query,
        json=put_query,
        timeout=REQUEST_TIMEOUT,
    )
    return user_status


def list_connect_admins(group_name):
    """
    Return list of admins of connect group
    Return list of nested dictionaries with state, user_name, and state_set_by
    """
    memberships = []
    query = {"token": CICONNECT_API_TOKEN}
    try:
        group_members = requests.get(
            CICONNECT_API_ENDPOINT
            + "/v1alpha1/groups/"
            + connect_name(group_name)
            + "/members",
            params=query,
            timeout=REQUEST_TIMEOUT,
        )
        memberships = group_members.json()["memberships"]
        memberships = [member for member in memberships if member["state"] == "admin"]
    except requests.exceptions.RequestException as e:
        logger: error("Could not get memberships for %s. Error: %s", group_name, e)
    return memberships


def get_user_profile(unix_name):
    profile = None
    identity_id = session.get("primary_identity")
    query = {"token": CICONNECT_API_TOKEN, "globus_id": identity_id}
    profile = requests.get(
        CICONNECT_API_ENDPOINT + "/v1alpha1/users/" + unix_name,
        params=query,
        timeout=REQUEST_TIMEOUT,
    )
    if profile.status_code == requests.codes.ok:
        profile = profile.json()
    else:
        err_msg = profile.json()["message"]
        logger.error("Error getting user profile: %s", err_msg)
    return profile


def get_user_access_token(session):
    access_token = None
    user = get_user_info(session)
    if user:
        access_token = user["metadata"]["access_token"]
    return access_token


def domain_branding_remap():
    domain_name = request.headers["Host"]
    try:
        mapped_domain = app.config["DOMAIN_MAP"][domain_name]
    except KeyError:
        logger.warning("Could not map %s to domain from config", domain_name)
        mapped_domain = "www.ci-connect.net"
    return mapped_domain
