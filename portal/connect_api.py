from flask import session
from portal import app
import requests

# Read configurable tokens and endpoints from config file, values must be set
ciconnect_api_token = app.config['CONNECT_API_TOKEN']
ciconnect_api_endpoint = app.config['CONNECT_API_ENDPOINT']

try:
    query = {'token': session['access_token']}
except:
    query = {'token': ciconnect_api_token}


def connect_name(group_name):
    """
    Returns string of root connect name, i.e. cms, osg, atlas, spt, etc.
    :param group_name: unix string name of group
    :return: string of connect name
    """
    connect_name = '.'.join(group_name.split('.')[:2])
    return connect_name


def query_status_code(query_response):
    if query_response.status_code == requests.codes.ok:
        query_return = query_response.json()['items']
    else:
        query_return = []
    return query_return


def get_user_info(session):
    """
    Returns object of user information
    :param session: user session to pull primary_identity
    :return: object {kind: User, apiVersion: v1alpha1, metadata: {access_token, unix_name}}
    """
    query = {'token': ciconnect_api_token,
             'globus_id': session['primary_identity']}

    user = requests.get(ciconnect_api_endpoint +
                        '/v1alpha1/find_user', params=query)
    user = user.json()
    return user


def get_user_group_memberships(session, unix_name):
    """
    Returns list of objects, containing group membership information
    :param session: user session to pull primary_identity
    :return: {query: {status: response, body: { apiVersion, kind, metadata: {} } }}
    """
    query = {'token': ciconnect_api_token,
             'globus_id': session['primary_identity']}

    users_group_memberships = requests.get(
        ciconnect_api_endpoint + '/v1alpha1/users/' + unix_name + '/groups', params=query)
    users_group_memberships = users_group_memberships.json()['group_memberships']
    return users_group_memberships


def get_multiplex(json):
    """
    Returns list of objects, containing multiplex information
    :param json: json object containing query and request methods
    :return: [{state, name, state_set_by}]
    """
    multiplex = requests.post(
        ciconnect_api_endpoint + '/v1alpha1/multiplex', params=query, json=json)
    multiplex = multiplex.json()
    return multiplex


def user_connect_status(unix_name, connect_group):
    """
    Returns user's status in root connect group
    :param unix_name: string user's unix name
    :param connect_group: string name of connect group
    :return: string (active, admin, nonmember)
    """
    connect_status = requests.get(ciconnect_api_endpoint + '/v1alpha1/users/'
                                    + unix_name + '/groups/'
                                    + connect_group, params=query)
    connect_status = connect_status.json()['membership']['state']
    return connect_status


def get_user_pending_project_requests(unix_name):
    """
    Returns user's status in root connect group
    :param unix_name: string user's unix name
    :param connect_group: string name of connect group
    :return: string (active, admin, nonmember)
    """
    pending_project_requests = requests.get(ciconnect_api_endpoint
                                            + '/v1alpha1/users/'
                                            + unix_name
                                            + '/group_requests', params=query)
    pending_project_requests = pending_project_requests.json()['groups']
    return pending_project_requests


def list_connect_admins(group_name):
    """
    Return list of admins of connect group
    Return list of nested dictionaries with state, user_name, and state_set_by
    """
    query = {'token': ciconnect_api_token}
    group_members = requests.get(
            ciconnect_api_endpoint + '/v1alpha1/groups/'
            + connect_name(group_name) + '/members', params=query)
    memberships = group_members.json()['memberships']
    memberships = [member for member in memberships if member['state'] == 'admin']

    return memberships