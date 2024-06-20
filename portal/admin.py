import json
import base64
from io import BytesIO
from datetime import datetime
import requests
from dateutil.parser import parse
from flask import session
from matplotlib.figure import Figure
from portal import logger
from portal import app

ciconnect_api_token = app.config["CONNECT_API_TOKEN"]
ciconnect_api_endpoint = app.config["CONNECT_API_ENDPOINT"]
mailgun_api_token = app.config["MAILGUN_API_TOKEN"]
params = {"token": ciconnect_api_token}
MAX_TIMEOUT = 10  # seconds


def authorized():
    return session.get("admin") == "admin"


def get_usernames(group):
    if authorized():
        try:
            url = (
                ciconnect_api_endpoint
                + "/v1alpha1/groups/"
                + group
                + "/members?token="
                + ciconnect_api_token
            )
            users = requests.get(url, timeout=MAX_TIMEOUT).json()
            return [member["user_name"] for member in users["memberships"]]
        except requests.exceptions.RequestException as e:
            logger.error("Error getting usernames: %s", e)


def get_user_profiles(group):
    profiles = []
    if authorized():
        try:
            usernames = get_usernames(group)

            multiplex_json = {}
            for username in usernames:
                multiplex_json[
                    "/v1alpha1/users/" + username + "?token=" + ciconnect_api_token
                ] = {"method": "GET"}

            url = ciconnect_api_endpoint + "/v1alpha1/multiplex"
            resp = requests.post(
                url, params=params, json=multiplex_json, timeout=MAX_TIMEOUT
            )
            data = resp.json()

            for entry in data:
                user = json.loads(data[entry]["body"])
                username = user["metadata"]["unix_name"]
                email = user["metadata"]["email"]
                join_date = parse(user["metadata"]["join_date"]).strftime("%Y-%m-%d")
                institution = user["metadata"]["institution"]
                name = user["metadata"]["name"]
                profiles.append(
                    {
                        "username": username,
                        "email": email,
                        "join_date": join_date,
                        "institution": institution,
                        "name": name,
                    }
                )
        except requests.exceptions.RequestException as e:
            logger.error("Error getting user profiles: %s", e)
    return profiles


def get_email_list(group):
    email_list = []
    if authorized():
        profiles = get_user_profiles(group)
        for profile in profiles:
            email_list.append(profile["email"])
    return email_list


def update_user_institution(username, institution):
    if authorized():
        try:
            json_data = {
                "apiVersion": "v1alpha1",
                "kind": "User",
                "metadata": {"institution": institution},
            }
            url = ciconnect_api_endpoint + "/v1alpha1/users/" + username
            resp = requests.put(url, params=params, json=json_data, timeout=MAX_TIMEOUT)
            logger.info("Updated user %s. Set institution to %s", username, institution)
            return resp
        except requests.exceptions.RequestException as e:
            logger.error("Error updating institution for user %s: %s", username, e)


def email_users(sender, recipients, subject, body):
    if authorized():
        try:
            logger.info("Sending email...")
            resp = requests.post(
                "https://api.mailgun.net/v3/api.ci-connect.net/messages",
                auth=("api", mailgun_api_token),
                data={
                    "from": "<" + sender + ">",
                    "to": [sender],
                    "bcc": recipients,
                    "subject": subject,
                    "text": body,
                },
                timeout=MAX_TIMEOUT,
            )
            return resp
        except requests.exceptions.RequestException as e:
            logger.error("Error sending email to all users: %s", e)


def plot_users_by_join_date(users):
    if authorized():
        try:
            xvalues_format = "%m-%Y"
            xvalues_set = set()
            for user in users:
                join_date = datetime.strptime(user["join_date"], "%Y-%m-%d")
                user["jd"] = join_date
                xvalue = datetime(join_date.year, join_date.month, 1).strftime(
                    xvalues_format
                )
                xvalues_set.add(xvalue)
            xvalues = list(xvalues_set)
            xvalues.sort(key=lambda x: datetime.strptime(x, xvalues_format))
            yvalues = [0] * len(xvalues)
            for i in range(len(xvalues)):
                xvalue = datetime.strptime(xvalues[i], xvalues_format)
                l = list(
                    filter(
                        lambda u: ((xvalue.year - u["jd"].year) * 12)
                        + (xvalue.month - u["jd"].month)
                        >= 0,
                        users,
                    )
                )
                yvalues[i] = len(l)
            fig = Figure(figsize=(16, 8), dpi=80, tight_layout=True)
            ax = fig.subplots()
            ax.plot(xvalues, yvalues)
            ax.set_xlabel("Month")
            ax.set_ylabel("Number of users")
            ax.set_title("Number of users by month")
            buf = BytesIO()
            fig.savefig(buf, format="png")
            data = base64.b64encode(buf.getbuffer()).decode("ascii")
            return data
        except:
            logger.error("Error generating user by join date plot")
