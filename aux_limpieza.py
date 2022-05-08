from google.cloud import firestore
import requests

def get_vip_list(my_user_id):
    db = firestore.Client("twitter-redirect")
    doc_ref = db.collection("state").document(my_user_id)
    data = doc_ref.get().to_dict()
    return data["vip_list"]


def unfollow(user_id, target_user_id, access_token):
    url = "https://api.twitter.com/2/users/{}/following/{}".format(user_id, target_user_id)
    headers = {
        "Authorization": "Bearer {}".format(access_token)
    }
    response = requests.request("DELETE", url, headers=headers, json={})
    if response.status_code != 200:
        raise Exception(
            "Request returned an error: {} {}".format(response.status_code, response.text)
        )

def get_contacts(user_id, api, bearer_token):
    global global_bearer_token

    global_bearer_token = bearer_token

    contacts = []
    query_param = "?max_results=1000"
    url = "https://api.twitter.com/2/users/{}/{}{}".format(user_id,api,query_param)
    params = {"user.fields": "created_at"}
    
    response = requests.request("GET", url, auth=bearer_oauth, params=params)
    if response.status_code == 200:
        contacts = contacts + response.json()["data"]
        response_metadata = response.json()["meta"]
        next_page = ""
        if "next_token" in response_metadata:
            next_page = response_metadata["next_token"]
        while next_page != "":
            query_param="&pagination_token={}".format(next_page)
            response = requests.request("GET", url+query_param, auth=bearer_oauth, params=params)
            if response.status_code != 200:
                next_page = ""
                break
            contacts = contacts + response.json()["data"]
            response_metadata = response.json()["meta"]
            next_page = ""
            if "next_token" in response_metadata:
                next_page = response.json()["meta"]["next_token"]
    if response.status_code != 200:
        raise Exception(
            "Request returned an error: {} {}".format(
                response.status_code, response.text
            )
        )
    return contacts

def bearer_oauth(r):
    """
    Method required by bearer token authentication.
    """

    r.headers["Authorization"] = f"Bearer {global_bearer_token}"
    r.headers["User-Agent"] = "v2FollowersLookupPython"
    return r