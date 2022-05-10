from flask import Flask, render_template, request
from datetime import datetime, timezone, timedelta
from google.cloud import firestore
from google.cloud import secretmanager
from datetime import datetime, timezone, timedelta
import os
import google_crc32c
import base64
import hashlib
import re
from requests.auth import HTTPBasicAuth
from requests_oauthlib import OAuth2Session
import aux_limpieza

app = Flask(__name__)

# Diccionario de variables de estado de la autenticación, ya refrescaremos de la DB si es necesario
oauth_record={}

TW_USER_ID=os.environ['TW_USER_ID']

def set_secret(client, proj_id, secret_id, payload):
    parent = client.secret_path(proj_id, secret_id)

    payload = payload.encode("UTF-8")

    try:  # Si el secreto existe, voy a actualizarlo
        client.add_secret_version(
            request={
                "parent": parent,
                "payload": {"data": payload}
            }
        )
    except Exception:
        # No existía así que voy a crearlo de cero
        parent = f"projects/{proj_id}"

        # Create the secret.
        client.create_secret(
            request={
                "parent": parent,
                "secret_id": secret_id,
                "secret": {"replication": {"user_managed": {"replicas": [{"location": "europe-west1"}]}}},
            }
        )

    return

def get_secret(client, proj_id, secret):
    secretName = "projects/{}/secrets/{}/versions/latest".format(proj_id, secret)
    try:
        secretResponse = client.access_secret_version(request={"name": secretName})
    except Exception:
        #Probablemente es porque no existe el secreto
        return ""

    crc32c = google_crc32c.Checksum()
    crc32c.update(secretResponse.payload.data)
    if secretResponse.payload.data_crc32c != int(crc32c.hexdigest(),16):
        return ""

    return secretResponse.payload.data.decode("UTF-8")


# Miramos la validez del token en caché
# Podría cargar de la DB aquí mismo, pero supondría una pérdida de rendimiento en la primera carga de la página. Dejamos para el procedimiento de Logon
def valid_token_cache():
    
    access_token_existe = ("access" in oauth_record) and (oauth_record["access"]!="")
    bearer_token_existe = ("bearer_token" in oauth_record) and (oauth_record["bearer_token"]!="")
    token_timestamp_existe = ("token_timestamp" in oauth_record) and (oauth_record["token_timestamp"]!="")
    token_no_caducado = False
    if token_timestamp_existe:
        dt_now = datetime.now()
        ahora_timestamp = datetime(dt_now.year, dt_now.month, dt_now.day, dt_now.hour, dt_now.minute, dt_now.second, tzinfo=timezone(timedelta(hours=2)))

        token_no_caducado = (ahora_timestamp - oauth_record["token_timestamp"] < timedelta(hours=24))
    
    if access_token_existe and bearer_token_existe and token_no_caducado:
        return True
    else:
        return False

# Objetivo: verificar la validez del token en la DB
# Si es válido, devuelvo True y refresco las variables de caché
# Si no es válido, devuelvo False y las variables de caché se pueblan a excepción de timestamp y access
def valid_token_db(my_user_id):
    global oauth_record

    project_id = aux_limpieza.get_project_id()
    db = firestore.Client(project_id)
    doc_ref = db.collection("oauth").document(my_user_id)
    local_oauth_record = doc_ref.get().to_dict()

    secretClient = secretmanager.SecretManagerServiceClient()

    if project_id == "":
        raise Exception("Failed to determine GCP Project ID")

    local_oauth_record["bearer_token"]=get_secret(client=secretClient,proj_id=project_id, secret="bearer_token")
    local_oauth_record["client_id"]=get_secret(client=secretClient,proj_id=project_id, secret="client_id")
    local_oauth_record["client_secret"]=get_secret(client=secretClient,proj_id=project_id, secret="client_secret")
    local_oauth_record["access"]=get_secret(client=secretClient,proj_id=project_id, secret="access")

    db_timestamp = None
    access = None
    if "token_timestamp" in local_oauth_record:
        temp_timestamp = local_oauth_record["token_timestamp"]
        db_timestamp = datetime(temp_timestamp.year, temp_timestamp.month, temp_timestamp.day, temp_timestamp.hour+2, temp_timestamp.minute, temp_timestamp.second, tzinfo=timezone(timedelta(hours=2)))
        dt_now = datetime.now()
        now_timestamp = datetime(dt_now.year, dt_now.month, dt_now.day, dt_now.hour, dt_now.minute, dt_now.second, tzinfo=timezone(timedelta(hours=2)))
    if "access" in local_oauth_record:
        access=local_oauth_record["access"]
    
    oauth_record = local_oauth_record
    if db_timestamp is None or access is None or (now_timestamp - db_timestamp > timedelta(hours=24)):
        if "access" in oauth_record:
            del oauth_record["access"]
        if "token_timestamp" in oauth_record:
            del oauth_record["token_timestamp"]
        return False
    else:
        return True

# Objetivo - generar la URL de autorización oauth para que el usuario pueda autorizar a la aplicación en su cuenta de Twitter
# Modifica - objeto OAUTH y Code Verifier globales que tengo que declarar así muy a mi pesar
def generar_url_oauth():
    global global_oauth, code_verifier
    # Create a code verifier
    code_verifier = base64.urlsafe_b64encode(os.urandom(30)).decode("utf-8")
    code_verifier = re.sub("[^a-zA-Z0-9]+", "", code_verifier)

    # Create a code challenge
    code_challenge = hashlib.sha256(code_verifier.encode("utf-8")).digest()
    code_challenge = base64.urlsafe_b64encode(code_challenge).decode("utf-8")
    code_challenge = code_challenge.replace("=", "")

    # Start and OAuth 2.0 session
    global_oauth = OAuth2Session(oauth_record["client_id"], redirect_uri=oauth_record["redirect_uri"], scope=oauth_record["scopes"])

    # Create an authorize URL
    auth_url = "https://twitter.com/i/oauth2/authorize"
    authorization_url, state = global_oauth.authorization_url(
        auth_url, code_challenge=code_challenge, code_challenge_method="S256")

    return authorization_url

# Objetivo - completar el flujo oAuth a partir de la URL que el usuario ha pegado en el campo correspondiente, después de autorizar a la aplicación en Twitter
# Resultado - refrescar DB y caché con tokens y timestamps válidos, tras lo cual el usuario se considera autenticado
# Modifica - Registro oAuth_record con toda la información y borra las variables global_oauth y code verifier
def generar_tokens_oauth(authorization_response):
    global global_oauth, code_verifier
    # Fetch your access token
    token_url = "https://api.twitter.com/2/oauth2/token"
    auth = HTTPBasicAuth(oauth_record["client_id"], oauth_record["client_secret"])

    token = global_oauth.fetch_token(
        token_url=token_url,
        authorization_response=authorization_response,
        auth=auth,
        client_id=oauth_record["client_id"],
        include_client_id=True,
        code_verifier=code_verifier,
    )
    global_oauth = None
    code_verifier = None
    # Your access token
    oauth_record["access"] = token["access_token"]
    return

# Objetivo - sincronizar el registro oauth (espero que después de haber realizado el flujo oauth adecuadamente) con la base de datos y el secret manager
def flush_oauth_record(my_user_id):
    db = firestore.Client(aux_limpieza.get_project_id())
    doc_ref = db.collection("oauth").document(my_user_id)

    doc_ref.update({"token_timestamp" : firestore.SERVER_TIMESTAMP})
    oauth_record["token_timestamp"] = doc_ref.get().to_dict()["token_timestamp"]

    secretClient = secretmanager.SecretManagerServiceClient()
    project_id = aux_limpieza.get_project_id()

    set_secret(client=secretClient,proj_id=project_id,secret_id="access",payload=oauth_record["access"])

    return

#########
# Rutas #
#########
@app.route("/")
def index():
    return render_template("index.html", autenticado=valid_token_cache())

@app.route("/autenticar", methods=["GET", "POST"])
def autenticar():
    # Aquí realizamos la comprobación sobre la base de datos, y 
    # en caso necesario, lanzamos todo el flujo oauth completo
    # para refrecar tanto la base de datos como las variables en caché
    if request.method == "GET":
        if valid_token_cache():
            return render_template("autenticacion_completa.html", autenticado=True)
        if valid_token_db(my_user_id=TW_USER_ID):
            return render_template("autenticacion_completa.html", autenticado=True)
        else:
            oauth_url = generar_url_oauth()
            return render_template("autenticar.html", auth_url=oauth_url, autenticado=False)
    if request.method == "POST":
        url = request.form.get('url')
        try:
            generar_tokens_oauth(url)
            flush_oauth_record(my_user_id=TW_USER_ID)
        except Exception:
            return render_template("hubo_algun_problema.html", autenticado=False)
        
        return render_template("autenticacion_completa.html", autenticado=True)

@app.route("/comenzar", methods=["POST"])
def comenzar():
    eliminados = limpieza()
    return render_template("limpieza_exito.html", eliminados=eliminados, autenticado=valid_token_cache())

def limpieza():
    my_user_id = TW_USER_ID

    vip_list = aux_limpieza.get_vip_list(my_user_id)

    followers = aux_limpieza.get_contacts(user_id=my_user_id, api="followers", bearer_token=oauth_record["bearer_token"])

    followees = aux_limpieza.get_contacts(user_id=my_user_id, api="following", bearer_token=oauth_record["bearer_token"])

    # Cross check both lists to find who I follow, who doesn't follow me back
    rate_limit = 50
    unfollowed = []
    for followee in followees:
        if rate_limit == 0:
            break
        if (followee not in followers) & (followee["username"] not in vip_list):
            aux_limpieza.unfollow(user_id=my_user_id, target_user_id=followee["id"], access_token=oauth_record["access"])
            unfollowed.append(followee["username"])
            rate_limit -= 1

    return (unfollowed)


@app.route("/redirect")
def redirect():
    return "Amparo"

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
