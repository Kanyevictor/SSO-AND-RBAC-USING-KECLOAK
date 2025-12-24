import os
from flask import Flask, redirect, url_for, session, jsonify
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = "dev-secret-change-me"

KEYCLOAK_URL = os.getenv("KEYCLOAK_URL")
REALM = os.getenv("REALM")
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")

oauth = OAuth(app)

oauth.register(
    name="keycloak",
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    server_metadata_url=f"{KEYCLOAK_URL}/realms/{REALM}/.well-known/openid-configuration",
    client_kwargs={"scope": "openid profile email",
                    "verify": False},
)

@app.route("/")
def home():
    if "user" in session:
        return f"""
        <h2>App 1</h2>
        <p>Welcome {session['user']['preferred_username']}</p>
        <a href="/api/data">Call API</a><br>
        <a href="/logout">Logout</a>
        """
    return '<a href="/login">Login to App 1</a>'

@app.route("/login")
def login():
    return oauth.keycloak.authorize_redirect(
        redirect_uri=url_for("callback", _external=True)
    )

@app.route("/callback")
def callback():
    token = oauth.keycloak.authorize_access_token()
    userinfo = token["userinfo"]
    session["user"] = userinfo
    session["token"] = token
    return redirect("/")

@app.route("/api/data")
def api_data():
    if "user" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    return jsonify({
        "app": "app1",
        "user": session["user"]["preferred_username"],
        "email": session["user"].get("email")
    })

@app.route("/logout")
def logout():
    session.clear()
    return redirect(
        f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/logout"
    )

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3001)