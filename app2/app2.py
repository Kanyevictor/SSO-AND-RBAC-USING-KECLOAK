import os
from flask import Flask, redirect, url_for, session, jsonify, render_template
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
from functools import wraps
import jwt

# =============================
# Load environment variables
# =============================
load_dotenv()

app = Flask(__name__)

# Flask session secret (ONLY for lab/demo)
app.secret_key = "dev-secret-change-me"

# =============================
# Keycloak configuration
# =============================
KEYCLOAK_URL = os.getenv("KEYCLOAK_URL")
REALM = os.getenv("REALM")
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")

# =============================
# OAuth client setup
# =============================
oauth = OAuth(app)

oauth.register(
    name="keycloak",
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    # OpenID Connect discovery endpoint
    server_metadata_url=f"{KEYCLOAK_URL}/realms/{REALM}/.well-known/openid-configuration",
    client_kwargs={
        "scope": "openid profile email",
        "verify": False  # OK for lab / self-signed TLS
    },
)

# ==================================================
# RBAC helper functions (roles extracted from token)
# ==================================================

def get_user_roles():
    """
    Extract realm and client roles from Keycloak access token
    """
    if "token" not in session:
        return []

    token = session["token"]
    roles = []

    try:
        decoded = jwt.decode(
            token["access_token"],
            options={"verify_signature": False}
        )

        # Realm roles
        realm_roles = decoded.get("realm_access", {}).get("roles", [])
        roles.extend(realm_roles)

        # Client roles
        client_roles = decoded.get(
            "resource_access", {}
        ).get(CLIENT_ID, {}).get("roles", [])
        roles.extend(client_roles)

    except Exception:
        pass

    return list(set(roles))


def role_required(*required_roles):
    """
    Decorator enforcing role-based access control
    """
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if "user" not in session:
                return redirect(url_for("login"))

            user_roles = get_user_roles()

            if not any(role in user_roles for role in required_roles):
                return render_template(
                    "access_denied.html",
                    required_roles=required_roles,
                    user_roles=user_roles
                )

            return f(*args, **kwargs)
        return wrapper
    return decorator


# =============================
# Routes
# =============================

@app.route("/")
def home():
    """
    Home page ALWAYS renders HTML.
    Login state is handled inside the template.
    """
    user = session.get("user")
    roles = get_user_roles() if user else []
    return render_template("home.html", user=user, roles=roles)


@app.route("/login")
def login():
    """
    Redirect user to Keycloak login page
    """
    return oauth.keycloak.authorize_redirect(
        redirect_uri=url_for("callback", _external=True)
    )


@app.route("/callback")
def callback():
    """
    Called by Keycloak after successful login.
    Exchanges authorization code for tokens.
    """
    token = oauth.keycloak.authorize_access_token()
    session["token"] = token
    session["user"] = token["userinfo"]
    return redirect(url_for("home"))


@app.route("/logout")
def logout():
    """
    Clear local session and redirect to Keycloak logout
    """
    session.clear()
    return redirect(
        f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/logout"
    )


# =============================
# API endpoint (for demo)
# =============================

@app.route("/api/info")
def api_info():
    """
    Simple protected API endpoint
    """
    if "user" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    return jsonify({
        "app": "app2",
        "user": session["user"]["preferred_username"],
        "roles": get_user_roles()
    })


# =============================
# RBAC protected pages
# =============================

@app.route("/public")
def public_page():
    return render_template("public.html")


@app.route("/viewer")
@role_required("viewer", "editor", "admin")
def viewer_page():
    return render_template(
        "protected.html",
        title="Viewer Page",
        icon="👁️",
        message="You have viewer access.",
        user=session.get("user"),
        roles=get_user_roles()
    )


@app.route("/editor")
@role_required("editor", "admin")
def editor_page():
    return render_template(
        "protected.html",
        title="Editor Page",
        icon="✏️",
        message="You have editor access.",
        user=session.get("user"),
        roles=get_user_roles()
    )


@app.route("/admin")
@role_required("admin")
def admin_page():
    return render_template(
        "protected.html",
        title="Admin Page",
        icon="⚙️",
        message="You have full admin access.",
        user=session.get("user"),
        roles=get_user_roles()
    )


# =============================
# App entry point
# =============================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3002)
