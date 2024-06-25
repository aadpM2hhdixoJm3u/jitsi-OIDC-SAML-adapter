import configparser
import secrets
from flask import Flask, request, redirect, url_for, session
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_session import Session
import os

app = Flask(__name__)
app.secret_key = secrets.token_urlsafe(16)

# Apply ProxyFix to the main application
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

# Configure Flask-Session
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
Session(app)

# Load configuration
config = configparser.ConfigParser()
config.read('app.conf')
auth_mode = config['mode']['auth_mode'].upper()

# Conditionally import and register blueprints based on auth_mode
if auth_mode == 'OIDC':
    from oidc_auth import oidc_blueprint, register_oidc_client
    register_oidc_client(app)
    app.register_blueprint(oidc_blueprint)
elif auth_mode == 'SAML':
    from saml_auth import saml_blueprint
    app.register_blueprint(saml_blueprint)
else:
    raise ValueError("Invalid authentication mode configured")

@app.route('/auth')
def auth():
    roomname = request.args.get('roomname', 'default_room')
    session['room_name'] = roomname  # Store the room name in the session
    
    if auth_mode == 'SAML':
        return redirect(url_for('saml_auth.saml_login'))
    elif auth_mode == 'OIDC':
        return redirect(url_for('oidc_auth.login'))
    else:
        return "Invalid authentication mode configured", 400

def list_routes():
    with app.test_request_context():
        for rule in app.url_map.iter_rules():
            print(f"{rule.endpoint}: {rule.rule}")

if __name__ == '__main__':
    if os.getenv('LIST_ROUTES', '0') == '1':
        list_routes()
    app.run(debug=True)
