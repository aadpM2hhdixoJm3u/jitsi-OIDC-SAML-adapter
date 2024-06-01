from flask import Blueprint, request, session, url_for, redirect, current_app
from authlib.integrations.flask_client import OAuth
import jwt
from jwt import PyJWTError
from urllib.parse import urljoin
import datetime
import logging
import requests
import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import base64
import configparser

oidc_blueprint = Blueprint('oidc_auth', __name__)
oauth = OAuth()

# Load configurations
config = configparser.ConfigParser()
config.read('app.conf')

# Setup logging based on configuration file
logging_level = getattr(logging, config['logging']['level'].upper(), logging.INFO)
logging.basicConfig(
    level=logging_level,
    filename=config['logging']['filename'],
    filemode=config['logging']['filemode'],
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Access the settings from the configuration file
try:
    client_id = config['oauth']['client_id']
    client_secret = config['oauth']['client_secret']
    authorize_url = config['oauth']['authorize_url']
    access_token_url = config['oauth']['access_token_url']
    default_scope = config['oauth']['scope']
    jwks_uri = config['oauth']['jwks_uri']
    
    jitsi_base = config['urls']['jitsi_base']
    oidc_discovery = config['urls']['oidc_discovery']

    audience = config['jwt']['audience']
    issuer = config['jwt']['issuer']
    subject = config['jwt']['subject']
    secret_key = config['jwt']['secret_key']

    logging.info("Configuration loaded successfully")
except KeyError as e:
    logging.error(f"Configuration error: {e}")
    raise

def fetch_oidc_configuration():
    if not oidc_discovery:
        logging.debug("OIDC discovery URL is not provided. Skipping dynamic configuration.")
        return None

    try:
        response = requests.get(oidc_discovery)
        response.raise_for_status()
        json_response = response.json()
        logging.debug("OIDC Configuration successfully fetched.")
        if all(k in json_response for k in ['authorization_endpoint', 'token_endpoint', 'jwks_uri']):
            logging.debug("OIDC Configuration fetched: %s", json_response)
            return json_response
        else:
            logging.debug("OIDC configuration is missing required fields.")
            return None
    except requests.RequestException as e:
        logging.debug('Failed to fetch OIDC configuration: %s', e)
        return None

oidc_config = fetch_oidc_configuration()

def register_oidc_client(app):
    try:
        # Ensure scope is assigned a default value
        scope = default_scope
        if oidc_config and all(k in oidc_config for k in ['authorization_endpoint', 'token_endpoint', 'jwks_uri', 'issuer']):
            scope = oidc_config.get('scopes_supported', [scope])
            oauth.init_app(app)
            oauth.register(
                name='oidc',
                issuer=oidc_config['issuer'],
                client_id=client_id,
                client_secret=client_secret,
                authorize_url=oidc_config['authorization_endpoint'],
                access_token_url=oidc_config['token_endpoint'],
                jwks_uri=oidc_config['jwks_uri'],
                client_kwargs={'scope': ' '.join(scope)},
            )
            logging.info("OAuth client registered using dynamic configuration")
        else:
            oauth.init_app(app)
            oauth.register(
                name='oidc',
                issuer=issuer,
                client_id=client_id,
                client_secret=client_secret,
                authorize_url=authorize_url,
                access_token_url=access_token_url,
                jwks_uri=jwks_uri,
                client_kwargs={'scope': scope},
            )
            logging.info("OAuth client registered using static configuration")
    except Exception as e:
        logging.error(f"Unexpected error during OAuth registration: {e}")
        raise

def get_jwks_keys(jwks_uri):
    logging.debug(f"Using JWKS URI: {jwks_uri}")
    resp = requests.get(jwks_uri)
    return resp.json()

def jwks_to_pem(key_json):
    logging.debug("Convert the RSA key from JWK to PEM format.")
    public_num = rsa.RSAPublicNumbers(
        e=int(base64.urlsafe_b64decode(key_json['e'] + '==').hex(), 16),
        n=int(base64.urlsafe_b64decode(key_json['n'] + '==').hex(), 16)
    )
    public_key = public_num.public_key(default_backend())
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem

def parse_id_token(id_token, jwks_uri):
    logging.debug("Parsing ID token.")
    jwks = get_jwks_keys(jwks_uri)
    header = jwt.get_unverified_header(id_token)
    rsa_key = {}
    for key in jwks['keys']:
        if key['kid'] == header['kid']:
            rsa_key = jwks_to_pem(key)
            break
    if rsa_key:
        try:
            decoded = jwt.decode(
                id_token,
                rsa_key,
                algorithms=['RS256'],
                audience=oidc_config.get('client_id', config['oauth']['client_id']) if oidc_config else config['oauth']['client_id'],
                issuer=oidc_config.get('issuer', config['oauth']['issuer']) if oidc_config else config['oauth']['issuer']
            )
            logging.info("ID token successfully decoded.")
            return decoded
        except jwt.ExpiredSignatureError:
            logging.error("Token expired.")
            return None
        except jwt.InvalidTokenError:
            logging.error("Invalid token.")
            return None
        except PyJWTError as e:
            logging.error(f"JWT Error: {e}")
            return None
        except Exception as e:
            logging.error(f"Unexpected error decoding token: {e}")
    else:
        logging.error("RSA key not found for token decoding.")
    return None

@oidc_blueprint.route('/oidc/auth')
def login():
    logging.info("Accessed login endpoint")
    redirect_uri = urljoin(jitsi_base, '/oidc/redirect')
    logging.debug(f'Redirect URI: {redirect_uri}')
    result = oauth.oidc.create_authorization_url(redirect_uri=redirect_uri)
    auth_url = result['url']
    room_name = request.args.get('roomname', 'default_room')

    logging.debug(f'Authorization URL: {auth_url}')
    logging.debug(f'Room Name: {room_name}')
    logging.debug(f'OAuth State: {result["state"]}')
    logging.debug(f'OAuth Nonce: {result.get("nonce", "None")}')

    session['room_name'] = room_name
    session['oauth_state'] = result['state']
    session['oauth_nonce'] = result.get('nonce')

    logging.info(f'Session Room Name: {session["room_name"]}')
    logging.info(f'Session OAuth State: {session["oauth_state"]}')
    logging.info(f'Session OAuth Nonce: {session.get("oauth_nonce", "None")}')

    return redirect(auth_url)

@oidc_blueprint.route('/oidc/redirect')
def oauth_callback():
    logging.info("Accessed oauth_callback endpoint")
    try:
        code = request.args.get('code')
        if not code:
            logging.error("Authorization code not found")
            return "Authorization code not found", 400

        token_data = exchange_code_for_token(code)
        if not token_data or 'access_token' not in token_data:
            logging.error("Failed to retrieve access token")
            return "Failed to retrieve access token", 500

        if 'id_token' in token_data:
            jwks_uri = oidc_config['jwks_uri'] if oidc_config and 'jwks_uri' in oidc_config else config['oauth']['jwks_uri']
            logging.debug(f"Using JWKS URI: {jwks_uri}")

            id_token = parse_id_token(token_data['id_token'], jwks_uri)
            stored_nonce = session.pop('oauth_nonce', None)
            if not id_token or 'nonce' not in id_token or id_token['nonce'] != stored_nonce:
                logging.error("Nonce mismatch")
                return "Nonce mismatch", 400
        else:
            logging.error("ID token not found")
            return "ID token not found", 500

        email = id_token.get('email')
        avatar_url = get_gravatar_url(email) if email else 'http://example.com/default-avatar.png'

        session['user_info'] = {
            'name': id_token.get('displayName', 'Change me'),
            'email': id_token.get('email', 'no-email@example.com'),
            'avatar': avatar_url
        }

        logging.debug(f"User info stored in session: {session['user_info']}")
        return redirect(url_for('oidc_auth.tokenize'))
    except Exception as e:
        logging.error(f"Error in OIDC redirect function: {e}")
        return "An error occurred during the OIDC redirect process.", 500

def get_gravatar_url(email):
    if not email:
        return None
    email = email.strip().lower()
    email_hash = hashlib.sha256(email.encode('utf-8')).hexdigest()
    return f"https://www.gravatar.com/avatar/{email_hash}"

def exchange_code_for_token(code):
    try:
        token_url = oidc_config['token_endpoint'] if oidc_config else config['oauth']['access_token_url']
        redirect_uri = urljoin(jitsi_base, '/oidc/redirect')
        
        data = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': redirect_uri,
            'client_id': client_id,
            'client_secret': client_secret
        }

        logging.debug(f"Exchanging code for token with data: {data}")
        response = requests.post(token_url, data=data)
        logging.debug(f"Token exchange response status: {response.status_code}")
        logging.debug(f"Token exchange response body: {response.text}")
        
        if response.status_code == 200:
            logging.info("Token exchange successful.")
            return response.json()
        else:
            logging.error(f"Failed to exchange authorization code: HTTP {response.status_code}")
            return None
    except Exception as e:
        logging.error(f"Error exchanging code for token: {e}")
        return None

@oidc_blueprint.route('/oidc/tokenize')
def tokenize():
    logging.info("Accessed tokenize endpoint")  
    user_info = session.get('user_info')
    if not user_info:
        return 'User not logged in', 401

    jwt_payload = {
        "context": {
            "user": {
                "avatar": user_info.get('avatar', 'https://www.gravatar.com/avatar/'),
                "name": user_info['name'],
                "email": user_info['email'],
                "affiliation": "owner",
            }
        },
        "aud": config['jwt']['audience'],
        "iss": config['jwt']['issuer'],
        "sub": config['jwt']['subject'],
        "room": "*",
        "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=5)
    }

    secret_key = config['jwt']['secret_key']
    encoded_jwt = jwt.encode(jwt_payload, secret_key, algorithm='HS256')

    room_name = session.get('room_name', 'default_room')
    final_url = f"https://{config['jwt']['subject']}/{room_name}?jwt={encoded_jwt}"
    logging.info(f"Redirecting to: {final_url}")
    return redirect(final_url)
