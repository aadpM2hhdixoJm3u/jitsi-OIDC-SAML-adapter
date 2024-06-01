from flask import Blueprint, request, redirect, session, url_for, send_file
import configparser
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from onelogin.saml2.idp_metadata_parser import OneLogin_Saml2_IdPMetadataParser
import logging
import datetime
import hashlib
import jwt
import uuid
import os
import subprocess
import requests

saml_blueprint = Blueprint('saml_auth', __name__)

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

def get_config_value(section, key, fallback=None):
    try:
        value = config[section].get(key, fallback)
        if value is None or value.strip() == '':
            if fallback is not None:
                return fallback
            else:
                logging.error(f"Missing value for key: [{section}] {key}")
                raise KeyError(f"Missing value for key: [{section}] {key}")
        return value
    except KeyError:
        if fallback is not None:
            return fallback
        else:
            logging.error(f"Missing configuration key: [{section}] {key}")
            raise

# Access the settings from the configuration file
try:
    jitsi_base = get_config_value('urls', 'jitsi_base')
    idp_metadata_url = get_config_value('urls', 'idp_metadata_url', '')

    audience = get_config_value('jwt', 'audience')
    issuer = get_config_value('jwt', 'issuer')
    subject = get_config_value('jwt', 'subject')
    secret_key = get_config_value('jwt', 'secret_key')

    authn_requests_signed = config.getboolean('security', 'authnRequestsSigned', fallback=False)
    logout_request_signed = config.getboolean('security', 'logoutRequestSigned', fallback=False)
    logout_response_signed = config.getboolean('security', 'logoutResponseSigned', fallback=False)
    want_messages_signed = config.getboolean('security', 'wantMessagesSigned', fallback=False)
    want_assertions_signed = config.getboolean('security', 'wantAssertionsSigned', fallback=False)
    want_assertions_encrypted = config.getboolean('security', 'wantAssertionsEncrypted', fallback=False)
    want_nameid_encrypted = config.getboolean('security', 'wantNameIdEncrypted', fallback=False)

    logging.info("Configuration loaded successfully")
except KeyError as e:
    logging.error(f"Configuration error: {e}")
    raise

def generate_certificate(cert_dir, cert_path, key_path):
    if not os.path.exists(cert_dir):
        os.makedirs(cert_dir)
        logging.info(f"Created directory: {cert_dir}")

    if not os.path.exists(cert_path) or not os.path.exists(key_path):
        logging.info("Certificate or key does not exist, creating...")
        try:
            subprocess.call([
                'openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-keyout', key_path,
                '-out', cert_path, '-days', '3650', '-nodes', '-subj',
                '/CN=samlsp' # If you need a bigger key, just change the value "rsa:2048" to the desired value
            ])
            logging.info("Certificate and key generated successfully.")
        except subprocess.CalledProcessError as e:
            raise Exception(f"Error generating certificate: {e}")
    else:
        logging.info("Certificate and key already exist")

base_dir = os.path.abspath(os.path.dirname(__file__))
cert_directory = os.path.join(base_dir, 'certs')
certificate_path = os.path.join(cert_directory, 'sp_cert.pem')
key_path = os.path.join(cert_directory, 'sp_key.pem')

generate_certificate(cert_directory, certificate_path, key_path)

metadata_directory = os.path.join(base_dir, 'metadata')
idp_metadata_directory = os.path.join(base_dir, 'idp_metadata')

os.makedirs(metadata_directory, exist_ok=True)
os.makedirs(idp_metadata_directory, exist_ok=True)

def fetch_idp_metadata_from_url(idp_metadata_url):
    logging.debug(f"Fetching IdP metadata from: {idp_metadata_url}")
    try:
        response = requests.get(idp_metadata_url)
        response.raise_for_status()
        return response.text
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching IdP metadata: {e}")
        raise

def read_idp_metadata_from_file(directory):
    logging.debug(f"Reading IdP metadata from directory: {directory}")

    latest_file = None
    latest_time = None

    for filename in os.listdir(directory):
        if filename.endswith(".xml"):
            file_path = os.path.join(directory, filename)
            file_mtime = os.path.getmtime(file_path)

            if latest_time is None or file_mtime > latest_time:
                latest_file = file_path
                latest_time = file_mtime

    if latest_file:
        try:
            with open(latest_file, 'r') as metadata_file:
                logging.info(f"IdP metadata loaded from: {latest_file}")
                return metadata_file.read()
        except Exception as e:
            logging.error(f"Error reading IdP metadata: {e}")
            raise

    raise FileNotFoundError("No IdP metadata file found in the metadata directory")

def init_saml_auth(request):
    req = prepare_flask_request(request)
    auth = OneLogin_Saml2_Auth(req, get_saml_settings())
    return auth

def get_saml_settings():
    if idp_metadata_url:
        idp_metadata = fetch_idp_metadata_from_url(idp_metadata_url)
        idp_metadata_file = os.path.join(idp_metadata_directory, 'idp_metadata.xml')
        with open(idp_metadata_file, 'w') as file:
            file.write(idp_metadata)
        logging.info(f"IdP metadata saved to: {idp_metadata_file}")
    else:
        idp_metadata_file = next(
            (os.path.join(idp_metadata_directory, f) for f in os.listdir(idp_metadata_directory) if f.endswith('.xml')),
            None
        )
        logging.info(f"Using IdP metadata file: {idp_metadata_file}")
        if not idp_metadata_file:
            raise FileNotFoundError("No IdP metadata file found in the metadata directory")
        idp_metadata = read_idp_metadata_from_file(idp_metadata_directory)

    # Parse the IdP metadata using OneLogin_Saml2_IdPMetadataParser
    parser = OneLogin_Saml2_IdPMetadataParser()
    idp_data = parser.parse(idp_metadata)

    # Generate SAML settings from the parsed IdP metadata
    saml_settings = {
        'strict': True,
        'debug': True,
        'sp': {
            'entityId': f"{jitsi_base}/saml/spmetadata",
            'assertionConsumerService': {
                'url': f"{jitsi_base}/saml/acs",
                'binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
            },
            'singleLogoutService': {
                'url': f"{jitsi_base}/saml/slo",
                'binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
            },
            'x509cert': open(certificate_path).read(),
            'privateKey': open(key_path).read(),
        },
        'idp': {
            'entityId': idp_data['idp']['entityId'],
            'singleSignOnService': idp_data['idp']['singleSignOnService'],
            'singleLogoutService': idp_data['idp'].get('singleLogoutService', {}),
            'x509cert': idp_data['idp']['x509cert'],
        },
        'security': {
            'authnRequestsSigned': authn_requests_signed,
            'logoutRequestSigned': logout_request_signed,
            'logoutResponseSigned': logout_response_signed,
            'wantMessagesSigned': want_messages_signed,
            'wantAssertionsSigned': want_assertions_signed,
            'wantAssertionsEncrypted': want_assertions_encrypted,
            'wantNameIdEncrypted': want_nameid_encrypted,
        },
    }

    # Debugging the values in the security section
    logging.debug("Security settings:")
    logging.debug(f"authnRequestsSigned: {saml_settings['security']['authnRequestsSigned']}")
    logging.debug(f"logoutRequestSigned: {saml_settings['security']['logoutRequestSigned']}")
    logging.debug(f"logoutResponseSigned: {saml_settings['security']['logoutResponseSigned']}")
    logging.debug(f"wantMessagesSigned: {saml_settings['security']['wantMessagesSigned']}")
    logging.debug(f"wantAssertionsSigned: {saml_settings['security']['wantAssertionsSigned']}")
    logging.debug(f"wantAssertionsEncrypted: {saml_settings['security']['wantAssertionsEncrypted']}")
    logging.debug(f"wantNameIdEncrypted: {saml_settings['security']['wantNameIdEncrypted']}")

    logging.debug("Security settings: %s", saml_settings['security'])

    return OneLogin_Saml2_Settings(settings=saml_settings, custom_base_path=os.path.abspath(base_dir))

def create_saml_metadata():
    metadata_file_path = os.path.join(metadata_directory, 'SPmetadata.xml')
    
    if os.path.exists(metadata_file_path):
        logging.info(f"Metadata file already exists at {metadata_file_path}, skipping generation. Delete {metadata_file_path} if you need to regenerate it.")
        return

    saml_settings = get_saml_settings()
    metadata = saml_settings.get_sp_metadata()
    errors = saml_settings.validate_metadata(metadata)

    if len(errors) > 0:
        raise Exception(f"Error validating SP metadata: {', '.join(errors)}")

    try:
        with open(metadata_file_path, 'w') as metadata_file:
            metadata_file.write(metadata.decode('utf-8'))  
        logging.info(f"Metadata successfully generated and saved to {metadata_file_path}")
    except Exception as e:
        logging.error(f"Failed to generate or write metadata: {e}")

create_saml_metadata()

@saml_blueprint.route('/saml/login')
def saml_login():
    try:
        auth = init_saml_auth(request)
        session['unique_id'] = str(uuid.uuid4())
        return redirect(auth.login())
    except Exception as e:
        logging.error(f"Error during SAML login: {e}")
        return f"Error during SAML login: {e}", 500

@saml_blueprint.route('/saml/acs', methods=['POST'])
def saml_acs():
    try:
        auth = init_saml_auth(request)
        auth.process_response()
        errors = auth.get_errors()

        if errors:
            logging.error(f"SAML ACS Errors: {errors}")
            logging.error(f"Last error reason: {auth.get_last_error_reason()}")
            return f"Error processing SAML response: {errors} - {auth.get_last_error_reason()}", 500

        if auth.is_authenticated():
            session['saml_user_data'] = auth.get_attributes()
            logging.debug(f"SAML Userdata: {session['saml_user_data']}")

            # Retrieve unique_id from the session and continue processing
            unique_id = session.get('unique_id')
            if unique_id is None:
                logging.error("No 'unique_id' found in session")
                return "Error: No unique ID found in session", 400

            # Check for displayName in the user's SAML attributes
            display_name = session['saml_user_data'].get('displayName')
            if not display_name:
                logging.error("Access denied: User does not have a displayName")
                return "Access Denied: Required displayName attribute not found. Please provide this information to your support team.", 403

            # Optionally check for email
            email = session['saml_user_data'].get('email')
            if email:
                logging.debug(f"User email: {email}")
            else:
                logging.debug("User email not provided")

            # Retrieve and remove the post-authentication redirect URL from the session
            redirect_url = session.pop('post_auth_redirect', None)
            if redirect_url:
                return redirect(redirect_url)
            else:
                return redirect(url_for('saml_auth.tokenize'))
        else:
            logging.error("Authentication failed")
            return "Authentication failed", 403
    except Exception as e:
        logging.error(f"Error during SAML ACS: {e}")
        return f"Error during SAML ACS: {e}", 500



@saml_blueprint.route('/saml/metadata')
def saml_metadata():
    metadata_file_path = os.path.join(metadata_directory, 'SPmetadata.xml')
    try:
        return send_file(metadata_file_path, mimetype='text/xml')
    except Exception as e:
        logging.error(f"Failed to send metadata file: {e}")
        return "Error serving metadata file", 500

@saml_blueprint.route('/saml/slo')
def saml_slo():
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    name_id = session.get('saml_name_id')
    session_index = session.get('saml_session_index')
    return redirect(auth.logout(name_id=name_id, session_index=session_index))

def get_gravatar_url(mail):
    if not mail:
        return None
    mail = mail.strip().lower()
    mail_hash = hashlib.sha256(mail.encode('utf-8')).hexdigest()
    return f"https://www.gravatar.com/avatar/{mail_hash}"

@saml_blueprint.route('/saml/tokenize')
def tokenize():
    user_info = session.get('saml_user_data')
    if not user_info:
        return 'User not logged in', 401

    room_name = session.get('room_name', 'default_room')
    logging.debug(f"Using room_name: {room_name}")

    # Extract displayName and email from the SAML attributes
    display_name = user_info.get('displayName', [None])[0]
    email = user_info.get('mail', [None])[0]
    
    if not email:
        logging.debug("User email not provided")
    
    logging.debug(f"User email: {email}")
    logging.debug(f"User displayName: {display_name}")

    jwt_payload = {
        "context": {
            "user": {
                "avatar": get_gravatar_url(email),
                "name": display_name,
                "email": email,
                "affiliation": "owner",
            }
        },
        "aud": audience,
        "iss": issuer,
        "sub": subject,
        "room": "*",
        "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=5)
    }

    encoded_jwt = jwt.encode(jwt_payload, secret_key, algorithm='HS256')

    final_url = f"https://{subject}/{room_name}?jwt={encoded_jwt}"
    logging.info(f"Redirecting to: {final_url}")
    return redirect(final_url)

def prepare_flask_request(request):
    url_data = {
        'https': 'on' if request.scheme == 'https' else 'off',
        'http_host': request.host.split(':')[0],  # Remove port number from host
        'script_name': request.path,
        'get_data': request.args.copy(),
        'post_data': request.form.copy(),
        'query_string': request.query_string
    }
    return {
        'https': url_data['https'],
        'http_host': url_data['http_host'],
        'script_name': url_data['script_name'],
        'get_data': url_data['get_data'],
        'post_data': url_data['post_data'],
        'query_string': url_data['query_string']
    }
