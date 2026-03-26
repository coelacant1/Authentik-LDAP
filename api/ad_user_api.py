# ad_user_api.py
from flask import Flask, request, jsonify, abort
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from ldap3 import Server, Connection, MODIFY_ADD, MODIFY_REPLACE
from ldap3.utils.conv import escape_filter_chars
import logging
import os
import re
import secrets
import string

app = Flask(__name__)
limiter = Limiter(app=app, key_func=get_remote_address, default_limits=["60 per minute"])

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration from environment variables
API_KEY = os.environ.get('AD_API_KEY', '')
AD_SERVER = os.environ.get('AD_SERVER', 'ldaps://localhost:636')
AD_BIND_USER = os.environ.get('AD_BIND_USER', '')
AD_BIND_PASSWORD = os.environ.get('AD_BIND_PASSWORD', '')
STUDENTS_OU = os.environ.get('AD_STUDENTS_OU', '')
USERS_SEARCH_BASE = os.environ.get('AD_USERS_SEARCH_BASE', '')
STUDENTS_GROUP_DN = os.environ.get('AD_STUDENTS_GROUP_DN', '')
ALLOWED_DOMAINS = os.environ.get('AD_ALLOWED_DOMAINS', '').split(',')

def generate_password(length=16):
    """Generate a secure random password with uppercase, lowercase, numbers, and symbols"""
    uppercase = string.ascii_uppercase
    lowercase = string.ascii_lowercase
    digits = string.digits
    symbols = "!@#$%^&*()-_=+[]{}|;:,.<>?"

    # Ensure at least one of each type
    password = [
        secrets.choice(uppercase),
        secrets.choice(lowercase),
        secrets.choice(digits),
        secrets.choice(symbols),
    ]

    # Fill the rest with random characters from all types
    all_chars = uppercase + lowercase + digits + symbols
    password += [secrets.choice(all_chars) for _ in range(length - 4)]

    # Shuffle to avoid predictable positions
    password_list = list(password)
    secrets.SystemRandom().shuffle(password_list)

    return ''.join(password_list)

def require_api_key(f):
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or auth_header != f'Bearer {API_KEY}':
            abort(401, 'Invalid or missing API key')
        return f(*args, **kwargs)
    decorated.__name__ = f.__name__
    return decorated

@app.route('/create-user', methods=['POST'])
@limiter.limit("10 per minute")
@require_api_key
def create_user():
    data = request.json

    # Handle direct API calls (for testing)
    email = data.get('email')
    name = data.get('name')
    password = generate_password(16)

    # Handle authentik webhook format
    if not email and 'body' in data:
        prompt_data = data.get('body', {}).get('context', {}).get('prompt_data', {})
        email = prompt_data.get('email')
        name = prompt_data.get('name')

    if not all([email, name, password]):
        return jsonify({'success': False, 'error': 'Missing required fields'}), 400

    # Check email domain
    if not any(email.lower().endswith(domain.lower()) for domain in ALLOWED_DOMAINS):
        return jsonify({'success': False, 'error': 'Email domain not allowed'}), 403

    # Generate username from email with validation
    username = email.split('@')[0]
    if not re.match(r'^[a-zA-Z0-9._-]{1,20}$', username):
        return jsonify({'success': False, 'error': 'Invalid email format'}), 400

    try:
        server = Server(AD_SERVER, use_ssl=True, connect_timeout=10)
        conn = Connection(server, user=AD_BIND_USER, password=AD_BIND_PASSWORD, receive_timeout=10)
        conn.bind()

        if not conn.bound:
            return jsonify({'success': False, 'error': 'Failed to bind to AD'}), 500

        # Check if user already exists
        safe_username = escape_filter_chars(username)
        conn.search(
            USERS_SEARCH_BASE,
            f'(&(objectCategory=person)(objectClass=user)(sAMAccountName={safe_username}))',
            attributes=['distinguishedName']
        )

        if conn.entries:
            conn.unbind()
            return jsonify({'success': False, 'error': 'User already exists'}), 409

        # Create user DN
        safe_cn = name.replace('\\', '\\\\').replace(',', '\\,').replace('+', '\\+').replace('"', '\\"').replace('<', '\\<').replace('>', '\\>').replace(';', '\\;').replace('=', '\\=')
        user_dn = f'CN={safe_cn},{STUDENTS_OU}'

        # Split name
        name_parts = name.split(' ', 1)
        first_name = name_parts[0]
        last_name = name_parts[1] if len(name_parts) > 1 else name_parts[0]

        # Create user attributes
        user_attributes = {
            'objectClass': ['top', 'person', 'organizationalPerson', 'user'],
            'cn': name,
            'givenName': first_name,
            'sn': last_name,
            'displayName': name,
            'sAMAccountName': username,
            'userPrincipalName': f'{username}@<AD_DOMAIN>',
            'mail': email,
            'userAccountControl': 512,
            'unicodePwd': ('"' + password + '"').encode('utf-16-le'),
        }

        result = conn.add(user_dn, attributes=user_attributes)

        if not result:
            conn.unbind()
            logger.error(f"Failed to create user {username}: {conn.result}")
            return jsonify({
                'success': False,
                'error': 'Failed to create user account'
            }), 500

        # Add to Students group
        group_result = conn.modify(STUDENTS_GROUP_DN, {'member': [(MODIFY_ADD, [user_dn])]})

        group_message = ""
        if not group_result:
            group_message = f"Warning: Failed to add to Students group: {conn.result}"
            logger.error(group_message)
        else:
            group_message = "User added to Students group"
            logger.info(group_message)

        conn.unbind()

        return jsonify({
            'success': True,
            'username': username,
            'message': f'Account created for {name}',
            'group_status': group_message
        })

    except Exception as e:
        logger.error(f"Error: {str(e)}")
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

@app.route('/enable-user', methods=['POST'])
@limiter.limit("10 per minute")
@require_api_key
def enable_user():
    """Enable a disabled user account and unlock if locked"""
    data = request.json
    email = data.get('email')

    # Handle authentik webhook format
    if not email and 'body' in data:
        prompt_data = data.get('body', {}).get('context', {}).get('prompt_data', {})
        email = prompt_data.get('email')

    # Also check for user object in webhook
    if not email and 'body' in data:
        user_data = data.get('body', {}).get('user', {})
        email = user_data.get('email')

    if not email:
        return jsonify({'success': False, 'error': 'Email is required'}), 400

    username = email.split('@')[0]
    if not re.match(r'^[a-zA-Z0-9._-]{1,20}$', username):
        return jsonify({'success': False, 'error': 'Invalid email format'}), 400

    try:
        server = Server(AD_SERVER, use_ssl=True, connect_timeout=10)
        conn = Connection(server, user=AD_BIND_USER, password=AD_BIND_PASSWORD, receive_timeout=10)
        conn.bind()

        if not conn.bound:
            return jsonify({'success': False, 'error': 'Failed to bind to AD'}), 500

        # Find user
        safe_username = escape_filter_chars(username)
        conn.search(
            USERS_SEARCH_BASE,
            f'(&(objectCategory=person)(objectClass=user)(sAMAccountName={safe_username}))',
            attributes=['userAccountControl', 'distinguishedName', 'lockoutTime']
        )

        if not conn.entries:
            conn.unbind()
            return jsonify({'success': False, 'error': 'User not found'}), 404

        user_entry = conn.entries[0]
        user_dn = user_entry.distinguishedName.value
        current_uac = user_entry.userAccountControl.value

        lockout_time = 0
        if hasattr(user_entry, 'lockoutTime') and user_entry.lockoutTime.value is not None:
            try:
                lockout_time = int(user_entry.lockoutTime.value)
            except (ValueError, TypeError):
                lockout_time = 0

        modifications = {}
        actions_taken = []

        # Check if account is disabled (bit 2)
        is_disabled = bool(current_uac & 0x2)

        if is_disabled:
            # Remove the disabled bit by clearing bit 2
            new_uac = current_uac & ~0x2  # Clear bit 2
            # Ensure bit 9 is set (normal account)
            new_uac = new_uac | 0x200

            modifications['userAccountControl'] = [(MODIFY_REPLACE, [new_uac])]
            actions_taken.append(f'enabled account (UAC: {current_uac} -> {new_uac})')
            logger.info(f"Enabling account {username}: UAC {current_uac} -> {new_uac}")

        # Check if account is locked out
        if lockout_time > 0:
            # Unlock by setting lockoutTime to 0
            modifications['lockoutTime'] = [(MODIFY_REPLACE, [0])]
            actions_taken.append('unlocked account')
            logger.info(f"Unlocking account {username}")

        if not modifications:
            conn.unbind()
            return jsonify({
                'success': True,
                'message': f'Account {username} is already enabled and unlocked',
                'already_enabled': True
            })

        # Apply modifications
        result = conn.modify(user_dn, modifications)

        if not result:
            error_msg = conn.result
            conn.unbind()
            logger.error(f"Failed to enable/unlock {username}: {error_msg}")
            return jsonify({
                'success': False,
                'error': 'Failed to enable account'
            }), 500

        conn.unbind()

        message = f"Account {username}: {', '.join(actions_taken)}"
        logger.info(f"Success: {message}")

        return jsonify({
            'success': True,
            'message': message,
            'username': username,
            'actions': actions_taken
        })

    except Exception as e:
        logger.error(f"Error: {str(e)}")
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

@app.route('/check-user-status', methods=['POST'])
@limiter.limit("10 per minute")
@require_api_key
def check_user_status():
    """Check if a user account is enabled/disabled in AD"""
    data = request.json
    email = data.get('email')

    if not email:
        return jsonify({'success': False, 'error': 'Email is required'}), 400

    username = email.split('@')[0]
    if not re.match(r'^[a-zA-Z0-9._-]{1,20}$', username):
        return jsonify({'success': False, 'error': 'Invalid email format'}), 400

    try:
        server = Server(AD_SERVER, use_ssl=True, connect_timeout=10)
        conn = Connection(server, user=AD_BIND_USER, password=AD_BIND_PASSWORD, receive_timeout=10)
        conn.bind()

        if not conn.bound:
            return jsonify({'success': False, 'error': 'Failed to bind to AD'}), 500

        # Find user
        safe_username = escape_filter_chars(username)
        conn.search(
            USERS_SEARCH_BASE,
            f'(&(objectCategory=person)(objectClass=user)(sAMAccountName={safe_username}))',
            attributes=['userAccountControl', 'lockoutTime']
        )

        if not conn.entries:
            conn.unbind()
            return jsonify({'success': False, 'error': 'User not found'}), 404

        user_entry = conn.entries[0]
        uac = user_entry.userAccountControl.value

        # Safely get lockoutTime
        lockout_time = 0
        if hasattr(user_entry, 'lockoutTime') and user_entry.lockoutTime.value is not None:
            try:
                lockout_time = int(user_entry.lockoutTime.value)
            except (ValueError, TypeError):
                lockout_time = 0

        # Check if account is enabled (bit 2 = 0x2 = disabled)
        is_disabled = bool(uac & 0x2)
        is_active = not is_disabled
        is_locked = lockout_time > 0

        conn.unbind()

        return jsonify({
            'success': True,
            'is_active': is_active,
            'is_locked': is_locked,
            'userAccountControl': uac,
            'lockoutTime': lockout_time
        })

    except Exception as e:
        logger.error(f"Error: {str(e)}")
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok'})


if __name__ == '__main__':
    app.run(host=os.environ.get('AD_API_HOST', '127.0.0.1'), port=int(os.environ.get('AD_API_PORT', '5000')))
