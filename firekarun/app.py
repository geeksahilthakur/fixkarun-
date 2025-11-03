import os
import json
from functools import wraps
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    Response,
    jsonify
)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'a_very_secret_key_fallback')

# --- Configuration ---
RULES_FILE = 'rules.json'
# Load admin credentials from environment variables, with defaults
ADMIN_USER = os.environ.get('FIXKAROO_ADMIN_USER', 'admin')
ADMIN_PASS = os.environ.get('FIXKAROO_ADMIN_PASS', 'password')


# --- Helper Functions ---

def load_rules():
    """Loads the firewall rules from the JSON file."""
    if not os.path.exists(RULES_FILE):
        # Create a default empty rules file if it doesn't exist
        save_rules({"blocked_ips": [], "blocked_ports": [], "blocked_combos": []})
        return {"blocked_ips": [], "blocked_ports": [], "blocked_combos": []}
    try:
        with open(RULES_FILE, 'r') as f:
            return json.load(f)
    except (IOError, json.JSONDecodeError):
        # Handle file read error or bad JSON
        return {"blocked_ips": [], "blocked_ports": [], "blocked_combos": []}


def save_rules(rules):
    """Saves the given rules dictionary to the JSON file."""
    try:
        with open(RULES_FILE, 'w') as f:
            json.dump(rules, f, indent=4)
        return True
    except IOError:
        return False


# --- Authentication ---

def check_auth(username, password):
    """Checks if a username and password are valid."""
    return username == ADMIN_USER and password == ADMIN_PASS


def authenticate():
    """Sends a 401 response that enables basic auth."""
    return Response(
        'Could not verify your access level for that URL.\n'
        'You have to login with proper credentials', 401,
        {'WWW-Authenticate': 'Basic realm="Login Required"'})


def requires_auth(f):
    """Decorator to protect routes with basic authentication."""

    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)

    return decorated


# --- Firewall Logic ---

def is_request_blocked():
    """Checks the incoming request against the firewall rules."""
    rules = load_rules()
    client_ip = request.remote_addr
    # Note: REMOTE_PORT is the *source* port of the client, which changes
    # for every new connection. Blocking source ports is unusual but
    hidden_port = request.environ.get('REMOTE_PORT')
    # Use a fallback if REMOTE_PORT is not available (e.g., in some test environments)
    client_port = 0
    if hidden_port:
        try:
            client_port = int(hidden_port)
        except ValueError:
            client_port = 0  # Could not parse port

    # 1. Check blocked IPs
    if client_ip in rules.get('blocked_ips', []):
        print(f"Blocking IP: {client_ip}")
        return True

    # 2. Check blocked ports
    if client_port in rules.get('blocked_ports', []):
        print(f"Blocking Port: {client_port}")
        return True

    # 3. Check blocked IP/Port combinations
    for combo in rules.get('blocked_combos', []):
        if combo.get('ip') == client_ip and combo.get('port') == client_port:
            print(f"Blocking Combo: {client_ip}:{client_port}")
            return True

    return False


# --- Main Application Routes ---

@app.route('/')
def index():
    """Main entry point. Runs the firewall check."""
    if is_request_blocked():
        return redirect(url_for('blocked'))

    # If not blocked, show the loading screen
    return render_template('loading.html')


@app.route('/success')
def success():
    """The page shown after the 'firewall check' passes."""
    return render_template('success.html')


@app.route('/blocked')
def blocked():
    """The page shown if the firewall blocks the request."""
    return render_template('blocked.html'), 403


# --- Admin Panel Routes ---

@app.route('/admin')
@requires_auth
def admin():
    """Displays the admin panel for managing rules."""
    rules = load_rules()
    return render_template('admin.html', rules=rules)


@app.route('/admin/add_rule', methods=['POST'])
@requires_auth
def add_rule():
    """Handles adding a new rule."""
    rules = load_rules()
    rule_type = request.form.get('rule_type')

    if rule_type == 'ip':
        ip = request.form.get('ip')
        if ip and ip not in rules['blocked_ips']:
            rules['blocked_ips'].append(ip)

    elif rule_type == 'port':
        port = request.form.get('port')
        if port:
            try:
                port_num = int(port)
                if port_num not in rules['blocked_ports']:
                    rules['blocked_ports'].append(port_num)
            except ValueError:
                pass  # Ignore invalid port numbers

    elif rule_type == 'combo':
        ip = request.form.get('ip')
        port = request.form.get('port')
        if ip and port:
            try:
                port_num = int(port)
                new_combo = {'ip': ip, 'port': port_num}
                if new_combo not in rules['blocked_combos']:
                    rules['blocked_combos'].append(new_combo)
            except ValueError:
                pass  # Ignore invalid port numbers

    save_rules(rules)
    return redirect(url_for('admin'))


@app.route('/admin/remove_rule', methods=['POST'])
@requires_auth
def remove_rule():
    """Handles removing an existing rule."""
    rules = load_rules()
    rule_type = request.form.get('rule_type')
    value = request.form.get('value')

    if rule_type == 'ip' and value in rules['blocked_ips']:
        rules['blocked_ips'].remove(value)

    elif rule_type == 'port':
        try:
            port_num = int(value)
            if port_num in rules['blocked_ports']:
                rules['blocked_ports'].remove(port_num)
        except (ValueError, TypeError):
            pass

    elif rule_type == 'combo':
        # Value will be a string like "ip:port"
        try:
            ip, port_str = value.split(':')
            port_num = int(port_str)
            combo_to_remove = {'ip': ip, 'port': port_num}
            if combo_to_remove in rules['blocked_combos']:
                rules['blocked_combos'].remove(combo_to_remove)
        except (ValueError, IndexError):
            pass  # Ignore malformed values

    save_rules(rules)
    return redirect(url_for('admin'))


# --- Main Execution ---

if __name__ == '__main__':
    # Initialize the rules file on first run
    load_rules()
    print("--- FixKaroo Admin Credentials ---")
    print(f"Username: {ADMIN_USER}")
    print(f"Password: {ADMIN_PASS}")
    print("----------------------------------")
    print("To change, set FIXKAROO_ADMIN_USER and FIXKAROO_ADMIN_PASS env variables.")
    # Run on 0.0.0.0 to be accessible on your network
    app.run(host='0.0.0.0', port=5000, debug=True)
