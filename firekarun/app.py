import json
import os
from functools import wraps
from flask import Flask, request, Response, render_template, redirect, url_for, session
import requests

app = Flask(__name__)

# --- CONFIGURATION ---
# !! IMPORTANT: Set this to your *real* Netlify site URL
TARGET_WEBSITE = "https://your-netlify-site.netlify.app"  # <--- SET THIS

# Admin credentials
ADMIN_USER = os.environ.get('ADMIN_USER', 'admin')
ADMIN_PASS = os.environ.get('ADMIN_PASS', 'fixkaroo123')
app.secret_key = os.environ.get('SECRET_KEY', 'a_very_secret_key_for_sessions')

RULES_FILE = 'rules.json'

# --- FIREWALL LOGIC ---

def get_rules():
    """Loads firewall rules from the JSON file."""
    if not os.path.exists(RULES_FILE):
        save_rules({"blocked_ips": [], "blocked_ports": [21, 22], "blocked_combos": []})
    with open(RULES_FILE, 'r') as f:
        return json.load(f)

def save_rules(rules):
    """Saves firewall rules to the JSON file."""
    with open(RULES_FILE, 'w') as f:
        json.dump(rules, f, indent=4)

def is_request_blocked(client_ip, client_port, rules):
    """Checks if a request matches any firewall rules."""
    if client_ip in rules.get('blocked_ips', []):
        print(f"Blocking IP: {client_ip}")
        return True
    
    try:
        # This try/except already handles client_port being None
        if int(client_port) in rules.get('blocked_ports', []):
            print(f"Blocking Port: {client_port}")
            return True
    except (ValueError, TypeError):
        pass 

    for combo in rules.get('blocked_combos', []):
        try:
            # This try/except already handles client_port being None
            if combo.get('ip') == client_ip and int(combo.get('port')) == int(client_port):
                print(f"Blocking Combo: {client_ip}:{client_port}")
                return True
        except (ValueError, TypeError):
            continue
            
    return False

# --- ADMIN PANEL ---
# (Admin routes must be defined *before* the catch-all proxy route)

def requires_auth(f):
    """Decorator to protect admin routes with session-based auth."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    """Admin login page."""
    error = None
    if request.method == 'POST':
        if request.form['username'] == ADMIN_USER and request.form['password'] == ADMIN_PASS:
            session['logged_in'] = True
            return redirect(url_for('admin_panel'))
        else:
            error = 'Invalid Credentials. Please try again.'
    # Uses the 'admin_login.html' template
    return render_template('admin_login.html', error=error) 

@app.route('/admin/logout')
def admin_logout():
    """Logs the admin out."""
    session.pop('logged_in', None)
    return redirect(url_for('admin_login'))

@app.route('/admin', methods=['GET', 'POST'])
@requires_auth
def admin_panel():
    """Admin panel for managing rules."""
    rules = get_rules()
    if request.method == 'POST':
        if 'add_ip' in request.form and request.form['ip']:
            if request.form['ip'] not in rules['blocked_ips']:
                rules['blocked_ips'].append(request.form['ip'])
        if 'add_port' in request.form and request.form['port']:
            port_to_add = int(request.form['port'])
            if port_to_add not in rules['blocked_ports']:
                rules['blocked_ports'].append(port_to_add)
        if 'add_combo_ip' in request.form and 'add_combo_port' in request.form:
            if request.form['add_combo_ip'] and request.form['add_combo_port']:
                combo_to_add = {
                    'ip': request.form['add_combo_ip'],
                    'port': int(request.form['add_combo_port'])
                }
                if combo_to_add not in rules['blocked_combos']:
                    rules['blocked_combos'].append(combo_to_add)
        
        if 'delete_ip' in request.form:
            rules['blocked_ips'] = [ip for ip in rules['blocked_ips'] if ip != request.form['delete_ip']]
        if 'delete_port' in request.form:
            rules['blocked_ports'] = [port for port in rules['blocked_ports'] if port != int(request.form['delete_port'])]
        if 'delete_combo' in request.form:
            ip_to_del, port_to_del = request.form['delete_combo'].split(':')
            rules['blocked_combos'] = [
                c for c in rules['blocked_combos'] 
                if not (c.get('ip') == ip_to_del and str(c.get('port')) == port_to_del)
            ]

        save_rules(rules)
        return redirect(url_for('admin_panel'))
        
    return render_template('admin.html', rules=rules)


# --- UI & PROXY ROUTES ---

@app.route('/success')
def success_page():
    """
    This page is shown after loading.html.
    It will automatically redirect to the / (root) to show the real site.
    """
    return render_template('success.html')

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
def main_proxy_handler(path):
    """
    This is the main entry point for ALL traffic.
    It checks if the user is verified (in session).
    If not, it runs the firewall check and shows the loading screen.
    If verified, it proxies the request.
    """
    
    # Check if user is already verified in this session
    if session.get('is_verified'):
        # --- PROXY LOGIC ---
        try:
            target_url = f"{TARGET_WEBSITE}/{path}"
            
            headers = {key: value for (key, value) in request.headers if key.lower() not in 'host'}
            headers['Host'] = TARGET_WEBSITE.split('//')[1]
            
            resp = requests.request(
                method=request.method,
                url=target_url,
                headers=headers,
                data=request.get_data(),
                cookies=request.cookies,
                allow_redirects=False,
                stream=True
            )

            if resp.status_code in (301, 302, 307, 308):
                # Rewrite redirect to point back to our proxy
                new_location = resp.headers['Location']
                if new_location.startswith(TARGET_WEBSITE):
                    # Replace target with our host_url, which is https://microsoft.in.net/
                    new_location = new_location.replace(TARGET_WEBSITE, request.host_url.rstrip('/'), 1)
                elif new_location.startswith('/'):
                    # This is a relative redirect, just pass it along
                    pass
                return redirect(new_location, code=resp.status_code)

            excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
            resp_headers = [(name, value) for (name, value) in resp.raw.headers.items()
                            if name.lower() not in excluded_headers]

            # --- Link Rewriting ---
            content = resp.content
            if 'text/html' in resp.headers.get('Content-Type', ''):
                # Rewrite links in the HTML to point back to our proxy
                content = content.replace(
                    TARGET_WEBSITE.encode('utf-8'), 
                    request.host_url.rstrip('/').encode('utf-8')
                )
            
            return Response(content, resp.status_code, resp_headers)

        except requests.exceptions.RequestException as e:
            print(f"Error proxying request: {e}")
            return "Proxy Error: Could not connect to target website.", 502
        # --- END OF PROXY LOGIC ---

    else:
        # --- NEW VISITOR / FIREWALL CHECK ---
        client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        client_port = request.environ.get('REMOTE_PORT')
        
        rules = get_rules()
        if is_request_blocked(client_ip, client_port, rules):
            return render_template('blocked.html', ip=client_ip, port=client_port), 403

        # If not blocked, mark as verified and show the loading screen
        session['is_verified'] = True
        return render_template('loading.html')



if __name__ == "__main__":
    app.run(debug=True, use_reloader=False)
