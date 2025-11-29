#!/bin/bash
# Full ZIVPN UDP + Web Admin Panel + HTTPS installer
# Run as root or with sudo: sudo bash zi-full-install.sh
set -euo pipefail

LOGFILE="/root/zi-install.log"
exec > >(tee -a "$LOGFILE") 2>&1

echo "===== ZIVPN UDP + Web Admin Panel Installer (Full) ====="
echo "Timestamp: $(date -u +"%Y-%m-%d %H:%M:%SZ")"

# Basic checks
if [ "$(id -u)" -ne 0 ]; then
  echo "Please run as root (sudo)." && exit 1
fi

# Update system
echo "--- Updating apt ---"
apt-get update -y
apt-get upgrade -y

# Stop existing services if present
systemctl stop zivpn.service 2>/dev/null || true
systemctl stop zivpn-admin.service 2>/dev/null || true

# 1) Install core ZIVPN binary
ZIVPN_BIN_URL="https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-amd64"
echo "--- Downloading zivpn binary ---"
if ! wget -q -O /usr/local/bin/zivpn "$ZIVPN_BIN_URL"; then
  echo "Failed to download zivpn binary from $ZIVPN_BIN_URL" && exit 1
fi
chmod +x /usr/local/bin/zivpn

# 2) Prepare config dir and default config
mkdir -p /etc/zivpn
ZIVPN_CONFIG_URL="https://raw.githubusercontent.com/zahidbd2/udp-zivpn/main/config.json"
echo "--- Downloading default config.json ---"
if ! wget -q -O /etc/zivpn/config.json "$ZIVPN_CONFIG_URL"; then
  echo "Failed to download config.json. Creating minimal default."
  cat > /etc/zivpn/config.json <<'JSON'
{
  "config": ["zi"],
  "port": 5667
}
JSON
fi
chmod 600 /etc/zivpn/config.json

# 3) Generate certificate for zivpn (not web)
echo "--- Generating self-signed cert for zivpn (internal) ---"
openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 \
  -subj "/C=US/ST=California/L=Los Angeles/O=ZIVPN/OU=IT/CN=zivpn" \
  -keyout /etc/zivpn/zivpn.key -out /etc/zivpn/zivpn.crt >/dev/null 2>&1 || true
chmod 600 /etc/zivpn/zivpn.key /etc/zivpn/zivpn.crt || true

# 4) sysctl tuning
sysctl -w net.core.rmem_max=16777216 >/dev/null 2>&1 || true
sysctl -w net.core.wmem_max=16777216 >/dev/null 2>&1 || true

# 5) Create systemd service for zivpn
cat > /etc/systemd/system/zivpn.service <<'SERVICE'
[Unit]
Description=zivpn VPN Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/etc/zivpn
ExecStart=/usr/local/bin/zivpn server -c /etc/zivpn/config.json
Restart=always
RestartSec=3
Environment=ZIVPN_LOG_LEVEL=info
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable zivpn.service
systemctl restart zivpn.service || true

# 6) Ask for initial ZIVPN passwords (preserve original behavior)
echo
echo "ZIVPN UDP Passwords"
read -p "Enter passwords separated by commas, example: pass1,pass2 (Press enter for Default 'zi'): " input_config || true
if [ -n "${input_config:-}" ]; then
  IFS=',' read -r -a config_array <<< "$input_config"
  if [ ${#config_array[@]} -eq 1 ]; then
    config_array+=("${config_array[0]}")
  fi
else
  config_array=("zi")
fi

# Save admin password (first password)
ADMIN_PASS="${config_array[0]}"
echo "${ADMIN_PASS}" > /etc/zivpn/admin.pass
chmod 600 /etc/zivpn/admin.pass

# Update config.json "config" array safely
# Read current config.json, update key "config"
python3 - <<PYCODE || true
import json,sys
cfg_path="/etc/zivpn/config.json"
try:
    with open(cfg_path,"r") as f:
        cfg=json.load(f)
except:
    cfg={}
cfg["config"]=[$(printf '"%s",' "${config_array[@]}" | sed 's/,$//')]
with open(cfg_path,"w") as f:
    json.dump(cfg,f,indent=2)
print("Updated /etc/zivpn/config.json")
PYCODE

# 7) Firewall / NAT rules
IFACE=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1 || echo "eth0")
echo "--- Setting iptables and ufw rules ---"
iptables -t nat -A PREROUTING -i "$IFACE" -p udp --dport 6000:19999 -j DNAT --to-destination :5667 2>/dev/null || true
iptables -t nat -A PREROUTING -i "$IFACE" -p udp --dport 6000:19999 -j DNAT --to-destination :5667 -m comment --comment "zivpn" 2>/dev/null || true
ufw allow 6000:19999/udp || true
ufw allow 5667/udp || true

echo "Core ZIVPN installed."

################################################################################
# Admin Panel (Flask) installation
################################################################################

echo "--- Installing Python and dependencies for Admin Panel ---"
apt-get install -y python3 python3-venv python3-pip build-essential nginx certbot python3-certbot-nginx >/dev/null 2>&1 || {
  echo "Failed to install some packages via apt. Please check apt sources."; 
}

ADMIN_DIR="/opt/zivpn-admin"
mkdir -p "$ADMIN_DIR"
chown root:root "$ADMIN_DIR"

echo "--- Creating virtualenv and installing python packages ---"
python3 -m venv "${ADMIN_DIR}/venv"
"${ADMIN_DIR}/venv/bin/pip" install --upgrade pip >/dev/null 2>&1
"${ADMIN_DIR}/venv/bin/pip" install flask psutil >/dev/null 2>&1

# Data files
if [ ! -f /etc/zivpn/accounts.json ]; then
  echo "[]" > /etc/zivpn/accounts.json
  chmod 600 /etc/zivpn/accounts.json
fi
if [ ! -f /etc/zivpn/web_secret.key ]; then
  head -c 32 /dev/urandom > /etc/zivpn/web_secret.key
  chmod 600 /etc/zivpn/web_secret.key
fi

cat > /etc/zivpn/admin.meta <<'META'
# admin metadata (do not edit)
ADMIN_PASSWORD_FILE=/etc/zivpn/admin.pass
META
chmod 600 /etc/zivpn/admin.meta

# 8) Write Flask app (complete) to ADMIN_DIR/app.py
cat > "${ADMIN_DIR}/app.py" <<'PY'
#!/usr/bin/env python3
from flask import Flask, request, redirect, render_template_string, session, url_for, jsonify, flash
import os, json, subprocess, datetime, time
import psutil
from functools import wraps

app = Flask(__name__)
try:
    with open('/etc/zivpn/web_secret.key','rb') as f:
        app.secret_key = f.read()
except:
    app.secret_key = os.urandom(24)

ADMIN_PASS_FILE = '/etc/zivpn/admin.pass'
ACCOUNTS_FILE = '/etc/zivpn/accounts.json'
ZIVPN_CONFIG = '/etc/zivpn/config.json'
ZIVPN_SERVICE = 'zivpn.service'

def read_admin_pass():
    try:
        return open(ADMIN_PASS_FILE).read().strip()
    except:
        return ''

def login_required(f):
    @wraps(f)
    def wrapped(*a, **kw):
        if session.get('logged_in'):
            return f(*a, **kw)
        return redirect(url_for('login'))
    return wrapped

def get_server_ip():
    try:
        out = subprocess.check_output("hostname -I | awk '{print $1}'", shell=True).decode().strip()
        if out:
            return out
    except:
        pass
    return request.host.split(':')[0]

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        pw = request.form.get('password','')
        if pw == read_admin_pass():
            session['logged_in'] = True
            flash('Login successful','success')
            return redirect(url_for('dashboard'))
        flash('Invalid password','danger')
    return render_template_string(LOGIN_HTML, message=request.args.get('message',''))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def dashboard():
    server_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    cpu = psutil.cpu_percent(interval=0.5)
    vm = psutil.virtual_memory()
    ram_used = f"{vm.used // (1024**2)} MB / {vm.total // (1024**2)} MB ({vm.percent}%)"
    disk = psutil.disk_usage('/')
    storage = f"{disk.used // (1024**3)} GB / {disk.total // (1024**3)} GB ({disk.percent}%)"
    try:
        with open(ACCOUNTS_FILE,'r') as f:
            accounts = json.load(f)
    except:
        accounts = []
    total_accounts = len(accounts)
    now_ts = int(time.time())
    offline_accounts = sum(1 for a in accounts if int(a.get('expires_at',0)) < now_ts)
    server_ip = get_server_ip()
    return render_template_string(DASH_HTML,
                                  server_time=server_time,
                                  cpu=cpu, ram=ram_used, storage=storage,
                                  total_accounts=total_accounts, offline_accounts=offline_accounts,
                                  server_ip=server_ip,
                                  accounts=accounts)

@app.route('/create_account', methods=['POST'])
@login_required
def create_account():
    pw = request.form.get('password') or ''
    if not pw:
        pw = os.urandom(4).hex()
    expires_at = int(time.time()) + 3*24*3600
    entry = {
        'password': pw,
        'created_at': int(time.time()),
        'expires_at': expires_at
    }
    try:
        with open(ACCOUNTS_FILE,'r') as f:
            accounts = json.load(f)
    except:
        accounts = []
    accounts.append(entry)
    with open(ACCOUNTS_FILE,'w') as f:
        json.dump(accounts, f, indent=2)
    # update zivpn config
    try:
        with open(ZIVPN_CONFIG,'r') as f:
            cfg = json.load(f)
    except:
        cfg = {}
    if 'config' not in cfg or not isinstance(cfg['config'], list):
        cfg['config'] = []
    if pw not in cfg['config']:
        cfg['config'].append(pw)
        with open(ZIVPN_CONFIG,'w') as f:
            json.dump(cfg, f, indent=2)
        try:
            subprocess.check_call(['systemctl','restart',ZIVPN_SERVICE])
        except Exception as e:
            print("Failed to restart zivpn service:", e)
    flash('Create Account Successfully ✅','success')
    expires_readable = datetime.datetime.fromtimestamp(expires_at).strftime('%Y-%m-%d %H:%M:%S')
    return render_template_string(CREATE_SUCCESS_HTML, password=pw, expires=expires_readable, server_ip=get_server_ip())

@app.route('/api/accounts')
@login_required
def api_accounts():
    try:
        with open(ACCOUNTS_FILE,'r') as f:
            accounts = json.load(f)
    except:
        accounts = []
    return jsonify(accounts)

@app.route('/contact')
@login_required
def contact():
    return render_template_string(CONTACT_HTML)

# Templates
LOGIN_HTML = """
<!doctype html>
<title>ZIVPN Admin Login</title>
<style>
body{font-family:Inter,Segoe UI,Arial;background:#0f172a;color:#fff;display:flex;align-items:center;justify-content:center;height:100vh}
.card{background:#0b1220;padding:24px;border-radius:8px;width:360px;box-shadow:0 6px 20px rgba(0,0,0,.6)}
input{width:100%;padding:10px;margin-top:8px;border-radius:6px;border:1px solid #213040;background:#071422;color:#fff}
button{width:100%;padding:10px;margin-top:12px;border-radius:6px;border:0;background:#0ea5a1;color:#042022;font-weight:600}
.small{font-size:13px;color:#94a3b8;margin-top:6px}
</style>
<div class="card">
  <h2>Admin Login</h2>
  <form method="post">
    <label>Password</label>
    <input name="password" type="password" required />
    <button type="submit">Login</button>
  </form>
  <p class="small">Use the password you entered when running installer (first password).</p>
</div>
"""

DASH_HTML = """
<!doctype html>
<title>ZIVPN Admin Dashboard</title>
<style>
body{font-family:Inter,Arial;background:#0f172a;color:#fff;margin:0}
.top{display:flex;justify-content:space-between;padding:18px 24px;border-bottom:1px solid #15202b}
.brand{font-weight:700}
.container{display:flex}
.sidebar{width:220px;background:#071422;padding:16px;height:calc(100vh - 56px)}
.content{flex:1;padding:20px}
.card{background:#061221;padding:14px;border-radius:8px;margin-bottom:12px}
.row{display:flex;gap:12px}
.stat{flex:1;padding:12px;background:#071a27;border-radius:8px}
.menu a{display:block;color:#9fb3c3;padding:8px 6px;text-decoration:none;border-radius:6px}
.menu a:hover{background:#06232c}
.copybtn{padding:6px 8px;border-radius:6px;border:0;background:#0ea5a1;color:#00201f;cursor:pointer}
.table{width:100%;border-collapse:collapse;margin-top:8px}
.table th, .table td{padding:8px;border-bottom:1px solid #0b2a36;text-align:left}
.notice{background:#052a2a;padding:10px;border-radius:8px;margin-bottom:12px}
</style>
<div class="top">
  <div class="brand">ZIVPN Admin</div>
  <div><a href="/logout" style="color:#9fb3c3;text-decoration:none">Logout</a></div>
</div>
<div class="container">
  <div class="sidebar">
    <div style="margin-bottom:12px"><strong>Menu</strong></div>
    <div class="menu">
      <a href="/">Dashboard</a>
      <a href="#" onclick="document.getElementById('create').scrollIntoView()">Create Password (3 days)</a>
      <a href="/contact">Contact Admin</a>
      <a href="#" onclick="alert('Donate: Thank you! Add your donation link in /opt/zivpn-admin/app.py')">Donate</a>
    </div>
  </div>
  <div class="content">
    <div class="card">
      <div style="display:flex;justify-content:space-between;align-items:center">
        <div>
          <div style="font-size:13px;color:#9fb3c3">Server Time</div>
          <div style="font-weight:700">{{ server_time }}</div>
        </div>
        <div>
          <div style="font-size:13px;color:#9fb3c3">Server IP</div>
          <div style="font-weight:700">{{ server_ip }}</div>
          <button class="copybtn" onclick="copyText('{{ server_ip }}')">Copy</button>
        </div>
      </div>
    </div>

    <div class="row">
      <div class="stat card"><div>CPU</div><div style="font-size:20px;font-weight:700">{{ cpu }}%</div></div>
      <div class="stat card"><div>RAM</div><div style="font-size:20px;font-weight:700">{{ ram }}</div></div>
      <div class="stat card"><div>Storage</div><div style="font-size:20px;font-weight:700">{{ storage }}</div></div>
    </div>

    <div class="row" style="margin-top:12px">
      <div class="stat card"><div>Total Account</div><div style="font-size:20px;font-weight:700">{{ total_accounts }}</div></div>
      <div class="stat card"><div>Offline Account</div><div style="font-size:20px;font-weight:700">{{ offline_accounts }}</div></div>
    </div>

    <div id="create" class="card" style="margin-top:14px">
      <h3>Create Password (valid 3 days)</h3>
      <form method="post" action="/create_account">
        <div><label>Custom password (optional)</label></div>
        <div><input name="password" style="padding:8px;border-radius:6px;background:#071422;border:1px solid #123; color:#fff;width:320px" /></div>
        <div style="margin-top:8px">
          <button type="submit" class="copybtn">Create Account</button>
        </div>
      </form>
      <div class="small" style="margin-top:6px;color:#93b0bf">When created, the password is added to server config and zivpn service will be restarted automatically.</div>
    </div>

    <div class="card">
      <h3>Accounts</h3>
      <table class="table">
        <thead><tr><th>Password</th><th>Created</th><th>Expires</th></tr></thead>
        <tbody>
        {% for a in accounts %}
          <tr>
            <td>{{ a.password }}</td>
            <td>{{ (a.created_at | int) | datetimeformat }}</td>
            <td>{{ (a.expires_at | int) | datetimeformat }}</td>
          </tr>
        {% endfor %}
        </tbody>
      </table>
    </div>

    <div style="margin-top:20px" class="notice">
      <strong>Message Alert:</strong> Create Account Successfully ✅
    </div>

  </div>
</div>

<script>
function copyText(t){
  navigator.clipboard.writeText(t).then(()=>{ alert('Copied: '+t); })
}
</script>
"""

CREATE_SUCCESS_HTML = """
<!doctype html>
<title>Account Created</title>
<style>
body{font-family:Inter,Arial;background:#0f172a;color:#fff;display:flex;align-items:center;justify-content:center;height:100vh}
.card{background:#071422;padding:20px;border-radius:8px;width:420px}
.copybtn{padding:8px 10px;border-radius:6px;border:0;background:#0ea5a1;color:#042022;margin-top:10px;cursor:pointer}
</style>
<div class="card">
  <h3>Create Account Successfully ✅</h3>
  <div><strong>Server IP :</strong> {{ server_ip }}</div>
  <div style="margin-top:6px"><strong>Password:</strong> <code id="pw">{{ password }}</code> <button class="copybtn" onclick="copy()">Copy</button></div>
  <div style="margin-top:6px"><strong>Expired Date:</strong> {{ expires }}</div>
  <div style="margin-top:12px;color:#9fb3c3">🙏🏿 Donate For More Servers</div>
  <div style="margin-top:10px"><a href="/" style="color:#9fb3c3">Back to Dashboard</a></div>
</div>
<script>
function copy(){
  navigator.clipboard.writeText(document.getElementById('pw').innerText).then(()=>alert('Password copied'));
}
</script>
"""

CONTACT_HTML = """
<!doctype html>
<title>Contact Admin</title>
<style>body{font-family:Inter,Arial;background:#0f172a;color:#fff;padding:20px} .card{background:#071422;padding:16px;border-radius:8px}</style>
<div class="card">
  <h3>Contact Admin</h3>
  <p>Send your message to the server admin.</p>
  <p><strong>Note:</strong> This is a placeholder. Edit /opt/zivpn-admin/app.py to add real contact handling (email/tele).</p>
</div>
"""

from flask import Markup
@app.template_filter('datetimeformat')
def _jinja2_filter_datetimeformat(ts):
    try:
        return datetime.datetime.fromtimestamp(int(ts)).strftime('%Y-%m-%d %H:%M:%S')
    except:
        return '-'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
PY

chmod +x "${ADMIN_DIR}/app.py"
chown -R root:root "${ADMIN_DIR}"

# 9) systemd service for admin panel
cat > /etc/systemd/system/zivpn-admin.service <<'SVC'
[Unit]
Description=Zivpn Admin Panel (Flask)
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/zivpn-admin
ExecStart=/opt/zivpn-admin/venv/bin/python /opt/zivpn-admin/app.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
SVC

systemctl daemon-reload
systemctl enable zivpn-admin.service
systemctl restart zivpn-admin.service || true

# 10) Nginx + HTTPS setup
NGINX_CONF="/etc/nginx/sites-available/zivpn-admin"
echo
read -p "Enter a domain name for HTTPS (example: vpn.example.com). Leave empty to use self-signed cert: " DOMAIN || true
DOMAIN="${DOMAIN:-}"

if [ -n "$DOMAIN" ]; then
  echo "--- Configuring nginx for domain $DOMAIN ---"
  cat > "$NGINX_CONF" <<EOF
server {
    listen 80;
    server_name ${DOMAIN};

    location / {
        proxy_pass http://127.0.0.1:8080/;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
}
EOF
  ln -sf "$NGINX_CONF" /etc/nginx/sites-enabled/zivpn-admin
  rm -f /etc/nginx/sites-enabled/default /etc/nginx/sites-available/default >/dev/null 2>&1 || true
  nginx -t && systemctl restart nginx || true

  echo "--- Attempting Let's Encrypt via certbot for $DOMAIN ---"
  if certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos -m "admin@$DOMAIN" >/dev/null 2>&1; then
    echo "Let's Encrypt certificate obtained and nginx configured."
  else
    echo "certbot failed or DNS not pointing to this server. Falling back to self-signed."
    DOMAIN=""
  fi
fi

if [ -z "$DOMAIN" ]; then
  echo "--- Configuring nginx with self-signed cert ---"
  mkdir -p /etc/ssl/zivpn
  openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -subj "/C=US/ST=California/L=Los Angeles/O=ZIVPN/OU=IT/CN=$(hostname -I | awk '{print $1}')" \
    -keyout /etc/ssl/zivpn/zivpn.key -out /etc/ssl/zivpn/zivpn.crt >/dev/null 2>&1 || true

  cat > "$NGINX_CONF" <<EOF
server {
    listen 80;
    server_name _;
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl;
    server_name _;

    ssl_certificate /etc/ssl/zivpn/zivpn.crt;
    ssl_certificate_key /etc/ssl/zivpn/zivpn.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    location / {
        proxy_pass http://127.0.0.1:8080/;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
}
EOF
  ln -sf "$NGINX_CONF" /etc/nginx/sites-enabled/zivpn-admin
  rm -f /etc/nginx/sites-enabled/default /etc/nginx/sites-available/default >/dev/null 2>&1 || true
  nginx -t && systemctl restart nginx || true
else
  echo "Nginx configured for $DOMAIN with Let's Encrypt (if certbot succeeded)."
fi

ufw allow 80/tcp || true
ufw allow 443/tcp || true

# Final summary output
SERVER_IP=$(hostname -I | awk '{print $1}' || echo "127.0.0.1")
if [ -z "$SERVER_IP" ]; then SERVER_IP="127.0.0.1"; fi

echo
echo "===== INSTALL COMPLETE ====="
if [ -n "$DOMAIN" ]; then
  echo "Access the admin panel at: https://$DOMAIN/"
else
  echo "Access the admin panel at: https://$SERVER_IP/  (self-signed cert - browser warning likely)"
fi

echo
echo "Admin login credential:"
echo "  Admin Username: admin"
echo "  Admin Password: ${ADMIN_PASS}"
echo
echo "Server IP: ${SERVER_IP}"
echo
echo "Files created:"
echo "  /etc/zivpn/config.json"
echo "  /etc/zivpn/admin.pass (admin password file, 600)"
echo "  /etc/zivpn/accounts.json (accounts list)"
echo "  /opt/zivpn-admin/app.py (Flask admin app)"
echo "  systemd services: zivpn.service, zivpn-admin.service"
echo
echo "Installer log: $LOGFILE"
echo "If anything failed, run: sudo journalctl -u zivpn-admin.service -n 200 --no-pager"
echo "Or view installer log: sudo tail -n 200 $LOGFILE"
echo "================================"
exit 0
