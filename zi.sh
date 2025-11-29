#!/bin/bash
# installer: ZIVPN UDP + Web Admin Panel + HTTPS (nginx & Let's Encrypt or self-signed)
# modified to add HTTPS and final summary (prints Server IP, Admin Username, Admin Password)
# Run as root or with sudo: sudo bash install-zivpn-admin.sh

set -euo pipefail

echo -e "\n=== ZIVPN UDP + Web Admin Panel Installer (with HTTPS) ===\n"

apt-get update && apt-get upgrade -y

# --- stop existing service if any ---
systemctl stop zivpn.service 1>/dev/null 2>/dev/null || true

# --- download zivpn binary ---
echo "Downloading zivpn binary..."
wget -q https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-amd64 -O /usr/local/bin/zivpn || { echo "Failed to download zivpn binary"; exit 1; }
chmod +x /usr/local/bin/zivpn

# --- prepare config ---
mkdir -p /etc/zivpn
wget -q https://raw.githubusercontent.com/zahidbd2/udp-zivpn/main/config.json -O /etc/zivpn/config.json || { echo "Failed to download config.json"; exit 1; }

# --- certs for zivpn (not web) ---
openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 \
  -subj "/C=US/ST=California/L=Los Angeles/O=Example Corp/OU=IT Department/CN=zivpn" \
  -keyout "/etc/zivpn/zivpn.key" -out "/etc/zivpn/zivpn.crt" >/dev/null 2>&1 || true

sysctl -w net.core.rmem_max=16777216 >/dev/null 2>&1 || true
sysctl -w net.core.wmem_max=16777216 >/dev/null 2>&1 || true

# --- systemd service for zivpn ---
cat > /etc/systemd/system/zivpn.service <<'EOF'
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
EOF

# --- passwords from user (preserve original) ---
echo -e "\nZIVPN UDP Passwords"
read -p "Enter passwords separated by commas, example: pass1,pass2 (Press enter for Default 'zi'): " input_config || true

if [ -n "${input_config:-}" ]; then
    IFS=',' read -r -a config <<< "$input_config"
    if [ ${#config[@]} -eq 1 ]; then
        config+=("${config[0]}")
    fi
else
    config=("zi")
fi

ADMIN_PASS="${config[0]}"
echo "${ADMIN_PASS}" > /etc/zivpn/admin.pass
chmod 600 /etc/zivpn/admin.pass

new_config_str="\"config\": [$(printf "\"%s\"," "${config[@]}" | sed 's/,$//')]"
# safer replacement using perl (multiline)
perl -0777 -pe "s/\"config\"\s*:\s*\[.*?\]/${new_config_str}/s" -i /etc/zivpn/config.json

systemctl daemon-reload
systemctl enable zivpn.service
systemctl restart zivpn.service

# --- firewall / iptables ---
IFACE=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1 || echo "eth0")
iptables -t nat -A PREROUTING -i "$IFACE" -p udp --dport 6000:19999 -j DNAT --to-destination :5667 || true
ufw allow 6000:19999/udp || true
ufw allow 5667/udp || true

rm -f zi.* 1>/dev/null 2>/dev/null || true

echo -e "\n=== Core ZIVPN installed ==="

################################################################################
# Admin panel (Flask) - same as before
################################################################################

apt-get install -y python3 python3-venv python3-pip build-essential >/dev/null 2>&1 || { echo "Failed installing python packages"; exit 1; }

ADMIN_DIR="/opt/zivpn-admin"
mkdir -p "$ADMIN_DIR"
chown root:root "$ADMIN_DIR"

python3 -m venv "$ADMIN_DIR/venv"
"$ADMIN_DIR/venv/bin/pip" install --upgrade pip >/dev/null 2>&1
"$ADMIN_DIR/venv/bin/pip" install flask psutil >/dev/null 2>&1

if [ ! -f /etc/zivpn/accounts.json ]; then
  echo "[]" > /etc/zivpn/accounts.json
  chmod 600 /etc/zivpn/accounts.json
fi

if [ ! -f /etc/zivpn/web_secret.key ]; then
  head -c 32 /dev/urandom > /etc/zivpn/web_secret.key
  chmod 600 /etc/zivpn/web_secret.key
fi

cat > /etc/zivpn/admin.meta <<EOF
# admin metadata (do not edit)
ADMIN_PASSWORD_FILE=/etc/zivpn/admin.pass
ADMIN_PASSWORD=$(cat /etc/zivpn/admin.pass)
EOF
chmod 600 /etc/zivpn/admin.meta

# Flask app (same content as previous installer)
cat > "${ADMIN_DIR}/app.py" <<'PY'
#!/usr/bin/env python3
# simple Flask admin for ZIVPN (same as provided earlier)
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
    from functools import wraps
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
    return '127.0.0.1'

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

# Templates (shortened for brevity) - use same as previous installer
LOGIN_HTML = """<!doctype html>
<title>ZIVPN Admin Login</title>
<style>body{font-family:Inter,Segoe UI,Arial;background:#0f172a;color:#fff;display:flex;align-items:center;justify-content:center;height:100vh}.card{background:#0b1220;padding:24px;border-radius:8px;width:360px}input{width:100%;padding:10px;margin-top:8px;border-radius:6px;border:1px solid #213040;background:#071422;color:#fff}button{width:100%;padding:10px;margin-top:12px;border-radius:6px;border:0;background:#0ea5a1;color:#042022;font-weight:600}.small{font-size:13px;color:#94a3b8;margin-top:6px}</style>
<div class="card"><h2>Admin Login</h2><form method="post"><label>Password</label><input name="password" type="password" required /><button type="submit">Login</button></form><p class="small">Use the password you entered when running installer (first password).</p></div>
"""
# Using the full DASH_HTML and CREATE_SUCCESS_HTML / CONTACT_HTML from previous script:
DASH_HTML = """..."""  # (omitted here in source for brevity but in installer we use full templates)
CREATE_SUCCESS_HTML = """..."""
CONTACT_HTML = """..."""

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

# Ensure templates are present — in this installer we placed '...'; rewrite them fully to be safe:
# To keep this installer concise, overwrite the placeholders with the full template strings used previously:
# (We'll inject the full template content exactly as in prior script)
# Here we append the real templates to the app.py file to replace placeholders
python3 - <<'PY' >/dev/null 2>&1
from pathlib import Path
p = Path("/opt/zivpn-admin/app.py")
s = p.read_text()
s = s.replace("DASH_HTML = \"...\"","DASH_HTML = " + repr('''<!doctype html>
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
.rightlinks{position:fixed;right:12px;top:80px;width:180px}
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
</script>''')
s = s.replace("CREATE_SUCCESS_HTML = \"...\"","CREATE_SUCCESS_HTML = " + repr('''<!doctype html>
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
</script>''')
s = s.replace("CONTACT_HTML = \"...\"","CONTACT_HTML = " + repr('''<!doctype html>
<title>Contact Admin</title>
<style>body{font-family:Inter,Arial;background:#0f172a;color:#fff;padding:20px} .card{background:#071422;padding:16px;border-radius:8px}</style>
<div class="card">
  <h3>Contact Admin</h3>
  <p>Send your message to the server admin.</p>
  <p><strong>Note:</strong> This is a placeholder. Edit /opt/zivpn-admin/app.py to add real contact handling (email/tele).</p>
</div>''')
p.write_text(s)
print("templates injected")
PY

chmod +x "${ADMIN_DIR}/app.py"
chown -R root:root "${ADMIN_DIR}"

cat > /etc/systemd/system/zivpn-admin.service <<'SRV'
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
SRV

systemctl daemon-reload
systemctl enable zivpn-admin.service
systemctl restart zivpn-admin.service

echo -e "\n=== Installing nginx & certbot (for HTTPS) ==="
apt-get install -y nginx certbot python3-certbot-nginx >/dev/null 2>&1 || { echo "Failed to install nginx/certbot; continuing with self-signed option"; }

# prompt for domain (no clarification from user allowed per instruction) — best-effort automatic behavior:
read -p "Enter a domain name for HTTPS (example: vpn.example.com). Leave empty to use self-signed cert: " DOMAIN || true
DOMAIN=${DOMAIN:-}

NGINX_CONF="/etc/nginx/sites-available/zivpn-admin"
if [ -n "$DOMAIN" ]; then
  echo "Setting up nginx for domain: $DOMAIN"
  cat > "${NGINX_CONF}" <<EOF
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
  ln -sf "${NGINX_CONF}" /etc/nginx/sites-enabled/zivpn-admin
  # remove default if exists
  rm -f /etc/nginx/sites-enabled/default /etc/nginx/sites-available/default >/dev/null 2>&1 || true
  nginx -t && systemctl restart nginx

  # attempt to obtain Let's Encrypt certificate
  echo "Attempting to obtain Let's Encrypt certificate with certbot for ${DOMAIN}..."
  if certbot --nginx -d "${DOMAIN}" --non-interactive --agree-tos -m "admin@${DOMAIN}" >/dev/null 2>&1; then
    echo "Let's Encrypt certificate obtained and nginx configured."
  else
    echo "certbot failed (maybe DNS not pointed). Falling back to self-signed certificate."
    DOMAIN=""
  fi
fi

if [ -z "$DOMAIN" ]; then
  # create self-signed cert for nginx
  echo "Configuring nginx with self-signed certificate (HTTPS) on server IP"
  mkdir -p /etc/ssl/zivpn
  openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -subj "/C=US/ST=California/L=Los Angeles/O=ZIVPN/OU=IT/CN=$(hostname -I | awk '{print $1}')" \
    -keyout /etc/ssl/zivpn/zivpn.key -out /etc/ssl/zivpn/zivpn.crt >/dev/null 2>&1 || true

  cat > "${NGINX_CONF}" <<EOF
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
  ln -sf "${NGINX_CONF}" /etc/nginx/sites-enabled/zivpn-admin
  rm -f /etc/nginx/sites-enabled/default /etc/nginx/sites-available/default >/dev/null 2>&1 || true
  nginx -t && systemctl restart nginx
else
  # if we have a valid domain and certbot succeeded, ensure nginx handles HTTPS (certbot already did)
  echo "Nginx configured for ${DOMAIN} with Let's Encrypt cert."
fi

# open firewall for 80 and 443
ufw allow 80/tcp || true
ufw allow 443/tcp || true

# final summary info
SERVER_IP=$(hostname -I | awk '{print $1}' || echo "127.0.0.1")
if [ -z "$SERVER_IP" ]; then SERVER_IP="127.0.0.1"; fi

echo -e "\n=== INSTALL COMPLETE ==="
if [ -n "$DOMAIN" ]; then
  echo -e "Access the admin panel at: https://${DOMAIN}/ (HTTPS via Let's Encrypt)"
else
  echo -e "Access the admin panel at: https://${SERVER_IP}/  (self-signed certificate)"
fi

echo -e "\nAdmin login credential:"
echo -e "  Admin Username: admin"
echo -e "  Admin Password: ${ADMIN_PASS}"

echo -e "\nServer IP: ${SERVER_IP}"
echo -e "\nCreate Password behavior: new accounts created from admin panel are valid for 3 days and will be appended to /etc/zivpn/accounts.json and /etc/zivpn/config.json (zivpn service restarted automatically)."
echo -e "\nFiles created:"
echo -e "  /etc/zivpn/config.json"
echo -e "  /etc/zivpn/admin.pass (admin password file, 600)"
echo -e "  /etc/zivpn/accounts.json (accounts list)"
echo -e "  /opt/zivpn-admin/app.py (Flask admin app)"
echo -e "  systemd services: zivpn.service, zivpn-admin.service"
echo -e "\nIf you want a valid Let's Encrypt cert, run this installer again and provide a domain name that points to this server's IP (DNS A record)."

exit 0
