#!/bin/bash

# Zivpn UDP Module installer with Web Admin Panel (Enhanced UI + API)
# Original Creator: Zahid Islam
# Enhancements: UI updates, API endpoints for stats and account creation, credentials display

set -euo pipefail
IFS=$'\n\t'

echo -e "\n=== Updating server packages ==="
apt-get update -y && apt-get upgrade -y

echo -e "\n=== Installing required packages ==="
DEBIAN_FRONTEND=noninteractive apt-get install -y python3 python3-pip nodejs npm ufw openssl wget iptables python3-venv

# try to install psutil (optional) for more accurate stats
python3 -m pip install --upgrade pip >/dev/null 2>&1 || true
python3 -m pip install psutil >/dev/null 2>&1 || true

echo -e "\n=== Downloading UDP Service binary ==="
mkdir -p /usr/local/bin /etc/zivpn /var/www/zivpn-admin
if wget -q -O /usr/local/bin/zivpn "https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-amd64"; then
    chmod +x /usr/local/bin/zivpn
else
    echo "Warning: could not download udp-zivpn binary. Continue with install but service may fail."
fi

# create default config if none
if [ ! -f /etc/zivpn/config.json ]; then
  cat > /etc/zivpn/config.json <<'EOF'
{
  "listen": "0.0.0.0:5667",
  "config": ["zi"]
}
EOF
fi

echo -e "\n=== Generating self-signed TLS certs (for local use) ==="
openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 \
  -subj "/C=US/ST=California/L=Los Angeles/O=Example Corp/OU=IT Department/CN=zivpn" \
  -keyout "/etc/zivpn/zivpn.key" -out "/etc/zivpn/zivpn.crt" >/dev/null 2>&1 || true

# Create systemd service for zivpn (if binary exists)
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

# Prompt for UDP passwords
echo -e "\n=== ZIVPN UDP Passwords ==="
read -p "Enter passwords separated by commas (example: pass1,pass2). Press Enter for default 'zi': " input_config
if [ -n "${input_config}" ]; then
    IFS=',' read -r -a config_array <<< "${input_config}"
else
    config_array=("zi")
fi

# Update config.json config array
if command -v jq >/dev/null 2>&1; then
    jq --argjson arr "$(printf '%s\n' "${config_array[@]}" | jq -R . | jq -s .)" '.config = $arr' /etc/zivpn/config.json > /etc/zivpn/config.json.tmp && mv /etc/zivpn/config.json.tmp /etc/zivpn/config.json
else
    arr=""
    for p in "${config_array[@]}"; do
        esc=$(printf '%s' "$p" | sed 's/\\/\\\\/g; s/"/\\"/g')
        arr="${arr}\"${esc}\","
    done
    arr="[${arr%,}]"
    sed -i "s|\"config\": *\[[^]]*\]|\"config\": ${arr}|g" /etc/zivpn/config.json || ( sed -i "1s|{|\n{\"config\": ${arr},|" /etc/zivpn/config.json )
fi

# Prompt for admin username/password
echo -e "\n=== Admin credentials setup ==="
read -p "Enter admin username (leave blank to auto-generate): " ADMIN_USER_INPUT
read -s -p "Enter admin password (leave blank to auto-generate): " ADMIN_PASS_INPUT
echo ""
if [ -n "${ADMIN_USER_INPUT}" ]; then
    ADMIN_USER="${ADMIN_USER_INPUT}"
else
    ADMIN_USER="admin_$(openssl rand -hex 3)"
fi
if [ -n "${ADMIN_PASS_INPUT}" ]; then
    ADMIN_PASS="${ADMIN_PASS_INPUT}"
else
    ADMIN_PASS="pass_$(openssl rand -hex 6)"
fi

# Detect server IP
echo -e "\n=== Detecting server public IP ==="
SERVER_IP=""
for svc in "ifconfig.me" "icanhazip.com" "ipinfo.io/ip" "api.ipify.org"; do
  SERVER_IP=$(curl -s --max-time 5 "$svc" || true)
  if [[ -n "$SERVER_IP" ]]; then
    SERVER_IP=$(echo "$SERVER_IP" | tr -d ' \n\r')
    break
  fi
done
if [[ -z "$SERVER_IP" ]]; then
  SERVER_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || true)
fi
if [[ -z "$SERVER_IP" ]]; then
  read -p "Could not auto-detect server IP. Enter server IP or domain to use in admin panel: " SERVER_IP
fi

# create accounts storage
ACCOUNTS_FILE="/var/www/zivpn-admin/accounts.json"
if [ ! -f "${ACCOUNTS_FILE}" ]; then
  echo "[]" > "${ACCOUNTS_FILE}"
fi

# Create admin-panel HTML (enhanced UI)
cat > /var/www/zivpn-admin/admin-panel.html <<'HTML'
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>ZIVPN Admin Panel</title>
<style>
:root{--bg:#f6f8fb;--card:#fff;--accent:#2563eb;--muted:#64748b;}
body{font-family:Inter,Arial,Helvetica,sans-serif;margin:0;background:var(--bg);color:#0f172a}
.topbar{display:flex;align-items:center;justify-content:space-between;padding:18px 22px;background:linear-gradient(90deg,#ffffff,#f1f5f9);box-shadow:0 1px 0 rgba(0,0,0,0.04)}
.brand{font-size:22px;font-weight:700}
.menu{display:flex;gap:12px}
.menu button{background:transparent;border:0;padding:8px 10px;border-radius:8px;cursor:pointer}
.container{max-width:1100px;margin:24px auto;padding:0 16px}
.card{background:var(--card);border-radius:12px;padding:18px;box-shadow:0 10px 30px rgba(15,23,42,0.03);margin-bottom:16px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px}
.stat{padding:12px;border-radius:8px;background:#fcfdff}
.stat h3{margin:0;font-size:14px;color:var(--muted)}
.stat p{margin:6px 0 0;font-weight:700;font-size:20px}
.login-box{max-width:420px;margin:22px auto;padding:18px;border-radius:10px;background:var(--card);box-shadow:0 8px 24px rgba(2,6,23,0.04)}
.field{display:flex;gap:8px;margin:8px 0}
input[type=text],input[type=password]{flex:1;padding:8px;border:1px solid #e6eef8;border-radius:6px}
.btn{background:var(--accent);color:#fff;border:0;padding:8px 12px;border-radius:8px;cursor:pointer}
.small{font-size:13px;color:var(--muted)}
.success{background:#ecfdf5;border:1px solid #bbf7d0;padding:12px;border-radius:8px}
.table{width:100%;border-collapse:collapse;margin-top:8px}
.table th,.table td{padding:8px;border-bottom:1px solid #f1f5f9;text-align:left}
.actions{display:flex;gap:8px}
.copy-btn{background:#10b981;color:#fff;border:0;padding:6px 8px;border-radius:6px;cursor:pointer}
</style>
</head>
<body>
  <div class="topbar">
    <div class="brand">ZIVPN Admin Panel</div>
    <div class="menu">
      <button onclick="showDonate()">Donate</button>
      <button onclick="showContact()">Contact Admin</button>
    </div>
  </div>

  <div class="container">
    <!-- Login -->
    <div id="loginBox" class="login-box card">
      <h2>ZIVPN Admin Login</h2>
      <div class="small">Server: <strong id="serverIp"></strong></div>
      <div style="height:8px"></div>
      <div class="field"><input id="username" type="text" placeholder="Username"></div>
      <div class="field"><input id="password" type="password" placeholder="Password"></div>
      <div class="field"><button class="btn" onclick="login()">Login</button></div>
      <div id="loginError" class="small" style="color:#ef4444;display:none">Invalid username or password</div>

      <div style="height:12px"></div>
      <!-- Display generated admin credentials (below login) -->
      <div class="card small">
        <strong>Admin Credentials (for this server)</strong>
        <div style="height:8px"></div>
        <div>Username: <code id="credUser"></code> <button class="copy-btn" onclick="copy($('#credUser').text())">Copy</button></div>
        <div style="height:6px"></div>
        <div>Password: <code id="credPass"></code> <button class="copy-btn" onclick="copy($('#credPass').text())">Copy</button></div>
      </div>
    </div>

    <!-- Admin Panel -->
    <div id="adminPanel" style="display:none">
      <div class="card">
        <div style="display:flex;align-items:center;justify-content:space-between">
          <div>
            <h2 style="margin:0">Dashboard</h2>
            <div class="small">Manage accounts and server</div>
          </div>
          <div>
            <button class="btn" onclick="logout()">Logout</button>
          </div>
        </div>

        <div style="height:12px"></div>
        <div class="grid">
          <div class="stat"><h3>Server Time</h3><p id="serverTime">--</p></div>
          <div class="stat"><h3>CPU Usage</h3><p id="cpuUsage">--</p></div>
          <div class="stat"><h3>RAM Usage</h3><p id="ramUsage">--</p></div>
          <div class="stat"><h3>Storage</h3><p id="storageUsage">--</p></div>
          <div class="stat"><h3>Total Accounts</h3><p id="totalAccounts">0</p></div>
          <div class="stat"><h3>Offline Accounts</h3><p id="offlineAccounts">0</p></div>
        </div>
      </div>

      <div class="card">
        <h3>Create Account (auto expires in 3 days)</h3>
        <div class="field"><input id="newPass" type="text" placeholder="Password (leave empty to auto-generate)"></div>
        <div class="field">
          <button class="btn" onclick="createAccount()">Create Account</button>
        </div>
        <div id="createResult"></div>
      </div>

      <div id="donateCard" class="card" style="display:none">
        <h3>Donate</h3>
        <div class="small">Support us to keep more servers online</div>
        <div style="height:8px"></div>
        <div class="success">
          <div>📱 Bitcoin: <code>bc1qexample...</code></div>
          <div>💳 PayPal: <code>donate@zivpn.com</code></div>
        </div>
      </div>

      <div id="contactCard" class="card" style="display:none">
        <h3>Contact Admin</h3>
        <div class="small">For support and inquiries</div>
        <div style="height:8px"></div>
        <div class="success">
          <div>📧 Email: admin@zivpn.com</div>
          <div>📱 Telegram: @zivpn_admin</div>
        </div>
      </div>

      <div id="accountsList" class="card">
        <h3>Accounts</h3>
        <table class="table" id="accountsTable">
          <thead><tr><th>Password</th><th>Expires</th><th>Actions</th></tr></thead>
          <tbody></tbody>
        </table>
      </div>
    </div>
  </div>

<script>
// small helper for legacy copy
function copy(text){ navigator.clipboard.writeText(text).then(()=>alert('Copied')) }

// placeholders replaced by server script
const ADMIN_USERNAME = "ADMIN_USERNAME_PLACEHOLDER";
const ADMIN_PASSWORD = "ADMIN_PASSWORD_PLACEHOLDER";
const SERVER_IP = "SERVER_IP_PLACEHOLDER";

// populate credentials display
document.getElementById('serverIp').textContent = SERVER_IP;
document.getElementById('credUser').textContent = ADMIN_USERNAME;
document.getElementById('credPass').textContent = ADMIN_PASSWORD;

// login function
function login(){
  const u=document.getElementById('username').value;
  const p=document.getElementById('password').value;
  if(u===ADMIN_USERNAME && p===ADMIN_PASSWORD){
    document.getElementById('loginBox').style.display='none';
    document.getElementById('adminPanel').style.display='block';
    fetchStats();
    fetchAccounts();
  } else {
    document.getElementById('loginError').style.display='block';
  }
}

function logout(){
  document.getElementById('loginBox').style.display='block';
  document.getElementById('adminPanel').style.display='none';
  document.getElementById('username').value='';
  document.getElementById('password').value='';
}

// show donate/contact
function showDonate(){ document.getElementById('donateCard').style.display='block'; document.getElementById('contactCard').style.display='none' }
function showContact(){ document.getElementById('donateCard').style.display='none'; document.getElementById('contactCard').style.display='block' }

// fetch stats from server
function fetchStats(){
  fetch('/api/stats').then(r=>r.json()).then(j=>{
    document.getElementById('serverTime').textContent=j.server_time;
    document.getElementById('cpuUsage').textContent=j.cpu;
    document.getElementById('ramUsage').textContent=j.ram;
    document.getElementById('storageUsage').textContent=j.storage;
    document.getElementById('totalAccounts').textContent=j.total_accounts;
    document.getElementById('offlineAccounts').textContent=j.offline_accounts;
  }).catch(e=>console.warn(e));
}

// accounts
function fetchAccounts(){
  fetch('/api/accounts').then(r=>r.json()).then(arr=>{
    const tbody=document.querySelector('#accountsTable tbody'); tbody.innerHTML='';
    arr.forEach((a,i)=>{
      const tr=document.createElement('tr');
      const tdPass=document.createElement('td'); tdPass.textContent=a.password;
      const tdExp=document.createElement('td'); tdExp.textContent=new Date(a.expires).toLocaleString();
      const tdAct=document.createElement('td');
      const del=document.createElement('button'); del.textContent='Delete'; del.onclick=()=>deleteAccount(i);
      tdAct.appendChild(del);
      tr.appendChild(tdPass); tr.appendChild(tdExp); tr.appendChild(tdAct);
      tbody.appendChild(tr);
    });
  }).catch(e=>console.warn(e));
}

function createAccount(){
  const pass=document.getElementById('newPass').value;
  fetch('/api/create_account', {
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({password: pass})
  }).then(r=>r.json()).then(j=>{
    document.getElementById('createResult').innerHTML='<div class="success"><strong>Created</strong><div>Server: '+SERVER_IP+'</div><div>Password: '+j.password+'</div><div>Expires: '+new Date(j.expires).toLocaleString()+'</div></div>';
    document.getElementById('newPass').value='';
    fetchStats();
    fetchAccounts();
  }).catch(e=>{console.error(e); alert('Failed to create account')});
}

function deleteAccount(index){
  fetch('/api/delete_account', {
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({index})
  }).then(r=>r.json()).then(j=>{
    fetchStats(); fetchAccounts();
  }).catch(e=>alert('Failed'));
}

// refresh stats periodically
setInterval(fetchStats, 5000);

</script>
</body>
</html>
HTML

# Replace placeholders safely
sed -i "s|ADMIN_USERNAME_PLACEHOLDER|${ADMIN_USER}|g" /var/www/zivpn-admin/admin-panel.html
# escape password for sed
ESC_PASS=$(printf '%s' "${ADMIN_PASS}" | sed 's|[&/\]|\\&|g')
sed -i "s|ADMIN_PASSWORD_PLACEHOLDER|${ESC_PASS}|g" /var/www/zivpn-admin/admin-panel.html
sed -i "s|SERVER_IP_PLACEHOLDER|${SERVER_IP}|g" /var/www/zivpn-admin/admin-panel.html

# Create Python server with API endpoints (/api/stats, /api/create_account, /api/accounts, /api/delete_account)
cat > /var/www/zivpn-admin/server.py <<'PY'
#!/usr/bin/env python3
import http.server, socketserver, json, os, shutil, subprocess, datetime, urllib
from http import HTTPStatus

ROOT = '/var/www/zivpn-admin'
ACCOUNTS_FILE = os.path.join(ROOT, 'accounts.json')

def load_accounts():
    try:
        with open(ACCOUNTS_FILE,'r') as f:
            return json.load(f)
    except:
        return []

def save_accounts(arr):
    with open(ACCOUNTS_FILE,'w') as f:
        json.dump(arr,f)

def get_stats():
    now = datetime.datetime.utcnow().isoformat() + 'Z'
    # CPU (try psutil)
    try:
        import psutil
        cpu = f"{psutil.cpu_percent(interval=0.5)} %"
        mem = psutil.virtual_memory()
        ram = f"{mem.percent} % ({round(mem.used/1024/1024)}MB/{round(mem.total/1024/1024)}MB)"
        disk = shutil.disk_usage('/')
        storage = f"{round((disk.used/disk.total)*100,1)} % ({round(disk.used/1024/1024/1024,1)}GB used)"
    except Exception:
        # fallback to /proc and shell
        try:
            load = os.getloadavg()
            cpu = f"load:{load[0]:.2f}"
        except:
            cpu = "N/A"
        try:
            out = subprocess.check_output(['free','-m']).decode()
            lines = out.splitlines()
            if len(lines)>1:
                parts = lines[1].split()
                ram = f\"{round( (1 - int(parts[6])/int(parts[1]) )*100 ,1)}% ({parts[2]}MB/{parts[1]}MB)\" if len(parts)>6 else "N/A"
            else:
                ram = "N/A"
        except:
            ram = "N/A"
        try:
            disk = shutil.disk_usage('/')
            storage = f\"{round((disk.used/disk.total)*100,1)}% ({round(disk.used/1024/1024/1024,1)}GB used)\"
        except:
            storage = "N/A"

    # accounts
    accounts = load_accounts()
    total = len(accounts)
    # offline = expired count
    now_dt = datetime.datetime.utcnow()
    offline = sum(1 for a in accounts if datetime.datetime.fromisoformat(a['expires']) < now_dt)
    return {
        'server_time': datetime.datetime.utcnow().isoformat() + 'Z',
        'cpu': cpu,
        'ram': ram,
        'storage': storage,
        'total_accounts': total,
        'offline_accounts': offline
    }

class Handler(http.server.SimpleHTTPRequestHandler):
    def _cors(self):
        self.send_header("Access-Control-Allow-Origin","*")
        self.send_header("Access-Control-Allow-Methods","GET,POST,OPTIONS")
        self.send_header("Access-Control-Allow-Headers","Content-Type")

    def do_OPTIONS(self):
        self.send_response(HTTPStatus.NO_CONTENT)
        self._cors()
        self.end_headers()

    def do_GET(self):
        if self.path.startswith('/api/stats'):
            data = get_stats()
            self.send_response(200)
            self._cors()
            self.send_header('Content-Type','application/json')
            self.end_headers()
            self.wfile.write(json.dumps(data).encode())
            return
        if self.path.startswith('/api/accounts'):
            arr = load_accounts()
            self.send_response(200)
            self._cors()
            self.send_header('Content-Type','application/json')
            self.end_headers()
            self.wfile.write(json.dumps(arr).encode())
            return
        # serve static files (admin-panel.html etc)
        if self.path == '/':
            self.path = '/admin-panel.html'
        return super().do_GET()

    def do_POST(self):
        length = int(self.headers.get('Content-Length',0))
        raw = self.rfile.read(length) if length else b''
        try:
            payload = json.loads(raw.decode()) if raw else {}
        except:
            payload = {}
        if self.path == '/api/create_account':
            password = payload.get('password','')
            if not password:
                # generate 8 char password
                import random, string
                password = ''.join(random.choice(string.ascii_lowercase+string.digits) for _ in range(8))
            expires = (datetime.datetime.utcnow() + datetime.timedelta(days=3)).isoformat()
            accounts = load_accounts()
            accounts.append({'password':password, 'expires':expires, 'created':datetime.datetime.utcnow().isoformat()})
            save_accounts(accounts)
            resp = {'password':password,'expires':expires}
            self.send_response(200)
            self._cors()
            self.send_header('Content-Type','application/json')
            self.end_headers()
            self.wfile.write(json.dumps(resp).encode())
            return
        if self.path == '/api/delete_account':
            idx = payload.get('index',None)
            accounts = load_accounts()
            if idx is not None and 0 <= idx < len(accounts):
                accounts.pop(idx)
                save_accounts(accounts)
            self.send_response(200)
            self._cors()
            self.send_header('Content-Type','application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'ok':True}).encode())
            return

        # unknown POST
        self.send_response(404)
        self._cors()
        self.end_headers()

if __name__ == '__main__':
    os.chdir(ROOT)
    PORT = 8989
    with socketserver.TCPServer(("", PORT), Handler) as httpd:
        print(f"Serving admin panel on port {PORT}")
        httpd.serve_forever()
PY

chmod +x /var/www/zivpn-admin/server.py
chown -R root:root /var/www/zivpn-admin
# create systemd service
cat > /etc/systemd/system/zivpn-admin.service <<'UNIT'
[Unit]
Description=ZIVPN Web Admin Panel (Enhanced)
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/var/www/zivpn-admin
ExecStart=/usr/bin/python3 /var/www/zivpn-admin/server.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
UNIT

echo -e "\n=== Firewall / UFW rules ==="
ufw allow 6000:19999/udp || true
ufw allow 5667/udp || true
ufw allow 8989/tcp || true
ufw --force enable || true

# iptables DNAT best-effort
INT_IF="$(ip -4 route ls | grep default | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1); exit}')"
if [ -n "$INT_IF" ]; then
  iptables -t nat -D PREROUTING -i "$INT_IF" -p udp --dport 6000:19999 -j DNAT --to-destination 127.0.0.1:5667 2>/dev/null || true
  iptables -t nat -A PREROUTING -i "$INT_IF" -p udp --dport 6000:19999 -j DNAT --to-destination 127.0.0.1:5667
fi

echo -e "\n=== Enable and start services ==="
systemctl daemon-reload
systemctl enable zivpn.service || true
systemctl start zivpn.service || true
systemctl enable zivpn-admin.service
systemctl start zivpn-admin.service || true

# store credentials
cat > /root/zivpn_credentials.txt <<CRED
================================================
           ZIVPN UDP Credentials
================================================
Web Admin Panel: http://${SERVER_IP}:8989
Admin Username: ${ADMIN_USER}
Admin Password: ${ADMIN_PASS}
UDP Port: 5667
Port Range: 6000-19999
Installation Date: $(date)
================================================
CRED

# finalize: replace placeholders in HTML already done above but ensure
sed -i "s|ADMIN_USERNAME_PLACEHOLDER|${ADMIN_USER}|g" /var/www/zivpn-admin/admin-panel.html || true
sed -i "s|ADMIN_PASSWORD_PLACEHOLDER|${ESC_PASS}|g" /var/www/zivpn-admin/admin-panel.html || true
sed -i "s|SERVER_IP_PLACEHOLDER|${SERVER_IP}|g" /var/www/zivpn-admin/admin-panel.html || true

clear
echo "================================================"
echo "           ZIVPN UDP Installation Complete      "
echo "================================================"
echo ""
echo "📊 Web Admin Panel: http://${SERVER_IP}:8989"
echo "👤 Admin Username: ${ADMIN_USER}"
echo "🔐 Admin Password: ${ADMIN_PASS}"
echo ""
echo "🔧 UDP Service Port: 5667"
echo "📡 UDP Port Range: 6000-19999"
echo ""
echo "Saved credentials to /root/zivpn_credentials.txt"
echo ""
echo "Notes:"
echo " - Admin credentials are shown under the login box on the page."
echo " - Dashboard shows Server Time, CPU, RAM, Storage, Total Accounts and Offline Accounts."
echo " - Use the Create Account box to add a password (auto-expires in 3 days)."
echo " - If you cannot access the admin page, check provider firewall and run:"
echo "     sudo systemctl status zivpn-admin.service"
echo "     sudo journalctl -u zivpn-admin.service -n 200 --no-pager"
echo "     ss -ltnp | grep 8989"
echo ""
echo "Installation finished."
