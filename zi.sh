#!/bin/bash

# Zivpn UDP Module installer with Web Admin Panel (HTTPS + Message Alert)
# Modified to show admin credentials under login and display Create Account success alert (with donate message)
# - Serves admin panel over HTTPS (self-signed)
# - API endpoints: /api/stats, /api/accounts, /api/create_account, /api/delete_account
# - Stores accounts in /var/www/zivpn-admin/accounts.json
# - Ports: HTTPS 8989 (opened by UFW), UDP 5667 and 6000-19999 mapped for zivpn

set -euo pipefail
IFS=$'\n\t'

echo -e "\n=== Update & install deps ==="
apt-get update -y && apt-get upgrade -y
DEBIAN_FRONTEND=noninteractive apt-get install -y python3 python3-pip openssl wget iptables ufw python3-venv

# pip extras
python3 -m pip install --upgrade pip >/dev/null 2>&1 || true
python3 -m pip install psutil >/dev/null 2>&1 || true

echo -e "\n=== Prepare directories ==="
mkdir -p /etc/zivpn /var/www/zivpn-admin /usr/local/bin

echo -e "\n=== Download udp-zivpn binary (best-effort) ==="
if wget -q -O /usr/local/bin/zivpn "https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-amd64"; then
  chmod +x /usr/local/bin/zivpn || true
else
  echo "Warning: could not download udp-zivpn binary (continue installer anyway)"
fi

# default config
if [ ! -f /etc/zivpn/config.json ]; then
  cat > /etc/zivpn/config.json <<'CFG'
{
  "listen": "0.0.0.0:5667",
  "config": ["zi"]
}
CFG
fi

echo -e "\n=== Create self-signed cert (used for HTTPS admin panel) ==="
openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 \
  -subj "/C=US/ST=CA/L=LosAngeles/O=ZIVPN/OU=IT/CN=zivpn" \
  -keyout /etc/zivpn/zivpn.key -out /etc/zivpn/zivpn.crt >/dev/null 2>&1 || true
chmod 600 /etc/zivpn/zivpn.key || true

echo -e "\n=== Create systemd service for zivpn (if binary available) ==="
cat > /etc/systemd/system/zivpn.service <<'UNIT'
[Unit]
Description=zivpn UDP Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/etc/zivpn
ExecStart=/usr/local/bin/zivpn server -c /etc/zivpn/config.json
Restart=always
RestartSec=3
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW

[Install]
WantedBy=multi-user.target
UNIT

# Prompt for UDP passwords (comma separated)
echo -e "\n=== ZIVPN UDP Passwords ==="
read -p "Enter passwords separated by commas (example: pass1,pass2). Press Enter for default 'zi': " input_config || true
if [ -n "${input_config}" ]; then
  IFS=',' read -r -a config_array <<< "${input_config}"
else
  config_array=("zi")
fi

# Update config.json "config" array safely (jq if available)
if command -v jq >/dev/null 2>&1; then
  jq --argjson arr "$(printf '%s\n' "${config_array[@]}" | jq -R . | jq -s .)" '.config = $arr' /etc/zivpn/config.json > /etc/zivpn/config.tmp && mv /etc/zivpn/config.tmp /etc/zivpn/config.json
else
  arr=""
  for p in "${config_array[@]}"; do
    esc=$(printf '%s' "$p" | sed 's/\\/\\\\/g; s/"/\\"/g')
    arr="${arr}\"${esc}\","
  done
  arr="[${arr%,}]"
  sed -i "s|\"config\": *\[[^]]*\]|\"config\": ${arr}|g" /etc/zivpn/config.json || true
fi

# Admin credentials prompt
echo -e "\n=== Admin credentials ==="
read -p "Enter admin username (leave blank to auto-generate): " ADMIN_USER_INPUT || true
read -s -p "Enter admin password (leave blank to auto-generate): " ADMIN_PASS_INPUT || true
echo ""
if [ -n "${ADMIN_USER_INPUT}" ]; then ADMIN_USER="${ADMIN_USER_INPUT}"; else ADMIN_USER="admin_$(openssl rand -hex 3)"; fi
if [ -n "${ADMIN_PASS_INPUT}" ]; then ADMIN_PASS="${ADMIN_PASS_INPUT}"; else ADMIN_PASS="pass_$(openssl rand -hex 6)"; fi
ESC_PASS=$(printf '%s' "${ADMIN_PASS}" | sed 's|[&/\]|\\&|g')

# Detect server IP
echo -e "\n=== Detect server IP ==="
SERVER_IP=""
for svc in "ifconfig.me" "icanhazip.com" "ipinfo.io/ip" "api.ipify.org"; do
  SERVER_IP=$(curl -s --max-time 5 "$svc" || true)
  if [ -n "$SERVER_IP" ]; then SERVER_IP=$(echo "$SERVER_IP" | tr -d ' \n\r'); break; fi
done
if [ -z "$SERVER_IP" ]; then
  SERVER_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || true)
fi
if [ -z "$SERVER_IP" ]; then
  read -p "Could not auto-detect server IP. Enter server IP or domain: " SERVER_IP || true
fi

# ensure accounts file exists
ACCOUNTS_FILE="/var/www/zivpn-admin/accounts.json"
if [ ! -f "${ACCOUNTS_FILE}" ]; then echo "[]" > "${ACCOUNTS_FILE}"; fi

# write admin-panel HTML (enhanced with Message Alert and credential display)
cat > /var/www/zivpn-admin/admin-panel.html <<'HTML'
<!doctype html>
<html>
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>ZIVPN Admin Panel</title>
<style>
body{font-family:Arial,Helvetica,sans-serif;background:#f4f7fb;margin:0;color:#0f172a}
.top{padding:16px;background:white;display:flex;justify-content:space-between;align-items:center;box-shadow:0 1px 0 rgba(0,0,0,0.06)}
.brand{font-weight:700;font-size:20px}
.container{max-width:980px;margin:20px auto;padding:0 16px}
.card{background:white;padding:16px;border-radius:10px;box-shadow:0 8px 24px rgba(2,6,23,0.04);margin-bottom:16px}
.field{display:flex;gap:8px;margin-top:8px}
input{flex:1;padding:8px;border:1px solid #e6eef8;border-radius:8px}
.btn{background:#2563eb;color:white;border:0;padding:8px 12px;border-radius:8px;cursor:pointer}
.small{font-size:13px;color:#64748b}
.alert{padding:12px;border-radius:8px;margin-top:12px;display:none}
.success{background:#ecfdf5;border:1px solid #bbf7d0;color:#064e3b}
.copy{background:#10b981;color:white;border:0;padding:6px 8px;border-radius:6px;cursor:pointer}
.table{width:100%;border-collapse:collapse;margin-top:12px}
.table th,.table td{padding:8px;border-bottom:1px solid #f1f5f9;text-align:left}
</style>
</head>
<body>
<div class="top"><div class="brand">ZIVPN Admin Panel</div><div><button onclick="showDonate()">Donate</button> <button onclick="showContact()">Contact</button></div></div>
<div class="container">
  <div id="loginBox" class="card">
    <h2>ZIVPN Admin Login</h2>
    <div class="small">Server: <strong id="serverIp"></strong></div>
    <div class="field"><input id="username" placeholder="Username"></div>
    <div class="field"><input id="password" type="password" placeholder="Password"></div>
    <div class="field"><button class="btn" onclick="login()">Login</button></div>
    <div id="loginError" style="color:#ef4444;display:none">Invalid username or password</div>

    <div style="margin-top:12px" class="small">
      <strong>Admin Credentials (for this server)</strong>
      <div>Username: <code id="credUser"></code> <button class="copy" onclick="copyText('credUser')">Copy</button></div>
      <div>Password: <code id="credPass"></code> <button class="copy" onclick="copyText('credPass')">Copy</button></div>
    </div>
  </div>

  <div id="adminPanel" style="display:none">
    <div class="card">
      <div style="display:flex;justify-content:space-between;align-items:center">
        <div><h2>Dashboard</h2><div class="small">Manage accounts & server</div></div>
        <div><button class="btn" onclick="logout()">Logout</button></div>
      </div>

      <div style="margin-top:12px" class="grid">
        <div class="card"><h4>Server Time</h4><p id="serverTime">--</p></div>
        <div class="card"><h4>CPU Usage</h4><p id="cpuUsage">--</p></div>
        <div class="card"><h4>RAM Usage</h4><p id="ramUsage">--</p></div>
        <div class="card"><h4>Storage</h4><p id="storageUsage">--</p></div>
        <div class="card"><h4>Total Accounts</h4><p id="totalAccounts">0</p></div>
        <div class="card"><h4>Offline Accounts</h4><p id="offlineAccounts">0</p></div>
      </div>
    </div>

    <div class="card">
      <h3>Create Account (auto expires in 3 days)</h3>
      <div class="field"><input id="newPass" placeholder="Password (leave empty to auto-generate)"></div>
      <div class="field"><button class="btn" onclick="createAccount()">Create Account</button></div>

      <!-- Message Alert (shows after creation) -->
      <div id="messageAlert" class="alert success" role="alert">
        <div id="alertContent"></div>
      </div>
    </div>

    <div id="donateCard" class="card" style="display:none">
      <h3>Donate</h3>
      <div class="small">Please donate to keep servers online</div>
      <div style="margin-top:8px">📱 Bitcoin: <code>bc1qexample...</code></div>
    </div>

    <div id="contactCard" class="card" style="display:none">
      <h3>Contact Admin</h3>
      <div>📧 admin@zivpn.com</div><div>📱 Telegram: @zivpn_admin</div>
    </div>

    <div class="card">
      <h3>Accounts</h3>
      <table class="table" id="accountsTable">
        <thead><tr><th>Password</th><th>Expires</th><th>Actions</th></tr></thead>
        <tbody></tbody>
      </table>
    </div>
  </div>
</div>

<script>
const ADMIN_USERNAME = "ADMIN_USERNAME_REPLACEME";
const ADMIN_PASSWORD = "ADMIN_PASSWORD_REPLACEME";
const SERVER_IP = "SERVER_IP_REPLACEME";

document.getElementById('serverIp').textContent = SERVER_IP;
document.getElementById('credUser').textContent = ADMIN_USERNAME;
document.getElementById('credPass').textContent = ADMIN_PASSWORD;

function copyText(id){
  const text=document.getElementById(id).textContent;
  navigator.clipboard.writeText(text).then(()=>alert('Copied'));
}

function login(){
  const u=document.getElementById('username').value;
  const p=document.getElementById('password').value;
  if(u===ADMIN_USERNAME && p===ADMIN_PASSWORD){
    document.getElementById('loginBox').style.display='none';
    document.getElementById('adminPanel').style.display='block';
    fetchStats(); fetchAccounts();
  } else {
    document.getElementById('loginError').style.display='block';
  }
}
function logout(){
  document.getElementById('loginBox').style.display='block';
  document.getElementById('adminPanel').style.display='none';
  document.getElementById('username').value=''; document.getElementById('password').value='';
}

function showDonate(){ document.getElementById('donateCard').style.display='block'; document.getElementById('contactCard').style.display='none'; }
function showContact(){ document.getElementById('donateCard').style.display='none'; document.getElementById('contactCard').style.display='block'; }

function fetchStats(){
  fetch('/api/stats').then(r=>r.json()).then(j=>{
    document.getElementById('serverTime').textContent = j.server_time;
    document.getElementById('cpuUsage').textContent = j.cpu;
    document.getElementById('ramUsage').textContent = j.ram;
    document.getElementById('storageUsage').textContent = j.storage;
    document.getElementById('totalAccounts').textContent = j.total_accounts;
    document.getElementById('offlineAccounts').textContent = j.offline_accounts;
  }).catch(()=>{});
}

function fetchAccounts(){
  fetch('/api/accounts').then(r=>r.json()).then(arr=>{
    const tbody=document.querySelector('#accountsTable tbody'); tbody.innerHTML='';
    arr.forEach((a,i)=>{
      const tr=document.createElement('tr');
      const td1=document.createElement('td'); td1.textContent=a.password;
      const td2=document.createElement('td'); td2.textContent=new Date(a.expires).toLocaleString();
      const td3=document.createElement('td');
      const del=document.createElement('button'); del.textContent='Delete'; del.onclick=()=>deleteAccount(i);
      td3.appendChild(del);
      tr.appendChild(td1); tr.appendChild(td2); tr.appendChild(td3);
      tbody.appendChild(tr);
    });
  }).catch(()=>{});
}

function createAccount(){
  const pass=document.getElementById('newPass').value;
  fetch('/api/create_account',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:pass})})
  .then(r=>r.json()).then(j=>{
    // show message alert with exact format requested
    const alert=document.getElementById('messageAlert');
    document.getElementById('alertContent').innerHTML =
      '<strong>Create Account Successfully ✅</strong><div>Server IP: '+SERVER_IP+'</div><div>Password: '+j.password+'</div><div>Expire Date: '+new Date(j.expires).toLocaleString()+'</div><div style="margin-top:8px">Please Donate For More Servers 😁</div>';
    alert.style.display='block';
    fetchStats(); fetchAccounts();
    document.getElementById('newPass').value='';
  }).catch(()=>{ alert('Create failed') });
}

function deleteAccount(index){
  fetch('/api/delete_account',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({index})})
  .then(()=>{ fetchStats(); fetchAccounts(); }).catch(()=>{});
}

setInterval(fetchStats,5000);
</script>
</body>
</html>
HTML

# replace placeholders securely
sed -i "s|ADMIN_USERNAME_REPLACEME|${ADMIN_USER}|g" /var/www/zivpn-admin/admin-panel.html
sed -i "s|ADMIN_PASSWORD_REPLACEME|${ESC_PASS}|g" /var/www/zivpn-admin/admin-panel.html
sed -i "s|SERVER_IP_REPLACEME|${SERVER_IP}|g" /var/www/zivpn-admin/admin-panel.html

# Create Python HTTPS server with API endpoints
cat > /var/www/zivpn-admin/server.py <<'PY'
#!/usr/bin/env python3
import http.server, socketserver, json, os, shutil, subprocess, datetime, ssl
ROOT='/var/www/zivpn-admin'
ACCOUNTS=os.path.join(ROOT,'accounts.json')
def load_accounts():
    try:
        with open(ACCOUNTS,'r') as f: return json.load(f)
    except: return []
def save_accounts(a):
    with open(ACCOUNTS,'w') as f: json.dump(a,f)
def get_stats():
    now=datetime.datetime.utcnow().isoformat()+'Z'
    try:
        import psutil
        cpu=f"{psutil.cpu_percent(interval=0.5)} %"
        mem=psutil.virtual_memory(); ram=f"{mem.percent} % ({round(mem.used/1024/1024)}MB/{round(mem.total/1024/1024)}MB)"
        d=shutil.disk_usage('/'); storage=f"{round((d.used/d.total)*100,1)} % ({round(d.used/1024/1024/1024,1)}GB used)"
    except:
        cpu="N/A"; ram="N/A"; storage="N/A"
    acc=load_accounts()
    total=len(acc)
    now_dt=datetime.datetime.utcnow()
    offline=sum(1 for x in acc if datetime.datetime.fromisoformat(x['expires']) < now_dt)
    return {'server_time':now,'cpu':cpu,'ram':ram,'storage':storage,'total_accounts':total,'offline_accounts':offline}
class Handler(http.server.SimpleHTTPRequestHandler):
    def _cors(self):
        self.send_header("Access-Control-Allow-Origin","*")
        self.send_header("Access-Control-Allow-Methods","GET,POST,OPTIONS")
        self.send_header("Access-Control-Allow-Headers","Content-Type")
    def do_OPTIONS(self):
        self.send_response(204); self._cors(); self.end_headers()
    def do_GET(self):
        if self.path.startswith('/api/stats'):
            d=get_stats(); self.send_response(200); self._cors(); self.send_header('Content-Type','application/json'); self.end_headers(); self.wfile.write(json.dumps(d).encode()); return
        if self.path.startswith('/api/accounts'):
            a=load_accounts(); self.send_response(200); self._cors(); self.send_header('Content-Type','application/json'); self.end_headers(); self.wfile.write(json.dumps(a).encode()); return
        if self.path == '/':
            self.path='/admin-panel.html'
        return super().do_GET()
    def do_POST(self):
        length=int(self.headers.get('Content-Length',0)); raw=self.rfile.read(length) if length else b''
        try: payload=json.loads(raw.decode()) if raw else {}
        except: payload={}
        if self.path=='/api/create_account':
            pw=payload.get('password','')
            if not pw:
                import random,string
                pw=''.join(random.choice(string.ascii_lowercase+string.digits) for _ in range(8))
            exp=(datetime.datetime.utcnow()+datetime.timedelta(days=3)).isoformat()
            a=load_accounts(); a.append({'password':pw,'expires':exp,'created':datetime.datetime.utcnow().isoformat()}); save_accounts(a)
            self.send_response(200); self._cors(); self.send_header('Content-Type','application/json'); self.end_headers(); self.wfile.write(json.dumps({'password':pw,'expires':exp}).encode()); return
        if self.path=='/api/delete_account':
            idx=payload.get('index',None); a=load_accounts()
            if idx is not None and 0 <= int(idx) < len(a): a.pop(int(idx)); save_accounts(a)
            self.send_response(200); self._cors(); self.send_header('Content-Type','application/json'); self.end_headers(); self.wfile.write(json.dumps({'ok':True}).encode()); return
        self.send_response(404); self._cors(); self.end_headers()

if __name__=='__main__':
    os.chdir(ROOT)
    PORT=8989
    with socketserver.TCPServer(("",PORT),Handler) as httpd:
        # wrap with SSL
        certfile='/etc/zivpn/zivpn.crt'; keyfile='/etc/zivpn/zivpn.key'
        try:
            httpd.socket = ssl.wrap_socket(httpd.socket, certfile=certfile, keyfile=keyfile, server_side=True)
            print("Serving HTTPS on port",PORT)
        except Exception as e:
            print("SSL wrap failed, serving HTTP instead:",e)
        httpd.serve_forever()
PY

chmod +x /var/www/zivpn-admin/server.py
chown -R root:root /var/www/zivpn-admin

# create systemd service for admin panel
cat > /etc/systemd/system/zivpn-admin.service <<'UNIT'
[Unit]
Description=ZIVPN Admin Panel (HTTPS)
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

# firewall rules
ufw allow 6000:19999/udp || true
ufw allow 5667/udp || true
ufw allow 8989/tcp || true
ufw --force enable || true

# iptables DNAT best-effort (map incoming UDP range to local zivpn port)
INT_IF="$(ip -4 route ls | grep default | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1); exit}')"
if [ -n "$INT_IF" ]; then
  iptables -t nat -D PREROUTING -i "$INT_IF" -p udp --dport 6000:19999 -j DNAT --to-destination 127.0.0.1:5667 2>/dev/null || true
  iptables -t nat -A PREROUTING -i "$INT_IF" -p udp --dport 6000:19999 -j DNAT --to-destination 127.0.0.1:5667
fi

# enable services
systemctl daemon-reload
systemctl enable zivpn.service || true
systemctl start zivpn.service || true
systemctl enable zivpn-admin.service
systemctl start zivpn-admin.service || true

# save credentials to root file
cat > /root/zivpn_credentials.txt <<CRED
================================================
           ZIVPN UDP Credentials
================================================
Web Admin Panel: https://${SERVER_IP}:8989
Admin Username: ${ADMIN_USER}
Admin Password: ${ADMIN_PASS}
UDP Port: 5667
Port Range: 6000-19999
Installation Date: $(date)
================================================
CRED

# ensure placeholders replaced in HTML (just in case)
sed -i "s|ADMIN_USERNAME_REPLACEME|${ADMIN_USER}|g" /var/www/zivpn-admin/admin-panel.html || true
sed -i "s|ADMIN_PASSWORD_REPLACEME|${ESC_PASS}|g" /var/www/zivpn-admin/admin-panel.html || true
sed -i "s|SERVER_IP_REPLACEME|${SERVER_IP}|g" /var/www/zivpn-admin/admin-panel.html || true

clear
echo "================================================"
echo "           ZIVPN UDP Installation Complete      "
echo "================================================"
echo ""
echo "📊 Web Admin Panel (HTTPS): https://${SERVER_IP}:8989"
echo "👤 Admin Username: ${ADMIN_USER}"
echo "🔐 Admin Password: ${ADMIN_PASS}"
echo ""
echo "🔧 UDP Service Port: 5667"
echo "📡 UDP Port Range: 6000-19999"
echo ""
echo "Saved credentials to /root/zivpn_credentials.txt"
echo ""
echo "Notes:"
echo " - The admin panel is served over HTTPS with a self-signed cert; your browser will warn about the certificate. For production, use nginx + certbot to get a valid Let's Encrypt cert."
echo " - If the page does not load: check provider firewall and run:"
echo "     sudo systemctl status zivpn-admin.service"
echo "     sudo journalctl -u zivpn-admin.service -n 200 --no-pager"
echo "     ss -ltnp | grep 8989"
echo ""
echo "Installation finished."
