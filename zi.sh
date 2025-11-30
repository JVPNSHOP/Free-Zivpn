#!/bin/bash
# zi.sh - ZIVPN UDP installer + Admin Web Panel
# Creator (adapted): Zahid Islam + assistant
set -e

echo -e "\n=== Updating server ==="
sudo apt-get update && sudo apt-get upgrade -y

echo -e "\n=== Stopping existing zivpn service (if any) ==="
systemctl stop zivpn.service 1> /dev/null 2> /dev/null || true

echo -e "\n=== Downloading UDP Service ==="
wget https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-amd64 -O /usr/local/bin/zivpn 1> /dev/null 2> /dev/null
chmod +x /usr/local/bin/zivpn

mkdir -p /etc/zivpn
mkdir -p /var/lib/zivpn
echo -e "\n=== Downloading default config.json ==="
wget https://raw.githubusercontent.com/zahidbd2/udp-zivpn/main/config.json -O /etc/zivpn/config.json 1> /dev/null 2> /dev/null || true

echo -e "\n=== Generating cert files (self-signed) ==="
openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 \
  -subj "/C=US/ST=California/L=Los Angeles/O=Example Corp/OU=IT Department/CN=zivpn" \
  -keyout "/etc/zivpn/zivpn.key" -out "/etc/zivpn/zivpn.crt" 1> /dev/null 2> /dev/null || true

sysctl -w net.core.rmem_max=16777216 1> /dev/null 2> /dev/null || true
sysctl -w net.core.wmem_max=16777216 1> /dev/null 2> /dev/null || true

echo -e "\n=== Installing/creating zivpn systemd service ==="
cat <<'EOF' > /etc/systemd/system/zivpn.service
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

# Prompt for initial ZIVPN passwords (existing behaviour preserved)
echo -e "\n=== ZIVPN UDP Passwords ==="
read -p "Enter passwords separated by commas, example: pass1,pass2 (Press enter for Default 'zi'): " input_config
if [ -n "$input_config" ]; then
    IFS=',' read -r -a config <<< "$input_config"
    if [ ${#config[@]} -eq 1 ]; then
        config+=("${config[0]}")
    fi
else
    config=("zi")
fi

# Build new config string
new_config_str="\"config\": [$(printf "\"%s\"," "${config[@]}" | sed 's/,$//')]"
# Replace existing config array or add it if not present
if grep -q '"config"\s*:' /etc/zivpn/config.json; then
  sed -i -E "s/\"config\": ?\[[[:space:]]*([^\]]*)\]/${new_config_str}/g" /etc/zivpn/config.json
else
  # insert into top-level (simple step: put before last })
  sed -i -E "s/}\s*$/,\n  ${new_config_str}\n}/" /etc/zivpn/config.json || true
fi

echo -e "\n=== Enabling and starting zivpn.service ==="
systemctl daemon-reload
systemctl enable zivpn.service
systemctl restart zivpn.service

# Open firewall rules for UDP range used by original script
IFACE=$(ip -4 route ls|grep default|grep -Po '(?<=dev )(\S+)'|head -1)
iptables -t nat -A PREROUTING -i "${IFACE}" -p udp --dport 6000:19999 -j DNAT --to-destination :5667 || true
ufw allow 6000:19999/udp || true
ufw allow 5667/udp || true

# Clean any temp files used before (keep safe)
rm -f zi.* 1> /dev/null 2> /dev/null || true

echo -e "\n=== ZIVPN UDP Installed ==="

##########################################
# Now install the Admin Web Panel (Flask)
##########################################

echo -e "\n=== Installing Python, pip, virtualenv ==="
apt-get install -y python3 python3-venv python3-pip >/dev/null 2>&1 || true

PANEL_DIR=/opt/zivpn_panel
mkdir -p "${PANEL_DIR}"
chown -R root:root "${PANEL_DIR}"

# Ask for admin username/password for the panel
echo -e "\n=== Admin panel credentials ==="
read -p "Enter Admin Username (default: admin): " ADMIN_USER
ADMIN_USER=${ADMIN_USER:-admin}
read -p "Enter Admin Password (default: admin): " ADMIN_PASS
ADMIN_PASS=${ADMIN_PASS:-admin}

# Save admin creds (file mode 600)
mkdir -p /var/lib/zivpn
cat > /var/lib/zivpn/panel_auth.json <<EOF
{"user":"${ADMIN_USER}","pass":"${ADMIN_PASS}"}
EOF
chmod 600 /var/lib/zivpn/panel_auth.json

# Create data files for accounts and daily counter
ACCOUNTS_FILE=/var/lib/zivpn/accounts.json
DAILY_FILE=/var/lib/zivpn/daily_count.json

if [ ! -f "${ACCOUNTS_FILE}" ]; then
  echo "[]" > "${ACCOUNTS_FILE}"
fi

if [ ! -f "${DAILY_FILE}" ]; then
  echo "{\"date\":\"$(date +%F)\",\"count\":0}" > "${DAILY_FILE}"
fi

# Create Flask app
cat > "${PANEL_DIR}/app.py" <<'PY'
from flask import Flask, render_template, request, redirect, jsonify, session, url_for
import json, os, datetime, subprocess

APP_ROOT = os.path.dirname(os.path.abspath(__file__))
ACCOUNTS_FILE = "/var/lib/zivpn/accounts.json"
DAILY_FILE = "/var/lib/zivpn/daily_count.json"
AUTH_FILE = "/var/lib/zivpn/panel_auth.json"
CONFIG_JSON = "/etc/zivpn/config.json"

app = Flask(__name__)
app.secret_key = "zivpn-secret-key-change-this"

# helper functions
def read_json(path, default):
    try:
        with open(path,'r') as f:
            return json.load(f)
    except:
        return default

def write_json(path, data):
    with open(path,'w') as f:
        json.dump(data, f, indent=2)

def get_server_ip():
    try:
        # get primary IPv4 address
        dev = subprocess.check_output("ip -4 route ls|grep default|grep -Po '(?<=dev )(\S+)'|head -1", shell=True).decode().strip()
        ip = subprocess.check_output(f"ip -4 addr show {dev} | grep -Po 'inet \\K[0-9.]+' | head -1", shell=True).decode().strip()
        return ip or "127.0.0.1"
    except:
        return "127.0.0.1"

def system_stats():
    # server time
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    # cpu usage (load)
    try:
        load = subprocess.check_output("cat /proc/loadavg | awk '{print $1,$2,$3}'", shell=True).decode().strip()
    except:
        load = ""
    # memory
    try:
        mem = subprocess.check_output("free -h | awk 'NR==2{print $3\" / \"$2}'", shell=True).decode().strip()
    except:
        mem = ""
    # disk
    try:
        disk = subprocess.check_output("df -h / | awk 'NR==2{print $3\" / \"$2\" (\"$5\")\"}'", shell=True).decode().strip()
    except:
        disk = ""
    return {"time": now, "load": load, "mem": mem, "disk": disk}

def update_zivpn_config(passwords):
    # ensure config.json exists and is valid JSON
    cfg = read_json(CONFIG_JSON, {})
    # set "config" key to provided passwords list
    cfg["config"] = passwords
    write_json(CONFIG_JSON, cfg)
    # restart zivpn service to pick up change
    subprocess.call(["systemctl","restart","zivpn.service"])

@app.route("/", methods=["GET","POST"])
def login():
    auth = read_json(AUTH_FILE, {})
    # Show the login page, with admin creds displayed as requested
    return render_template("login.html", admin_user=auth.get("user","admin"), admin_pass=auth.get("pass","admin"))

@app.route("/panel", methods=["GET","POST"])
def panel():
    # Simple sessionless "login" using the posted credentials (but shows creds)
    auth = read_json(AUTH_FILE, {})
    if request.method == "POST":
        u = request.form.get("username")
        p = request.form.get("password")
        if u == auth.get("user") and p == auth.get("pass"):
            session["authed"] = True
            return redirect(url_for("dashboard"))
        else:
            return render_template("login.html", admin_user=auth.get("user"), admin_pass=auth.get("pass"), error="Invalid credentials")
    return redirect(url_for("login"))

@app.route("/dashboard")
def dashboard():
    if not session.get("authed"):
        return redirect(url_for("login"))
    stats = system_stats()
    accounts = read_json(ACCOUNTS_FILE, [])
    total = len(accounts)
    expired = sum(1 for a in accounts if a.get("expire") and datetime.datetime.fromisoformat(a["expire"]) < datetime.datetime.now())
    # daily quota
    daily = read_json(DAILY_FILE, {"date": datetime.date.today().isoformat(), "count": 0})
    # ensure daily.date is today
    if daily.get("date") != datetime.date.today().isoformat():
        daily = {"date": datetime.date.today().isoformat(), "count": 0}
        write_json(DAILY_FILE, daily)
    server_ip = get_server_ip()
    return render_template("dashboard.html", stats=stats, total=total, expired=expired, daily=daily, server_ip=server_ip)

@app.route("/api/add", methods=["POST"])
def api_add():
    if not session.get("authed"):
        return jsonify({"ok":False,"error":"unauthenticated"}),401
    data = request.get_json() or {}
    pwd = data.get("password")
    days = int(data.get("days",3))
    if not pwd:
        return jsonify({"ok":False,"error":"password required"}),400
    # check daily limit
    daily = read_json(DAILY_FILE, {"date": datetime.date.today().isoformat(), "count": 0})
    if daily.get("date") != datetime.date.today().isoformat():
        daily = {"date": datetime.date.today().isoformat(), "count": 0}
    if daily["count"] >= 250:
        return jsonify({"ok":False,"error":"daily limit reached (250)"}),402
    # add account
    now = datetime.datetime.now()
    expire = (now + datetime.timedelta(days=days)).isoformat()
    accounts = read_json(ACCOUNTS_FILE, [])
    accounts.append({"password": pwd, "created": now.isoformat(), "expire": expire, "active": True})
    write_json(ACCOUNTS_FILE, accounts)
    # update config.json passwords
    # pull existing config passwords and append if not present
    cfg = read_json(CONFIG_JSON, {})
    existing = cfg.get("config", [])
    if pwd not in existing:
        existing.append(pwd)
    cfg["config"] = existing
    write_json(CONFIG_JSON, cfg)
    # restart zivpn service to apply
    try:
        subprocess.call(["systemctl","restart","zivpn.service"])
    except:
        pass
    # increment daily counter
    daily["count"] = daily.get("count",0) + 1
    write_json(DAILY_FILE, daily)
    return jsonify({"ok":True,"password":pwd,"expire":expire,"server_ip":get_server_ip(),"daily":daily})

@app.route("/api/stats")
def api_stats():
    if not session.get("authed"):
        return jsonify({"ok":False,"error":"unauthenticated"}),401
    stats = system_stats()
    accounts = read_json(ACCOUNTS_FILE, [])
    total = len(accounts)
    expired = sum(1 for a in accounts if a.get("expire") and datetime.datetime.fromisoformat(a["expire"]) < datetime.datetime.now())
    daily = read_json(DAILY_FILE, {"date": datetime.date.today().isoformat(), "count": 0})
    if daily.get("date") != datetime.date.today().isoformat():
        daily = {"date": datetime.date.today().isoformat(), "count": 0}
    return jsonify({"ok":True,"stats":stats,"total":total,"expired":expired,"daily":daily,"ip":get_server_ip()})

@app.route("/logout")
def logout():
    session.pop("authed", None)
    return redirect(url_for("login"))

if __name__ == "__main__":
    # Run with certs created earlier
    cert = "/etc/zivpn/zivpn.crt"
    key = "/etc/zivpn/zivpn.key"
    app.run(host="0.0.0.0", port=8000, ssl_context=(cert,key))
PY

# Create templates and static files
mkdir -p "${PANEL_DIR}/templates"
mkdir -p "${PANEL_DIR}/static"

# login.html (shows admin creds on page as requested)
cat > "${PANEL_DIR}/templates/login.html" <<'HTML'
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>ZIVPN Admin Login</title>
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <style>
    body{font-family:Inter,Arial;margin:0;background:#0f172a;color:#fff;display:flex;align-items:center;justify-content:center;height:100vh}
    .box{background:linear-gradient(180deg,#111827,#0b1220);padding:22px;border-radius:12px;width:360px;box-shadow:0 6px 30px rgba(0,0,0,.6)}
    h2{margin:0 0 10px 0}
    .hint{font-size:12px;color:#cbd5e1;background:#071028;padding:8px;border-radius:6px;margin-bottom:12px}
    input{width:100%;padding:10px;margin:6px 0;border-radius:6px;border:1px solid #1f2937;background:#071028;color:#fff}
    button{width:100%;padding:10px;border-radius:8px;border:0;background:#fb7185;color:#fff;font-weight:600}
    .footer{font-size:13px;margin-top:8px;color:#94a3b8;display:flex;justify-content:space-between}
  </style>
</head>
<body>
  <div class="box">
    <h2>ZIVPN Admin Panel</h2>
    <div class="hint">
      Admin Username: <strong>{{ admin_user }}</strong><br>
      Admin Password: <strong>{{ admin_pass }}</strong><br>
      (These credentials are shown here as requested.)
    </div>
    {% if error %}
      <div style="color:#fecaca;margin-bottom:8px">{{ error }}</div>
    {% endif %}
    <form method="post" action="/panel">
      <input name="username" placeholder="Username" value="{{ admin_user }}">
      <input name="password" placeholder="Password" value="{{ admin_pass }}">
      <button type="submit">Login</button>
    </form>
    <div class="footer">
      <div>Donate ❤️</div>
      <div>Contact Admin ✉️</div>
    </div>
  </div>
</body>
</html>
HTML

# dashboard.html - simple UI with Add Password form and stats
cat > "${PANEL_DIR}/templates/dashboard.html" <<'HTML'
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>ZIVPN Panel</title>
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <style>
    :root{--bg:#0f172a;--card:#071028;--accent:#fb7185;--muted:#94a3b8}
    body{font-family:Inter,Arial;margin:0;background:var(--bg);color:#fff}
    header{display:flex;justify-content:space-between;align-items:center;padding:14px 20px;border-bottom:1px solid rgba(255,255,255,.03)}
    .brand{font-weight:700}
    .menu{display:flex;gap:12px;align-items:center}
    .container{padding:18px;display:grid;grid-template-columns:1fr 420px;gap:18px}
    .card{background:linear-gradient(180deg,var(--card),#050615);padding:14px;border-radius:12px}
    .stat{display:flex;justify-content:space-between;padding:10px 0;border-bottom:1px dashed rgba(255,255,255,.03)}
    .small{font-size:12px;color:var(--muted)}
    input,button,select{width:100%;padding:10px;border-radius:8px;border:1px solid rgba(255,255,255,.04);background:transparent;color:#fff}
    button{background:var(--accent);border:0;font-weight:600}
    .top-right{display:flex;gap:10px;align-items:center}
    .note{margin-top:8px;color:var(--muted);font-size:13px}
    .copy{cursor:pointer;padding:6px;border-radius:6px;background:rgba(255,255,255,.03)}
  </style>
</head>
<body>
  <header>
    <div class="brand">ZIVPN Admin</div>
    <div class="top-right menu">
      <div>Donate 💖</div>
      <div>Contact Admin ✉️</div>
    </div>
  </header>

  <div class="container">
    <div>
      <div class="card">
        <h3>Server Overview</h3>
        <div class="stat"><div>Server Time</div><div>{{ stats.time }}</div></div>
        <div class="stat"><div>CPU Load</div><div>{{ stats.load }}</div></div>
        <div class="stat"><div>RAM Usage</div><div>{{ stats.mem }}</div></div>
        <div class="stat"><div>Storage</div><div>{{ stats.disk }}</div></div>
        <div class="stat"><div>Total Account</div><div>{{ total }}</div></div>
        <div class="stat"><div>Total Offline</div><div>{{ expired }}</div></div>
      </div>

      <div style="height:12px"></div>

      <div class="card">
        <h3>Add Password</h3>
        <div style="display:grid;gap:8px">
          <input id="pwd" placeholder="password to add (required)">
          <select id="days">
            <option value="3">3 days (default)</option>
            <option value="1">1 day</option>
            <option value="7">7 days</option>
            <option value="30">30 days</option>
          </select>
          <div style="display:flex;gap:8px">
            <button id="addBtn">Add Password</button>
            <button id="bulkBtn">Bulk (comma separated)</button>
          </div>
          <div class="note">Today's usage: <span id="dailyCount">{{ daily.count }}</span>/250</div>
          <div id="alerts"></div>
        </div>
      </div>
    </div>

    <aside>
      <div class="card">
        <h3>Quick Actions</h3>
        <div class="small">Server IP</div>
        <div style="display:flex;gap:8px;margin-top:6px;align-items:center">
          <div style="flex:1;padding:8px;background:#071028;border-radius:8px">{{ server_ip }}</div>
          <div class="copy" onclick="copyToClipboard('{{ server_ip }}')">Copy</div>
        </div>
        <div style="height:12px"></div>
        <div class="small">Daily Quota</div>
        <div style="margin-top:6px">{{ daily.count }} / 250</div>
        <div style="height:12px"></div>
        <div class="small">Menu</div>
        <div style="margin-top:6px;display:flex;gap:8px">
          <a href="#" style="text-decoration:none;color:#fff">Donate</a>
          <a href="#" style="text-decoration:none;color:#fff">Contact Admin</a>
        </div>
      </div>
    </aside>
  </div>

<script>
function showAlert(msg, ok=true){
  const a = document.getElementById('alerts');
  const el = document.createElement('div');
  el.style.padding='10px';
  el.style.marginTop='8px';
  el.style.borderRadius='8px';
  el.style.background = ok ? 'rgba(16,185,129,0.08)' : 'rgba(248,113,113,0.08)';
  el.innerHTML = msg;
  a.prepend(el);
  setTimeout(()=>el.remove(),12000);
}
function copyToClipboard(text){
  navigator.clipboard.writeText(text).then(()=> showAlert('Copied to clipboard'));
}

document.getElementById('addBtn').addEventListener('click', async ()=>{
  const pwd = document.getElementById('pwd').value.trim();
  const days = document.getElementById('days').value;
  if(!pwd){ showAlert('Password required', false); return; }
  const res = await fetch('/api/add',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:pwd,days:days})});
  const j = await res.json();
  if(j.ok){
    showAlert('✅ Create Account Successfully<br>Server IP: <strong>'+j.server_ip+'</strong><br>Password: <strong>'+j.password+'</strong><br>Expired Date: <strong>'+j.expire+'</strong>');
    document.getElementById('dailyCount').innerText = j.daily.count;
  } else {
    showAlert('Error: '+(j.error||'unknown'), false);
  }
});

document.getElementById('bulkBtn').addEventListener('click', async ()=>{
  const raw = document.getElementById('pwd').value.trim();
  if(!raw){ showAlert('Please paste comma separated passwords for bulk add', false); return; }
  const arr = raw.split(',').map(s=>s.trim()).filter(Boolean);
  for(const p of arr){
    const days = document.getElementById('days').value;
    const res = await fetch('/api/add',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:p,days:days})});
    const j = await res.json();
    if(j.ok){
      showAlert('✅ '+p+' created. Expire: '+j.expire);
      document.getElementById('dailyCount').innerText = j.daily.count;
    } else {
      showAlert('Error for '+p+': '+(j.error||'unknown'), false);
    }
  }
});
</script>
</body>
</html>
HTML

# Create a simple systemd service to run the panel with the venv
echo -e "\n=== Creating Python venv and installing Flask ==="
python3 -m venv "${PANEL_DIR}/venv"
"${PANEL_DIR}/venv/bin/pip" install --upgrade pip >/dev/null 2>&1 || true
"${PANEL_DIR}/venv/bin/pip" install flask >/dev/null 2>&1 || true

cat > /etc/systemd/system/zivpn-panel.service <<EOF
[Unit]
Description=ZIVPN Admin Panel
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${PANEL_DIR}
Environment=FLASK_ENV=production
ExecStart=${PANEL_DIR}/venv/bin/python ${PANEL_DIR}/app.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable zivpn-panel.service
systemctl restart zivpn-panel.service

# Friendly summary printed at end (with colors)
IP="$(ip -4 addr show ${IFACE} | grep -Po 'inet \K[\d.]+' | head -1 || echo 127.0.0.1)"
NC='\033[0m'
PINK='\033[1;35m'
GREEN='\033[1;32m'
echo -e "\n${PINK}=== ZIVPN Admin Panel Installed ===${NC}"
echo -e "${GREEN}Admin Panel: https://${IP}:8000${NC}"
echo -e "${GREEN}Admin Username: ${ADMIN_USER}${NC}"
echo -e "${GREEN}Admin Password: ${ADMIN_PASS}${NC}"
echo -e "\nDonate For More Servers 😁"
echo -e "\nMenu (top-right): Donate | Contact Admin"
echo -e "\n(If port 8000 is blocked, allow it in your firewall.)"
