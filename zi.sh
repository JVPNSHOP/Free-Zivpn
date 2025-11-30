#!/bin/bash
# zi.sh - ZIVPN UDP installer + improved Admin Web Panel (bulk add, copy buttons, icons, nicer UI)
# Run: chmod +x zi.sh && sudo ./zi.sh
set -e

echo -e "\n=== Updating server ==="
sudo apt-get update && sudo apt-get upgrade -y

echo -e "\n=== Stopping existing zivpn service (if any) ==="
systemctl stop zivpn.service 1> /dev/null 2> /dev/null || true

echo -e "\n=== Downloading UDP Service ==="
wget -q https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-amd64 -O /usr/local/bin/zivpn || true
chmod +x /usr/local/bin/zivpn || true

mkdir -p /etc/zivpn
mkdir -p /var/lib/zivpn
echo -e "\n=== Downloading default config.json ==="
wget -q https://raw.githubusercontent.com/zahidbd2/udp-zivpn/main/config.json -O /etc/zivpn/config.json || true

echo -e "\n=== Generating cert files (self-signed, kept but not used by default UI) ==="
openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 \
  -subj "/C=US/ST=California/L=Los Angeles/O=ZIVPN/OU=IT/CN=zivpn" \
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

# Prompt for initial ZIVPN passwords (keeps previous behaviour)
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

# Build new config string and insert/replace into /etc/zivpn/config.json
new_config_str="\"config\": [$(printf "\"%s\"," "${config[@]}" | sed 's/,$//')]"
if grep -q '"config"\s*:' /etc/zivpn/config.json; then
  sed -i -E "s/\"config\": ?\[[[:space:]]*([^\]]*)\]/${new_config_str}/g" /etc/zivpn/config.json || true
else
  sed -i -E "s/}\s*$/,\n  ${new_config_str}\n}/" /etc/zivpn/config.json || true
fi

echo -e "\n=== Enabling and starting zivpn.service ==="
systemctl daemon-reload
systemctl enable zivpn.service
systemctl restart zivpn.service || true

# Firewall / iptables (best-effort)
IFACE=$(ip -4 route ls|grep default|grep -Po '(?<=dev )(\S+)'|head -1 || true)
if [ -n "$IFACE" ]; then
  iptables -t nat -A PREROUTING -i "${IFACE}" -p udp --dport 6000:19999 -j DNAT --to-destination :5667 2> /dev/null || true
fi
ufw allow 6000:19999/udp 2> /dev/null || true
ufw allow 5667/udp 2> /dev/null || true

rm -f zi.* 1> /dev/null 2> /dev/null || true

echo -e "\n=== ZIVPN UDP Installed ==="

##########################################
# Now install the Admin Web Panel (Flask)
# - HTTP (no TLS) to avoid browser cert warnings by default
# - Bulk endpoint (/api/bulk) to add many passwords at once
# - Alerts include copy buttons for IP / Password / Expiry
# - Icons for CPU / RAM / Storage; cleaner header (removed big picture)
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

# Create Flask app (served over HTTP to avoid cert warning)
cat > "${PANEL_DIR}/app.py" <<'PY'
from flask import Flask, render_template, request, redirect, jsonify, session, url_for
import json, os, datetime, subprocess

APP_ROOT = os.path.dirname(os.path.abspath(__file__))
ACCOUNTS_FILE = "/var/lib/zivpn/accounts.json"
DAILY_FILE = "/var/lib/zivpn/daily_count.json"
AUTH_FILE = "/var/lib/zivpn/panel_auth.json"
CONFIG_JSON = "/etc/zivpn/config.json"

app = Flask(__name__, static_folder='static', template_folder='templates')
app.secret_key = "zivpn-secret-key-change-this"

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
        dev = subprocess.check_output("ip -4 route ls|grep default|grep -Po '(?<=dev )(\S+)'|head -1", shell=True).decode().strip()
        ip = subprocess.check_output(f"ip -4 addr show {dev} | grep -Po 'inet \\K[0-9.]+' | head -1", shell=True).decode().strip()
        return ip or "127.0.0.1"
    except:
        return "127.0.0.1"

def system_stats():
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        load = subprocess.check_output("cat /proc/loadavg | awk '{print $1\" \" $2\" \" $3}'", shell=True).decode().strip()
    except:
        load = ""
    try:
        mem = subprocess.check_output("free -h | awk 'NR==2{print $3\" / \"$2}'", shell=True).decode().strip()
    except:
        mem = ""
    try:
        disk = subprocess.check_output("df -h / | awk 'NR==2{print $3\" / \"$2\" (\"$5\")\"}'", shell=True).decode().strip()
    except:
        disk = ""
    return {"time": now, "load": load, "mem": mem, "disk": disk}

def restart_zivpn():
    try:
        subprocess.call(["systemctl","restart","zivpn.service"])
    except:
        pass

@app.route("/", methods=["GET","POST"])
def login():
    auth = read_json(AUTH_FILE, {})
    return render_template("login.html", admin_user=auth.get("user","admin"), admin_pass=auth.get("pass","admin"))

@app.route("/panel", methods=["GET","POST"])
def panel():
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
    daily = read_json(DAILY_FILE, {"date": datetime.date.today().isoformat(), "count": 0})
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
    # daily limit enforcement
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
    cfg = read_json(CONFIG_JSON, {})
    existing = cfg.get("config", [])
    if pwd not in existing:
        existing.append(pwd)
    cfg["config"] = existing
    write_json(CONFIG_JSON, cfg)
    restart_zivpn()
    # increment daily counter
    daily["count"] = daily.get("count",0) + 1
    write_json(DAILY_FILE, daily)
    # compute totals
    total = len(accounts)
    expired = sum(1 for a in accounts if a.get("expire") and datetime.datetime.fromisoformat(a["expire"]) < datetime.datetime.now())
    return jsonify({"ok":True,"password":pwd,"expire":expire,"server_ip":get_server_ip(),"daily":daily,"total":total,"expired":expired})

@app.route("/api/bulk", methods=["POST"])
def api_bulk():
    if not session.get("authed"):
        return jsonify({"ok":False,"error":"unauthenticated"}),401
    data = request.get_json() or {}
    pwds = data.get("passwords", [])
    days = int(data.get("days",3))
    if not pwds or not isinstance(pwds, list):
        return jsonify({"ok":False,"error":"passwords list required"}),400
    # daily limit check
    daily = read_json(DAILY_FILE, {"date": datetime.date.today().isoformat(), "count": 0})
    if daily.get("date") != datetime.date.today().isoformat():
        daily = {"date": datetime.date.today().isoformat(), "count": 0}
    added = []
    accounts = read_json(ACCOUNTS_FILE, [])
    cfg = read_json(CONFIG_JSON, {})
    existing = cfg.get("config", [])
    for pwd in pwds:
        if daily["count"] >= 250:
            break
        now = datetime.datetime.now()
        expire = (now + datetime.timedelta(days=days)).isoformat()
        accounts.append({"password": pwd, "created": now.isoformat(), "expire": expire, "active": True})
        if pwd not in existing:
            existing.append(pwd)
        daily["count"] = daily.get("count",0) + 1
        added.append({"password":pwd,"expire":expire})
    write_json(ACCOUNTS_FILE, accounts)
    cfg["config"] = existing
    write_json(CONFIG_JSON, cfg)
    write_json(DAILY_FILE, daily)
    restart_zivpn()
    total = len(accounts)
    expired = sum(1 for a in accounts if a.get("expire") and datetime.datetime.fromisoformat(a["expire"]) < datetime.datetime.now())
    return jsonify({"ok":True,"added":added,"daily":daily,"total":total,"expired":expired})

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
    # Serve HTTP on 0.0.0.0:8000 (no SSL) to avoid browser cert warnings.
    app.run(host="0.0.0.0", port=8000)
PY

# Create templates and static files (UI improvements, icons, bulk endpoint usage, copy buttons)
mkdir -p "${PANEL_DIR}/templates"
mkdir -p "${PANEL_DIR}/static"

# login.html (clean header - removed large image)
cat > "${PANEL_DIR}/templates/login.html" <<'HTML'
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>ZIVPN Admin Login</title>
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <style>
    :root{--bg:#0f172a;--card:#071028;--accent:#fb7185;--muted:#94a3b8}
    body{margin:0;font-family:Inter,Arial;background:var(--bg);color:#fff;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px}
    .box{width:100%;max-width:420px;background:linear-gradient(180deg,#0b1220,#050615);padding:22px;border-radius:14px;box-shadow:0 10px 30px rgba(0,0,0,.6)}
    h2{margin:0 0 12px 0;font-size:20px}
    .hint{font-size:13px;color:var(--muted);background:rgba(255,255,255,.02);padding:10px;border-radius:8px;margin-bottom:12px}
    input{width:100%;padding:12px;margin:8px 0;border-radius:8px;border:1px solid rgba(255,255,255,.04);background:transparent;color:#fff;box-sizing:border-box}
    button{width:100%;padding:12px;border-radius:10px;border:0;background:var(--accent);color:#fff;font-weight:700}
    .footer{display:flex;justify-content:space-between;margin-top:12px;color:var(--muted);font-size:13px}
    .logo{font-weight:800}
  </style>
</head>
<body>
  <div class="box">
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px">
      <div style="font-size:18px;font-weight:700">ZIVPN Admin</div>
      <div style="font-size:12px;color:var(--muted)">Manage accounts & passwords</div>
    </div>
    <h2>Sign in</h2>
    <div class="hint">
      Admin Username: <strong>{{ admin_user }}</strong><br>
      Admin Password: <strong>{{ admin_pass }}</strong><br>
      (Credentials shown here as requested)
    </div>
    {% if error %}
      <div style="color:#fecaca;margin-bottom:8px">{{ error }}</div>
    {% endif %}
    <form method="post" action="/panel">
      <input name="username" placeholder="Username" value="{{ admin_user }}" autocomplete="username">
      <input name="password" placeholder="Password" value="{{ admin_pass }}" type="password" autocomplete="current-password">
      <button type="submit">Login</button>
    </form>
    <div class="footer">
      <div>Donate 💖</div>
      <div>Contact Admin ✉️</div>
    </div>
  </div>
</body>
</html>
HTML

# dashboard.html - improved layout, icons, bulk endpoint usage, copy buttons in alerts
cat > "${PANEL_DIR}/templates/dashboard.html" <<'HTML'
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>ZIVPN Panel</title>
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <style>
    :root{--bg:#0f172a;--card:#071028;--accent:#fb7185;--muted:#94a3b8}
    *{box-sizing:border-box}
    body{font-family:Inter,Arial;margin:0;background:var(--bg);color:#fff}
    header{display:flex;justify-content:space-between;align-items:center;padding:14px 16px;border-bottom:1px solid rgba(255,255,255,.03);position:sticky;top:0;background:linear-gradient(180deg,rgba(11,17,32,.9),rgba(11,17,32,.6));backdrop-filter: blur(4px);z-index:10}
    .brand{font-weight:700;display:flex;align-items:center;gap:10px}
    .menu{display:flex;gap:12px;align-items:center;font-size:14px}
    .container{padding:18px;display:grid;grid-template-columns:1fr 360px;gap:18px}
    @media(max-width:900px){ .container{grid-template-columns:1fr; padding:12px} .right-col{order:2} .left-col{order:1}}
    .card{background:linear-gradient(180deg,var(--card),#050615);padding:14px;border-radius:12px;box-shadow:0 6px 20px rgba(0,0,0,.6)}
    .stat{display:flex;justify-content:space-between;padding:12px 0;border-bottom:1px dashed rgba(255,255,255,.03);align-items:center}
    .small{font-size:13px;color:var(--muted)}
    input,button,select,textarea{width:100%;padding:12px;border-radius:10px;border:1px solid rgba(255,255,255,.04);background:transparent;color:#fff;outline:none}
    button{background:var(--accent);border:0;font-weight:700}
    .grid-2{display:grid;grid-template-columns:1fr 1fr;gap:10px}
    .copy{cursor:pointer;padding:8px;border-radius:8px;background:rgba(255,255,255,.02);font-size:13px}
    .note{margin-top:8px;color:var(--muted);font-size:13px}
    .btn-soft{background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.03);color:#fff;padding:10px;border-radius:10px}
    .iconsmall{display:inline-block;width:20px;text-align:center;margin-right:8px}
    .alerts{margin-top:10px}
    .alert-card{padding:10px;border-radius:10px;background:rgba(255,255,255,0.02);margin-bottom:8px}
    .alert-actions{display:flex;gap:8px;margin-top:8px}
  </style>
</head>
<body>
  <header>
    <div class="brand"><div style="font-size:16px;font-weight:800">ZIVPN Admin</div></div>
    <div class="menu">
      <a href="#" style="text-decoration:none;color:#fff">Donate 💖</a>
      <a href="#" style="text-decoration:none;color:#fff">Contact Admin ✉️</a>
    </div>
  </header>

  <div class="container">
    <div class="left-col">
      <div class="card">
        <h3>Server Overview</h3>
        <div class="stat"><div><span class="iconsmall">🕒</span> Server Time</div><div>{{ stats.time }}</div></div>
        <div class="stat"><div><span class="iconsmall">🧠</span> CPU Load</div><div style="text-align:right">{{ stats.load }}</div></div>
        <div class="stat"><div><span class="iconsmall">💾</span> RAM Usage</div><div style="text-align:right">{{ stats.mem }}</div></div>
        <div class="stat"><div><span class="iconsmall">📦</span> Storage</div><div style="text-align:right">{{ stats.disk }}</div></div>
        <div class="stat"><div><span class="iconsmall">👥</span> Total Account</div><div id="totalAccount">{{ total }}</div></div>
        <div class="stat"><div><span class="iconsmall">⚠️</span> Total Offline</div><div id="totalOffline">{{ expired }}</div></div>
      </div>

      <div style="height:14px"></div>

      <div class="card">
        <h3>Add Password</h3>
        <div style="display:grid;gap:10px">
          <input id="pwd" placeholder="password to add (required)" autocomplete="off">
          <div>
            <label class="small">Expire in</label>
            <select id="days" aria-label="Expire days">
              <option value="3">🔒 3 days (default)</option>
              <option value="1">⏳ 1 day</option>
              <option value="7">📆 7 days</option>
              <option value="10">🔁 10 days (max)</option>
            </select>
          </div>

          <div class="grid-2">
            <button id="addBtn">Add Password</button>
            <button id="bulkBtn" class="btn-soft">Bulk (comma separated)</button>
          </div>

          <div class="note">Today's usage: <strong id="dailyCount">{{ daily.count }}</strong> / 250</div>
          <div id="alerts" class="alerts"></div>
        </div>
      </div>

    </div>

    <div class="right-col">
      <aside class="card">
        <h3>Quick Actions</h3>
        <div class="small">Server IP</div>
        <div style="display:flex;gap:8px;margin-top:6px;align-items:center">
          <div id="serverIpBox" style="flex:1;padding:10px;background:#071028;border-radius:8px">{{ server_ip }}</div>
          <div class="copy" onclick="copyToClipboard(document.getElementById('serverIpBox').innerText)">Copy</div>
        </div>

        <div style="height:10px"></div>
        <div class="small">Daily Quota</div>
        <div style="margin-top:6px" id="quotaText">{{ daily.count }} / 250</div>

        <div style="height:10px"></div>
        <div class="small">Menu</div>
        <div style="margin-top:6px;display:flex;gap:8px">
          <a class="btn-soft" href="#">Donate 💖</a>
          <a class="btn-soft" href="#">Contact ✉️</a>
        </div>
      </aside>
    </div>
  </div>

<script>
function showAlertHTML(html, ok=true){
  const a = document.getElementById('alerts');
  const el = document.createElement('div');
  el.className = 'alert-card';
  el.innerHTML = html;
  a.prepend(el);
  // attach copy handler for any button with data-copy
  el.querySelectorAll('[data-copy]').forEach(btn=>{
    btn.addEventListener('click', ()=> {
      const t = btn.getAttribute('data-copy');
      navigator.clipboard.writeText(t).then(()=> {
        btn.innerText = 'Copied';
        setTimeout(()=> btn.innerText = (btn.getAttribute('data-label')||'Copy'), 1200);
      });
    });
  });
  setTimeout(()=>{ try{ el.remove(); } catch(e){} },15000);
}
function copyToClipboard(text){
  if(!navigator.clipboard){ alert('Copy not supported'); return; }
  navigator.clipboard.writeText(text).then(()=> {
    const a = document.getElementById('alerts');
    const el = document.createElement('div');
    el.className='alert-card';
    el.innerText = 'Copied to clipboard';
    a.prepend(el);
    setTimeout(()=>el.remove(),2000);
  });
}

async function refreshStats(){
  try{
    const res = await fetch('/api/stats');
    const j = await res.json();
    if(j.ok){
      document.getElementById('totalAccount').innerText = j.total;
      document.getElementById('totalOffline').innerText = j.expired;
      document.getElementById('dailyCount').innerText = j.daily.count;
      document.getElementById('quotaText').innerText = j.daily.count + ' / 250';
    }
  }catch(e){}
}

document.getElementById('addBtn').addEventListener('click', async ()=>{
  const pwd = document.getElementById('pwd').value.trim();
  const days = document.getElementById('days').value;
  if(!pwd){ showAlertHTML('<strong style="color:#ffbaba">Password required</strong>', false); return; }
  const res = await fetch('/api/add',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:pwd,days:days})});
  const j = await res.json();
  if(j.ok){
    const html = '<div><strong>✅ Create Account Successfully</strong><div style="margin-top:6px">Server IP: <strong>'+j.server_ip+'</strong></div><div>Password: <strong>'+j.password+'</strong></div><div>Expired Date: <strong>'+j.expire+'</strong></div><div class="alert-actions"><button data-label="Copy IP" data-copy="'+j.server_ip+'">Copy IP</button><button data-label="Copy Password" data-copy="'+j.password+'">Copy Password</button><button data-label="Copy Expiry" data-copy="'+j.expire+'">Copy Expiry</button></div></div>';
    showAlertHTML(html,true);
    document.getElementById('pwd').value = '';
    document.getElementById('totalAccount').innerText = j.total;
    document.getElementById('totalOffline').innerText = j.expired;
    document.getElementById('dailyCount').innerText = j.daily.count;
    document.getElementById('quotaText').innerText = j.daily.count + ' / 250';
  } else {
    showAlertHTML('<strong style="color:#ffbaba">Error: '+(j.error||'unknown')+'</strong>', false);
  }
});

document.getElementById('bulkBtn').addEventListener('click', async ()=>{
  const raw = document.getElementById('pwd').value.trim();
  if(!raw){ showAlertHTML('<strong style="color:#ffbaba">Please paste comma separated passwords for bulk add</strong>', false); return; }
  const arr = raw.split(',').map(s=>s.trim()).filter(Boolean);
  if(arr.length===0){ showAlertHTML('<strong style="color:#ffbaba">No valid passwords found</strong>', false); return; }
  const days = document.getElementById('days').value;
  // send to server bulk endpoint
  const res = await fetch('/api/bulk',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({passwords:arr,days:days})});
  const j = await res.json();
  if(j.ok){
    // show added list with copy buttons per password (but limit display to first 50)
    let listHtml = '<strong>✅ Bulk add completed. Added: '+j.added.length+'</strong><div style="margin-top:8px">';
    j.added.slice(0,50).forEach(item=>{
      listHtml += '<div style="margin-top:6px" class="alert-card"><div>Password: <strong>'+item.password+'</strong></div><div>Expire: <strong>'+item.expire+'</strong></div><div class="alert-actions"><button data-label="Copy Password" data-copy="'+item.password+'">Copy Password</button><button data-label="Copy Expiry" data-copy="'+item.expire+'">Copy Expiry</button></div></div>';
    });
    listHtml += '</div>';
    showAlertHTML(listHtml,true);
    document.getElementById('pwd').value = '';
    document.getElementById('totalAccount').innerText = j.total;
    document.getElementById('totalOffline').innerText = j.expired;
    document.getElementById('dailyCount').innerText = j.daily.count;
    document.getElementById('quotaText').innerText = j.daily.count + ' / 250';
  } else {
    showAlertHTML('<strong style="color:#ffbaba">Bulk Error: '+(j.error||'unknown')+'</strong>', false);
  }
});

// initial refresh every 10s
refreshStats();
setInterval(refreshStats,10000);
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
systemctl restart zivpn-panel.service || true

# Friendly summary printed at end
IP="$(ip -4 addr show ${IFACE} | grep -Po 'inet \K[\d.]+' | head -1 || echo 127.0.0.1)"
NC='\033[0m'
PINK='\033[1;35m'
GREEN='\033[1;32m'
echo -e "\n${PINK}=== ZIVPN Admin Panel Installed (HTTP) ===${NC}"
echo -e "${GREEN}Admin Panel: http://${IP}:8000${NC}"
echo -e "${GREEN}Admin Username: ${ADMIN_USER}${NC}"
echo -e "${GREEN}Admin Password: ${ADMIN_PASS}${NC}"
echo -e "\nDonate For More Servers 😁"
echo -e "\nMenu (top-right): Donate | Contact Admin"
echo -e "\n(If port 8000 is blocked, allow it in your firewall.)"
