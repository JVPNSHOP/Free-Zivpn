#!/bin/bash
# zi.sh - ZIVPN UDP installer + Admin Web Panel (final UI tweaks)
# - Fixes Light mode readability (no dark overlay hiding text)
# - Menu cleaned up, Donate (bank icon), Contact (mail icon)
# - Theme toggle is a button
# - Footer 3D running text kept but with strong contrast for both themes
# Usage: chmod +x zi.sh && sudo ./zi.sh
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
# - Add-only: /api/add
# - Clean Menu: Donate (bank icon), Contact Admin (mail), Theme toggle button
# - Light mode readability fixes (no dark overlay that hides text)
# - Footer 3D running text with high contrast on both themes
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

# Create Flask app (served over HTTP)
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

# Create templates and static files (final UI tweaks)
mkdir -p "${PANEL_DIR}/templates"
mkdir -p "${PANEL_DIR}/static"

# login.html
cat > "${PANEL_DIR}/templates/login.html" <<'HTML'
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>ZIVPN Admin Login</title>
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <style>
    :root{--bg:#0f172a;--card:#ffffff10;--accent:#fb7185;--muted:#94a3b8;--text:#fff}
    [data-theme="light"]{--bg:#f7fafc;--card:#ffffff;--accent:#ef5b8c;--muted:#475569;--text:#0b1220}
    body{margin:0;font-family:Inter,Arial;background:var(--bg);color:var(--text);display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px}
    .box{width:100%;max-width:420px;background:var(--card);padding:22px;border-radius:14px;box-shadow:0 8px 30px rgba(2,6,23,.15)}
    h2{margin:0 0 12px 0;font-size:20px}
    .hint{font-size:13px;color:var(--muted);background:rgba(0,0,0,0.02);padding:10px;border-radius:8px;margin-bottom:12px}
    input{width:100%;padding:12px;margin:8px 0;border-radius:8px;border:1px solid rgba(0,0,0,0.06);background:transparent;color:var(--text);box-sizing:border-box}
    button{width:100%;padding:12px;border-radius:10px;border:0;background:var(--accent);color:#fff;font-weight:700}
    .footer{display:flex;justify-content:space-between;margin-top:12px;color:var(--muted);font-size:13px}
  </style>
</head>
<body data-theme="dark">
  <div class="box">
    <h2>ZIVPN Admin</h2>
    <div class="hint">
      Admin Username: <strong>{{ admin_user }}</strong><br>
      Admin Password: <strong>{{ admin_pass }}</strong><br>
      (Credentials shown here as requested)
    </div>
    {% if error %}
      <div style="color:#d33;margin-bottom:8px">{{ error }}</div>
    {% endif %}
    <form method="post" action="/panel">
      <input name="username" placeholder="Username" value="{{ admin_user }}" autocomplete="username">
      <input name="password" placeholder="Password" value="{{ admin_pass }}" type="password" autocomplete="current-password">
      <button type="submit">Login</button>
    </form>
    <div class="footer">
      <div>Donate 🏦</div>
      <div>Contact ✉️</div>
    </div>
  </div>
</body>
</html>
HTML

# dashboard.html (final adjustments for light-mode readability + menu + icons + footer text contrast)
cat > "${PANEL_DIR}/templates/dashboard.html" <<'HTML'
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>ZIVPN Panel</title>
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <style>
    :root{
      --bg:#0f172a; --card:#071028; --card-2:#0b1220; --accent:#fb7185; --muted:#94a3b8; --text:#fff; --glass: rgba(255,255,255,0.04);
    }
    [data-theme="light"]{
      --bg:#f7fafc; --card:#ffffff; --card-2:#f3f4f6; --accent:#ef5b8c; --muted:#475569; --text:#0b1220; --glass: rgba(11,17,32,0.03);
    }
    *{box-sizing:border-box}
    body{font-family:Inter,Arial;margin:0;background:var(--bg);color:var(--text);min-height:100vh;display:flex;flex-direction:column}
    header{display:flex;justify-content:space-between;align-items:center;padding:12px 16px;border-bottom:1px solid rgba(0,0,0,0.06);position:sticky;top:0;background:var(--card-2);z-index:20}
    .brand{font-weight:800;font-size:18px}
    .menu-btn{background:transparent;border:1px solid rgba(255,255,255,0.06);padding:8px 12px;border-radius:10px;color:var(--text);cursor:pointer}
    .dropdown{position:absolute;right:16px;top:56px;background:var(--card);padding:8px;border-radius:10px;box-shadow:0 8px 30px rgba(2,6,23,.2);display:none;min-width:160px}
    .dropdown a, .dropdown button{display:flex;align-items:center;gap:8px;padding:8px 10px;text-decoration:none;color:var(--text);border-radius:8px;background:transparent;border:0;width:100%;text-align:left;cursor:pointer}
    .container{padding:18px;display:grid;grid-template-columns:1fr 360px;gap:18px;flex:1;background:transparent}
    @media(max-width:900px){ .container{grid-template-columns:1fr; padding:12px} .right-col{order:2} .left-col{order:1}}
    .card{background:linear-gradient(180deg,var(--card),var(--card-2));padding:14px;border-radius:12px;box-shadow:0 6px 20px rgba(0,0,0,.4)}
    [data-theme="light"] .card{background:linear-gradient(180deg,var(--card),var(--card-2));box-shadow:0 6px 20px rgba(0,0,0,0.06)}
    .stat{display:flex;justify-content:space-between;padding:12px 0;border-bottom:1px dashed var(--glass);align-items:center}
    .small{font-size:13px;color:var(--muted)}
    input,button,select,textarea{width:100%;padding:12px;border-radius:10px;border:1px solid rgba(0,0,0,0.06);background:transparent;color:var(--text);outline:none}
    button{background:var(--accent);border:0;color:#fff;font-weight:700}
    .grid-2{display:grid;grid-template-columns:1fr 1fr;gap:10px}
    .note{margin-top:8px;color:var(--muted);font-size:13px}
    .iconsmall{display:inline-block;width:22px;text-align:center;margin-right:10px}
    .alerts{margin-top:10px}
    .alert-card{padding:10px;border-radius:10px;background:var(--glass);margin-bottom:8px;color:var(--text)}
    .alert-actions{display:flex;gap:8px;margin-top:8px}
    footer{padding:12px;background:transparent}
    /* 3D running text with high contrast for both themes */
    .marquee-wrap{perspective:600px;overflow:hidden;padding:6px 0}
    .marquee{display:inline-block;padding:12px 24px;border-radius:10px;background:linear-gradient(90deg,var(--card-2),var(--card));transform:translateZ(0);animation:marquee 18s linear infinite;white-space:nowrap;font-weight:700;color:var(--text)}
    @keyframes marquee{0%{transform:translateX(100%) rotateX(18deg)}100%{transform:translateX(-100%) rotateX(18deg)}}
  </style>
</head>
<body data-theme="dark">
  <header>
    <div class="brand">ZIVPN Admin</div>
    <div style="position:relative">
      <button id="menuBtn" class="menu-btn" aria-haspopup="true" aria-expanded="false">Menu ▾</button>
      <div id="dropdown" class="dropdown" role="menu" aria-hidden="true">
        <button id="donateLink" title="Donate"><span style="font-size:18px">🏦</span> Donate</button>
        <button id="contactLink" title="Contact Admin"><span style="font-size:18px">✉️</span> Contact Admin</button>
        <button id="themeToggle" title="Toggle theme"><span id="themeLabel">Switch to Light</span></button>
      </div>
    </div>
  </header>

  <div class="container">
    <div class="left-col">
      <div class="card" role="region" aria-label="Server Overview">
        <h3>Server Overview</h3>
        <div class="stat"><div><span class="iconsmall">🕒</span> Server Time</div><div>{{ stats.time }}</div></div>
        <div class="stat"><div><span class="iconsmall">⚙️</span> CPU Load</div><div style="text-align:right">{{ stats.load }}</div></div>
        <div class="stat"><div><span class="iconsmall">🧠</span> RAM Usage</div><div style="text-align:right">{{ stats.mem }}</div></div>
        <div class="stat"><div><span class="iconsmall">💽</span> Storage</div><div style="text-align:right">{{ stats.disk }}</div></div>
        <div class="stat"><div><span class="iconsmall">👥</span> Total Account</div><div id="totalAccount">{{ total }}</div></div>
        <div class="stat"><div><span class="iconsmall">⚠️</span> Total Offline</div><div id="totalOffline">{{ expired }}</div></div>
      </div>

      <div style="height:14px"></div>

      <div class="card" role="region" aria-label="Add Password">
        <h3>Add Password</h3>
        <div style="display:grid;gap:10px">
          <div style="display:flex;gap:8px;align-items:center">
            <div style="width:44px;height:44px;border-radius:10px;background:var(--glass);display:flex;align-items:center;justify-content:center;font-size:20px">🔐</div>
            <input id="pwd" placeholder="password to add (required)" autocomplete="off" aria-label="Password">
          </div>

          <div>
            <label class="small">Expire in</label>
            <select id="days" aria-label="Expire days">
              <option value="3">🔒 3 days (default)</option>
              <option value="1">⏳ 1 day</option>
              <option value="7">📆 7 days</option>
              <option value="10">🔁 10 days (max)</option>
            </select>
          </div>

          <button id="addBtn" aria-label="Add Password">Add Password</button>

          <div class="note">Today's usage: <strong id="dailyCount">{{ daily.count }}</strong> / 250</div>
          <div id="alerts" class="alerts" aria-live="polite"></div>
        </div>
      </div>

    </div>

    <div class="right-col">
      <aside class="card" role="complementary" aria-label="Actions">
        <h3 style="margin-top:0">Actions</h3>
        <div class="small">Server IP</div>
        <div style="display:flex;gap:8px;margin-top:6px;align-items:center">
          <div id="serverIpBox" style="flex:1;padding:10px;background:var(--glass);border-radius:8px">{{ server_ip }}</div>
          <div style="cursor:pointer;padding:8px;border-radius:8px;background:var(--card-2);color:var(--text)" onclick="copyToClipboard(document.getElementById('serverIpBox').innerText)">Copy</div>
        </div>

        <div style="height:10px"></div>
        <div class="small">Daily Quota</div>
        <div style="margin-top:6px" id="quotaText">{{ daily.count }} / 250</div>

      </aside>
    </div>
  </div>

  <footer>
    <div class="marquee-wrap">
      <div class="marquee" id="marq">
        Server တွေအများကြီးထပ်ထည့်ပေးစေလိုပါက Donate ကိုနှိပ်ပြီးတယောက်ကို 10/20 ကူညီနိုင်ပါတယ်ခင်ဗျား — Donate နှိပ်ပြီး 10/20 ကူညီပေးပါ။
      </div>
    </div>
  </footer>

<script>
/* Dropdown menu */
const menuBtn = document.getElementById('menuBtn');
const dropdown = document.getElementById('dropdown');
menuBtn.addEventListener('click', ()=> {
  const show = dropdown.style.display !== 'block';
  dropdown.style.display = show ? 'block' : 'none';
  menuBtn.setAttribute('aria-expanded', show ? 'true' : 'false');
});
document.addEventListener('click', (e)=> {
  if(!menuBtn.contains(e.target) && !dropdown.contains(e.target)) dropdown.style.display = 'none';
});

/* Theme toggle (dark/light) as a button */
const body = document.body;
const themeToggle = document.getElementById('themeToggle');
const themeLabel = document.getElementById('themeLabel');
function applyTheme(t){
  if(t === 'light'){ body.setAttribute('data-theme','light'); themeLabel.innerText='Switch to Dark'; }
  else { body.setAttribute('data-theme','dark'); themeLabel.innerText='Switch to Light'; }
  localStorage.setItem('zivpn_theme', t);
}
const saved = localStorage.getItem('zivpn_theme') || 'dark';
applyTheme(saved);
themeToggle.addEventListener('click', (e)=> {
  const cur = body.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
  applyTheme(cur);
});

/* Donate & Contact handlers (placeholders) */
document.getElementById('donateLink').addEventListener('click', ()=>{
  alert('Donate: Bank transfer / payment link can be added here.');
});
document.getElementById('contactLink').addEventListener('click', ()=>{
  alert('Contact Admin: put admin contact (Telegram/Email) here.');
});

/* Copy function */
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

/* Add password handler */
document.getElementById('addBtn').addEventListener('click', async ()=>{
  const pwd = document.getElementById('pwd').value.trim();
  const days = document.getElementById('days').value;
  if(!pwd){
    const a=document.getElementById('alerts');
    const el = document.createElement('div'); el.className='alert-card'; el.innerText = 'Password required';
    a.prepend(el); setTimeout(()=>el.remove(),3000); return;
  }
  try{
    const res = await fetch('/api/add',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:pwd,days:days})});
    const j = await res.json();
    if(j.ok){
      const a=document.getElementById('alerts');
      const el=document.createElement('div'); el.className='alert-card';
      el.innerHTML = '<div><strong>✅ Create Account Successfully</strong></div><div>Server IP: <strong>'+j.server_ip+'</strong></div><div>Password: <strong>'+j.password+'</strong></div><div>Expired: <strong>'+j.expire+'</strong></div><div class="alert-actions"><button data-copy="'+j.server_ip+'">Copy IP</button><button data-copy="'+j.password+'">Copy Password</button><button data-copy="'+j.expire+'">Copy Expiry</button></div>';
      a.prepend(el);
      el.querySelectorAll('[data-copy]').forEach(btn=> btn.addEventListener('click', ()=> { navigator.clipboard.writeText(btn.getAttribute('data-copy')); btn.innerText='Copied'; setTimeout(()=>btn.innerText='Copy',1200); }));
      document.getElementById('pwd').value='';
      document.getElementById('totalAccount').innerText = j.total;
      document.getElementById('totalOffline').innerText = j.expired;
      document.getElementById('dailyCount').innerText = j.daily.count;
      document.getElementById('quotaText').innerText = j.daily.count + ' / 250';
    } else {
      const a=document.getElementById('alerts'); const el=document.createElement('div'); el.className='alert-card'; el.innerText = 'Error: ' + (j.error || 'unknown'); a.prepend(el); setTimeout(()=>el.remove(),5000);
    }
  } catch(e){
    const a=document.getElementById('alerts'); const el=document.createElement('div'); el.className='alert-card'; el.innerText='Request failed'; a.prepend(el); setTimeout(()=>el.remove(),5000);
  }
});

/* Live refresh basic stats */
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
refreshStats(); setInterval(refreshStats,10000);
</script>
</body>
</html>
HTML

# Create venv & install Flask
echo -e "\n=== Creating Python venv and installing Flask ==="
python3 -m venv "${PANEL_DIR}/venv"
"${PANEL_DIR}/venv/bin/pip" install --upgrade pip >/dev/null 2>&1 || true
"${PANEL_DIR}/venv/bin/pip" install flask >/dev/null 2>&1 || true

# systemd service
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

# Summary
IP="$(ip -4 addr show ${IFACE} | grep -Po 'inet \K[\d.]+' | head -1 || echo 127.0.0.1)"
NC='\033[0m'
PINK='\033[1;35m'
GREEN='\033[1;32m'
echo -e "\n${PINK}=== ZIVPN Admin Panel Installed (HTTP) ===${NC}"
echo -e "${GREEN}Admin Panel: http://${IP}:8000${NC}"
echo -e "${GREEN}Admin Username: ${ADMIN_USER}${NC}"
echo -e "${GREEN}Admin Password: ${ADMIN_PASS}${NC}"
echo -e "\nDonate For More Servers 😁"
echo -e "\nMenu (top-right): Donate 🏦 | Contact ✉️ | Theme Toggle"
echo -e "\n(If port 8000 is blocked, allow it in your firewall.)"
