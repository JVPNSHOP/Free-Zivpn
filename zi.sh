#!/bin/bash
# zi.sh - ZIVPN UDP installer + Admin Web Panel (colored cards, 3D animated text, day options 1/3/5/7)
set -e

echo -e "\n=== Updating server ==="
sudo apt-get update && sudo apt-get upgrade -y

echo -e "\n=== Stopping existing zivpn service (if any) ==="
systemctl stop zivpn.service 1> /dev/null 2> /dev/null || true
systemctl stop zivpn-panel.service 1> /dev/null 2> /dev/null || true

echo -e "\n=== Downloading UDP Service ==="
wget -q https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-amd64 -O /usr/local/bin/zivpn || true
chmod +x /usr/local/bin/zivpn || true

mkdir -p /etc/zivpn
mkdir -p /var/lib/zivpn
echo -e "\n=== Downloading default config.json (if missing) ==="
if [ ! -f /etc/zivpn/config.json ]; then
  wget -q https://raw.githubusercontent.com/zahidbd2/udp-zivpn/main/config.json -O /etc/zivpn/config.json || echo '{"config":["zi"]}' > /etc/zivpn/config.json
fi

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

# Prompt for initial ZIVPN passwords (comma separated)
echo -e "\n=== ZIVPN UDP Passwords ==="
read -p "Enter passwords separated by commas, example: pass1,pass2 (Press enter for Default 'zi'): " input_config
if [ -n "$input_config" ]; then
    IFS=',' read -r -a rawarr <<< "$input_config"
    config=()
    for v in "${rawarr[@]}"; do
      vv="$(echo "$v" | sed -E 's/^[[:space:]]+//;s/[[:space:]]+$//')"
      if [ -n "$vv" ]; then
        config+=("$vv")
      fi
    done
    if [ ${#config[@]} -eq 0 ]; then
      config=("zi")
    fi
else
    config=("zi")
fi

# Create a small python script to update config.json atomically with provided passwords
py_pw_array=$(printf '"%s",' "${config[@]}" | sed 's/,$//')
cat > /tmp/update_zivpn_config.py <<PY
import json, os
cfgpath = "/etc/zivpn/config.json"
pwds = [${py_pw_array}]
try:
    with open(cfgpath,'r') as f:
        cfg = json.load(f)
except Exception:
    cfg = {}
existing = cfg.get("config", [])
if not isinstance(existing, list):
    existing = []
for p in pwds:
    if p not in existing:
        existing.append(p)
cfg["config"] = existing
tmp = cfgpath + ".tmp"
with open(tmp,'w') as f:
    json.dump(cfg,f,indent=2)
os.replace(tmp,cfgpath)
print("Updated /etc/zivpn/config.json")
PY

python3 /tmp/update_zivpn_config.py || true
rm -f /tmp/update_zivpn_config.py

echo -e "\n=== Enabling and starting zivpn.service ==="
systemctl daemon-reload
systemctl enable zivpn.service
systemctl restart zivpn.service || true

# Firewall / iptables
IFACE=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1 || true)
if [ -n "$IFACE" ]; then
  echo "Using interface: $IFACE"
  iptables -t nat -A PREROUTING -i "${IFACE}" -p udp --dport 6000:19999 -j REDIRECT --to-ports 5667 2> /dev/null || true
fi
ufw allow 6000:19999/udp 2> /dev/null || true
ufw allow 5667/udp 2> /dev/null || true

rm -f zi.* 1> /dev/null 2> /dev/null || true

echo -e "\n=== ZIVPN UDP Installed ==="

##########################################
# Admin Web Panel (Flask, HTTP:8000)
##########################################

echo -e "\n=== Installing Python, pip, virtualenv ==="
apt-get install -y python3 python3-venv python3-pip >/dev/null 2>&1 || true

PANEL_DIR=/opt/zivpn_panel
mkdir -p "${PANEL_DIR}"
chown -R root:root "${PANEL_DIR}"

echo -e "\n=== Admin panel credentials ==="
read -p "Enter Admin Username (default: admin): " ADMIN_USER
ADMIN_USER=${ADMIN_USER:-admin}
read -p "Enter Admin Password (default: admin): " ADMIN_PASS
ADMIN_PASS=${ADMIN_PASS:-admin}

mkdir -p /var/lib/zivpn
cat > /var/lib/zivpn/panel_auth.json <<EOF
{"user":"${ADMIN_USER}","pass":"${ADMIN_PASS}"}
EOF
chmod 600 /var/lib/zivpn/panel_auth.json

ACCOUNTS_FILE=/var/lib/zivpn/accounts.json
DAILY_FILE=/var/lib/zivpn/daily_count.json

[ -f "${ACCOUNTS_FILE}" ] || echo "[]" > "${ACCOUNTS_FILE}"
[ -f "${DAILY_FILE}" ] || echo "{\"date\":\"$(date +%F)\",\"count\":0}" > "${DAILY_FILE}"

# Flask app
cat > "${PANEL_DIR}/app.py" <<'PY'
from flask import Flask, render_template, request, redirect, jsonify, session, url_for
import json, os, datetime, subprocess

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
    try:
        days = int(data.get("days",3))
    except:
        days = 3
    if not pwd:
        return jsonify({"ok":False,"error":"password required"}),400
    daily = read_json(DAILY_FILE, {"date": datetime.date.today().isoformat(), "count": 0})
    if daily.get("date") != datetime.date.today().isoformat():
        daily = {"date": datetime.date.today().isoformat(), "count": 0}
    if daily["count"] >= 250:
        return jsonify({"ok":False,"error":"daily limit reached (250)"}),402
    now = datetime.datetime.now()
    expire = (now + datetime.timedelta(days=days)).isoformat()
    accounts = read_json(ACCOUNTS_FILE, [])
    accounts.append({"password": pwd, "created": now.isoformat(), "expire": expire, "active": True})
    write_json(ACCOUNTS_FILE, accounts)

    # update config.json safely
    try:
        cfg = read_json(CONFIG_JSON, {})
        existing = cfg.get("config", [])
        if not isinstance(existing, list):
            existing = []
        if pwd not in existing:
            existing.append(pwd)
        cfg["config"] = existing
        write_json(CONFIG_JSON, cfg)
        restart_zivpn()
    except Exception as e:
        pass

    daily["count"] = daily.get("count",0) + 1
    write_json(DAILY_FILE, daily)
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
    app.run(host="0.0.0.0", port=8000)
PY

mkdir -p "${PANEL_DIR}/templates"
mkdir -p "${PANEL_DIR}/static"

# LOGIN PAGE (with logo)
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
    .box{width:100%;max-width:420px;background:var(--card);padding:22px;border-radius:18px;box-shadow:0 12px 40px rgba(2,6,23,.35)}
    h2{margin:10px 0 12px 0;font-size:20px}
    .hint{font-size:13px;color:var(--muted);background:rgba(0,0,0,0.03);padding:10px;border-radius:8px;margin-bottom:12px}
    input{width:100%;padding:12px;margin:8px 0;border-radius:10px;border:1px solid rgba(0,0,0,0.08);background:transparent;color:var(--text);box-sizing:border-box}
    button{width:100%;padding:12px;border-radius:10px;border:0;background:var(--accent);color:#fff;font-weight:700}
    .footer{display:flex;justify-content:space-between;margin-top:12px;color:var(--muted);font-size:13px}
  </style>
</head>
<body data-theme="dark">
  <div class="box">
    <div style="display:flex;align-items:center;gap:10px">
      <img src="https://raw.githubusercontent.com/JVPNSHOP/Admin-Zivpn/main/image/z.png" alt="ZIVPN Logo" style="width:32px;height:32px;border-radius:8px">
      <div style="font-weight:800;font-size:18px">ZIVPN Admin</div>
    </div>
    <h2>Sign in</h2>
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

# DASHBOARD PAGE
cat > "${PANEL_DIR}/templates/dashboard.html" <<'HTML'
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>ZIVPN Panel</title>
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <style>
    :root{
      --bg:#0b1120; --card:#020617; --card-soft:#111827; --accent:#fb7185; --muted:#94a3b8; --text:#e5e7eb; --glass:rgba(148,163,184,.24);
    }
    [data-theme="light"]{
      --bg:#f3f4f6; --card:#ffffff; --card-soft:#e5e7eb; --accent:#ef5b8c; --muted:#475569; --text:#0b1120; --glass:rgba(148,163,184,.25);
    }
    *{box-sizing:border-box}
    body{font-family:Inter,Arial;margin:0;background:radial-gradient(circle at top,#1f2937 0,#020617 55%,#020617 100%);color:var(--text);min-height:100vh;display:flex;flex-direction:column}
    [data-theme="light"] body{background:radial-gradient(circle at top,#e5e7eb 0,#f3f4f6 50%,#e5e7eb 100%);}
    header{display:flex;justify-content:space-between;align-items:center;padding:10px 16px;border-bottom:1px solid rgba(15,23,42,.5);background:rgba(15,23,42,.92);backdrop-filter:blur(10px);position:sticky;top:0;z-index:20}
    [data-theme="light"] header{background:rgba(249,250,251,.9);border-bottom-color:rgba(148,163,184,.4);}
    .brand{display:flex;align-items:center;gap:8px;font-weight:800;font-size:18px}
    .brand img{width:26px;height:26px;border-radius:6px}
    .menu-btn{background:var(--card-soft);border:1px solid rgba(148,163,184,.35);padding:6px 12px;border-radius:999px;color:var(--text);cursor:pointer;font-size:13px;display:flex;align-items:center;gap:6px}
    .dropdown{position:absolute;right:16px;top:52px;background:var(--card);padding:8px;border-radius:14px;box-shadow:0 18px 40px rgba(15,23,42,.65);display:none;min-width:190px;border:1px solid rgba(148,163,184,.3)}
    .dropdown a, .dropdown button{display:flex;align-items:center;gap:8px;padding:8px 10px;text-decoration:none;color:var(--text);border-radius:10px;background:transparent;border:0;width:100%;text-align:left;cursor:pointer;font-size:14px}
    .dropdown a:hover, .dropdown button:hover{background:rgba(148,163,184,.15);}
    .pill{font-size:11px;padding:2px 8px;border-radius:999px;background:rgba(148,163,184,.18);color:var(--muted)}
    .container{padding:16px;display:grid;grid-template-columns:1.2fr 0.9fr;gap:18px;flex:1}
    @media(max-width:900px){ .container{grid-template-columns:1fr; padding:12px} .right-col{order:2} .left-col{order:1}}
    .card{background:linear-gradient(145deg,rgba(15,23,42,.98),rgba(15,23,42,.9));padding:16px;border-radius:20px;box-shadow:0 20px 40px rgba(15,23,42,.8);border:1px solid rgba(148,163,184,.35)}
    [data-theme="light"] .card{background:linear-gradient(145deg,#ffffff,#f9fafb);box-shadow:0 16px 30px rgba(148,163,184,.25);}
    .stat-row{display:flex;justify-content:space-between;align-items:center;padding:10px 0;border-bottom:1px dashed rgba(148,163,184,.35);}
    .stat-label{display:flex;align-items:center;gap:8px;font-size:14px}
    .dot{width:10px;height:10px;border-radius:999px}
    .dot-blue{background:#38bdf8}
    .dot-green{background:#22c55e}
    .dot-purple{background:#a855f7}
    .dot-orange{background:#fb923c}
    .dot-pink{background:#f472b6}
    .dot-yellow{background:#eab308}
    .stat-value{font-variant-numeric:tabular-nums;font-size:14px}
    .small{font-size:13px;color:var(--muted)}
    input,button,select{width:100%;padding:12px;border-radius:12px;border:1px solid rgba(148,163,184,.45);background:rgba(15,23,42,.7);color:var(--text);outline:none;font-size:14px}
    [data-theme="light"] input,[data-theme="light"] select{background:#f9fafb;color:var(--text)}
    button{background:var(--accent);border:0;color:#fff;font-weight:700}
    .field-row{display:flex;gap:10px;align-items:center}
    .icon-badge{width:46px;height:46px;border-radius:16px;background:radial-gradient(circle at 30% 20%,#fde68a,transparent 55%),#1d293b;display:flex;align-items:center;justify-content:center;font-size:22px;box-shadow:0 10px 25px rgba(234,179,8,.4)}
    [data-theme="light"] .icon-badge{background:radial-gradient(circle at 30% 20%,#f97316,transparent 55%),#111827;color:#fefce8}
    .note{margin-top:8px;color:var(--muted);font-size:13px}
    .alerts{margin-top:10px}
    .alert-card{padding:10px;border-radius:12px;background:rgba(22,163,74,.12);margin-bottom:8px;color:var(--text);border:1px solid rgba(34,197,94,.35)}
    .alert-actions{display:flex;gap:8px;margin-top:8px}
    .alert-actions button{
      flex:1;padding:8px;font-size:12px;border-radius:999px;border:0;background:var(--accent);color:#fff;cursor:pointer;font-weight:700;
    }
    .alert-error{background:rgba(248,113,113,.12);border:1px solid rgba(248,113,113,.35);color:var(--text);}
    [data-theme="light"] .alert-card{color:var(--text)}
    footer{padding:10px 0 14px 0}
    .marquee-wrap{perspective:900px;overflow:hidden}
    .marquee{display:inline-block;padding:12px 30px;border-radius:999px;background:linear-gradient(120deg,#ec4899,#f97316,#22c55e,#3b82f6,#ec4899);background-size:400% 400%;transform:rotateX(18deg) translateZ(0);animation:marqueeMove 18s linear infinite, gradientShift 10s ease-in-out infinite;white-space:nowrap;font-weight:800;color:#0b1120;box-shadow:0 18px 40px rgba(15,23,42,.8)}
    [data-theme="light"] .marquee{color:#0b1120;box-shadow:0 12px 28px rgba(148,163,184,.45);}
    @keyframes marqueeMove{0%{transform:translateX(100%) rotateX(18deg)}100%{transform:translateX(-100%) rotateX(18deg)}}
    @keyframes gradientShift{0%{background-position:0% 50%}50%{background-position:100% 50%}100%{background-position:0% 50%}}
    .stat-ic{font-size:16px;opacity:0.95}
    .ip-box{padding:10px;border-radius:12px;background:rgba(15,23,42,.75);border:1px solid rgba(148,163,184,.4);color:var(--text);overflow:hidden;white-space:nowrap;text-overflow:ellipsis}
    [data-theme="light"] .ip-box{background:#f9fafb;color:var(--text);border:1px solid rgba(148,163,184,.4)}
    .copy-btn{width:auto;padding:8px 12px;border-radius:999px;font-size:12px;background:var(--accent);color:#fff;border:0;cursor:pointer}
  </style>
</head>
<body data-theme="dark">
  <header>
    <div class="brand">
      <img src="https://raw.githubusercontent.com/JVPNSHOP/Admin-Zivpn/main/image/z.png" alt="logo">
      <span>ZIVPN Admin</span>
      <span class="pill">UDP Panel</span>
    </div>
    <div style="position:relative">
      <button id="menuBtn" class="menu-btn"><span>Menu</span> ▾</button>
      <div id="dropdown" class="dropdown" aria-hidden="true">
        <a href="http://donate.jvpn.shop/" target="_blank" rel="noreferrer"><span style="font-size:18px">🏦</span><span>Donate</span></a>
        <a href="https://m.me/juehtet2025" target="_blank" rel="noreferrer"><span style="font-size:18px">✉️</span><span>Contact Admin</span></a>
        <button id="themeToggle"><span style="font-size:18px">🌓</span><span id="themeLabel">Switch to Light</span></button>
      </div>
    </div>
  </header>

  <div class="container">
    <div class="left-col">
      <div class="card" role="region" aria-label="Server Overview">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
          <h3 style="margin:0">Server Overview</h3>
          <span class="pill">Live</span>
        </div>
        <div class="stat-row">
          <div class="stat-label"><span class="stat-ic">⏰</span><span>Server Time</span></div>
          <div class="stat-value">{{ stats.time }}</div>
        </div>
        <div class="stat-row">
          <div class="stat-label"><span class="stat-ic">⚙️</span><span>CPU Load</span></div>
          <div class="stat-value">{{ stats.load }}</div>
        </div>
        <div class="stat-row">
          <div class="stat-label"><span class="stat-ic">🧠</span><span>RAM Usage</span></div>
          <div class="stat-value">{{ stats.mem }}</div>
        </div>
        <div class="stat-row">
          <div class="stat-label"><span class="stat-ic">💾</span><span>Storage</span></div>
          <div class="stat-value">{{ stats.disk }}</div>
        </div>
        <div class="stat-row">
          <div class="stat-label"><span class="stat-ic">👥</span><span>Total Account</span></div>
          <div class="stat-value" id="totalAccount">{{ total }}</div>
        </div>
        <div class="stat-row" style="border-bottom:none">
          <div class="stat-label"><span class="stat-ic">🔌</span><span>Total Offline</span></div>
          <div class="stat-value" id="totalOffline">{{ expired }}</div>
        </div>
      </div>

      <div style="height:14px"></div>

      <div class="card" role="region" aria-label="Add Password">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
          <h3 style="margin:0">Add Password</h3>
          <span class="pill">Auto 1 / 3 / 5 / 7 days</span>
        </div>
        <div style="display:grid;gap:10px">
          <div class="field-row">
            <div class="icon-badge">🔐</div>
            <input id="pwd" placeholder="password to add (required)" autocomplete="off">
          </div>

          <div>
            <label class="small">Expire in</label>
            <select id="days">
              <option value="3">🔒 3 days (default)</option>
              <option value="1">⏳ 1 day</option>
              <option value="5">📅 5 days</option>
              <option value="7">📆 7 days (max)</option>
            </select>
          </div>

          <button id="addBtn">Add Password</button>

          <div class="note">Today's usage: <strong id="dailyCount">{{ daily.count }}</strong> / 250</div>
          <div id="alerts" class="alerts" aria-live="polite"></div>
        </div>
      </div>
    </div>

    <div class="right-col">
      <aside class="card" role="complementary">
        <h3 style="margin-top:0">Actions</h3>
        <div class="small">Server IP</div>
        <div style="display:flex;gap:8px;margin-top:6px;align-items:center">
          <div id="serverIpBox" class="ip-box" title="{{ server_ip }}">{{ server_ip }}</div>
          <button id="copyIpBtn" class="copy-btn" onclick="copyToClipboard(document.getElementById('serverIpBox').innerText)">Copy</button>
        </div>

        <div style="height:10px"></div>
        <div class="small">Daily Quota</div>
        <div style="margin-top:6px;font-variant-numeric:tabular-nums" id="quotaText">{{ daily.count }} / 250</div>
      </aside>
    </div>
  </div>

  <footer>
    <div class="marquee-wrap">
      <div class="marquee">
        Server တွေအများကြီးထပ်ထည့်ပေးစေလိုပါက Donate ကိုနှိပ်ပြီးတယောက်ကို 10/20 ကူညီနိုင်ပါတယ်ခင်ဗျား — Server တွေအများကြီးထပ်ထည့်ပေးစေလိုပါက Donate ကိုနှိပ်ပြီးတယောက်ကို 10/20 ကူညီနိုင်ပါတယ်ခင်ဗျား
      </div>
    </div>
  </footer>

<script>
/* dropdown */
const menuBtn = document.getElementById('menuBtn');
const dropdown = document.getElementById('dropdown');
menuBtn.addEventListener('click', ()=> {
  dropdown.style.display = dropdown.style.display === 'block' ? 'none' : 'block';
});
document.addEventListener('click', (e)=> {
  if(!menuBtn.contains(e.target) && !dropdown.contains(e.target)) dropdown.style.display = 'none';
});

/* theme toggle */
const body = document.body;
const themeToggle = document.getElementById('themeToggle');
const themeLabel = document.getElementById('themeLabel');
function applyTheme(t){
  if(t==='light'){ body.setAttribute('data-theme','light'); themeLabel.innerText='Switch to Dark'; }
  else { body.setAttribute('data-theme','dark'); themeLabel.innerText='Switch to Light'; }
  localStorage.setItem('zivpn_theme',t);
}
applyTheme(localStorage.getItem('zivpn_theme') || 'dark');
themeToggle.addEventListener('click', ()=> {
  const cur = body.getAttribute('data-theme')==='light' ? 'dark' : 'light';
  applyTheme(cur);
});

/* robust copy function with fallback */
function fallbackCopyTextToClipboard(text) {
  return new Promise((resolve, reject) => {
    try {
      const textArea = document.createElement("textarea");
      textArea.value = text;
      textArea.style.position = "fixed";
      textArea.style.top = 0;
      textArea.style.left = 0;
      textArea.style.width = '2em';
      textArea.style.height = '2em';
      textArea.style.padding = 0;
      textArea.style.border = 'none';
      textArea.style.outline = 'none';
      textArea.style.boxShadow = 'none';
      textArea.style.background = 'transparent';
      document.body.appendChild(textArea);
      textArea.focus();
      textArea.select();
      try {
        const successful = document.execCommand('copy');
        document.body.removeChild(textArea);
        if(successful) resolve(true);
        else reject(new Error('execCommand failed'));
      } catch (err) {
        document.body.removeChild(textArea);
        reject(err);
      }
    } catch(e) {
      reject(e);
    }
  });
}

function copyToClipboard(text){
  const t = String(text).trim();
  if(!t){
    showTempAlert('Nothing to copy', true);
    return;
  }
  if(navigator.clipboard && navigator.clipboard.writeText){
    navigator.clipboard.writeText(t).then(()=> {
      showTempAlert('Copied to clipboard', false);
    }).catch(()=> {
      fallbackCopyTextToClipboard(t).then(()=> showTempAlert('Copied to clipboard', false)).catch(()=> showTempAlert('Copy failed', true));
    });
  } else {
    fallbackCopyTextToClipboard(t).then(()=> showTempAlert('Copied to clipboard', false)).catch(()=> showTempAlert('Copy failed', true));
  }
}

function showTempAlert(msg, isError){
  const a=document.getElementById('alerts');
  const el=document.createElement('div');
  el.className='alert-card';
  if(isError) el.classList.add('alert-error');
  el.innerText=msg;
  a.prepend(el);
  setTimeout(()=>el.remove(),2500);
}

/* add password */
document.getElementById('addBtn').addEventListener('click', async ()=>{
  const pwd = document.getElementById('pwd').value.trim();
  const days = document.getElementById('days').value;
  if(!pwd){
    const a=document.getElementById('alerts');
    const el=document.createElement('div'); el.className='alert-card alert-error'; el.innerText='Password required';
    a.prepend(el); setTimeout(()=>el.remove(),3000); return;
  }
  try{
    const res = await fetch('/api/add',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:pwd,days:days})});
    const j = await res.json();
    if(j.ok){
      const a=document.getElementById('alerts');
      const el=document.createElement('div'); el.className='alert-card';
      el.innerHTML='<div style="font-weight:800;margin-bottom:6px">✅ Create Account Successfully</div><div>Server IP: <strong>'+j.server_ip+'</strong></div><div>Password: <strong>'+j.password+'</strong></div><div>Expired: <strong>'+j.expire+'</strong></div><div class="alert-actions" style="margin-top:10px"><button data-copy="'+j.server_ip+'">Copy IP</button><button data-copy="'+j.password+'">Copy Password</button><button data-copy="'+j.expire+'">Copy Expiry</button></div>';
      a.prepend(el);
      el.querySelectorAll('[data-copy]').forEach(btn=>{
        btn.addEventListener('click',()=>{
          const text = btn.getAttribute('data-copy') || '';
          copyToClipboard(text);
          const prev = btn.innerText;
          btn.innerText='Copied';
          setTimeout(()=>btn.innerText=prev,1200);
        });
      });
      document.getElementById('pwd').value='';
      document.getElementById('totalAccount').innerText=j.total;
      document.getElementById('totalOffline').innerText=j.expired;
      document.getElementById('dailyCount').innerText=j.daily.count;
      document.getElementById('quotaText').innerText=j.daily.count+' / 250';
    }else{
      const a=document.getElementById('alerts'); const el=document.createElement('div'); el.className='alert-card alert-error'; el.innerText='Error: '+(j.error||'unknown'); a.prepend(el); setTimeout(()=>el.remove(),5000);
    }
  }catch(e){
    const a=document.getElementById('alerts'); const el=document.createElement('div'); el.className='alert-card alert-error'; el.innerText='Request failed'; a.prepend(el); setTimeout(()=>el.remove(),5000);
  }
});

/* refresh stats */
async function refreshStats(){
  try{
    const res = await fetch('/api/stats');
    const j = await res.json();
    if(j.ok){
      document.getElementById('totalAccount').innerText=j.total;
      document.getElementById('totalOffline').innerText=j.expired;
      document.getElementById('dailyCount').innerText=j.daily.count;
      document.getElementById('quotaText').innerText=j.daily.count+' / 250';
    }
  }catch(e){}
}
refreshStats(); setInterval(refreshStats,10000);
</script>
</body>
</html>
HTML

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

IP="$(ip -4 addr show ${IFACE} | grep -Po 'inet \K[\d.]+' | head -1 || echo 127.0.0.1)"
NC='\033[0m'
PINK='\033[1;35m'
GREEN='\033[1;32m'
echo -e "\n${PINK}=== ZIVPN Admin Panel Installed (HTTP) ===${NC}"
echo -e "${GREEN}Admin Panel: http://${IP}:8000${NC}"
echo -e "${GREEN}Admin Username: ${ADMIN_USER}${NC}"
echo -e "${GREEN}Admin Password: ${ADMIN_PASS}${NC}"
echo -e "\nDonate For More Servers 😁"
echo -e "\nDonate:  http://donate.jvpn.shop/"
echo -e "Contact: https://m.me/juehtet2025"
echo -e "\n(If port 8000 is blocked, allow it in your firewall.)"
