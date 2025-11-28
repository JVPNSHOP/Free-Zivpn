#!/bin/bash
# ZIVPN UDP Module installer + Admin Panel (Flask)
# Integrated features:
# - original zivpn binary install
# - flask admin panel at :8000 with signup/login (admin signup via panel)
# - create password expiry = 5 days
# - JS popup alert on password creation with VPS IP, password, expire date, copy buttons
# - daily cleanup timer for expired passwords
# RUN THIS AS root

set -e

echo -e "==> Starting ZIVPN UDP installer + Admin Panel setup"

echo -e "\n==> 1) System update"
apt-get update -y
apt-get upgrade -y

echo -e "\n==> 2) Stop existing zivpn service (if any)"
if systemctl list-units --full -all | grep -q zivpn.service; then
  systemctl stop zivpn.service || true
fi

echo -e "\n==> 3) Download UDP Service binary"
wget -q https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-amd64 -O /usr/local/bin/zivpn || { echo "Failed to download zivpn binary"; exit 1; }
chmod +x /usr/local/bin/zivpn

mkdir -p /etc/zivpn
wget -q https://raw.githubusercontent.com/zahidbd2/udp-zivpn/main/config.json -O /etc/zivpn/config.json || true

echo -e "\n==> 4) Generate cert files if not exist"
if [ ! -f /etc/zivpn/zivpn.key ] || [ ! -f /etc/zivpn/zivpn.crt ]; then
  openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 \
    -subj "/C=US/ST=California/L=Los Angeles/O=Example Corp/OU=IT Department/CN=zivpn" \
    -keyout "/etc/zivpn/zivpn.key" -out "/etc/zivpn/zivpn.crt"
fi

echo -e "\n==> 5) Kernel tuning"
sysctl -w net.core.rmem_max=16777216 >/dev/null 2>&1 || true
sysctl -w net.core.wmem_max=16777216 >/dev/null 2>&1 || true

echo -e "\n==> 6) Create systemd service for zivpn"
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

systemctl daemon-reload
systemctl enable zivpn.service
systemctl start zivpn.service || true

echo -e "\n==> 7) IPTABLES / UFW rules"
IFACE=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1 || echo eth0)
iptables -t nat -A PREROUTING -i "$IFACE" -p udp --dport 6000:19999 -j DNAT --to-destination :5667 || true
if command -v ufw >/dev/null 2>&1; then
  ufw allow 6000:19999/udp || true
  ufw allow 5667/udp || true
fi
rm -f zi.* >/dev/null 2>&1 || true

echo -e "\n==> 8) Prompt for initial ZIVPN UDP Passwords (optional)"
read -p "Enter passwords separated by commas, example: pass1,pass2 (Press enter for Default 'zi'): " input_config
if [ -n "$input_config" ]; then
  IFS=',' read -r -a config <<< "$input_config"
  if [ ${#config[@]} -eq 1 ]; then
    config+=(${config[0]})
  fi
else
  config=("zi")
fi
new_config_str="\"config\": [$(printf "\"%s\"," "${config[@]}" | sed 's/,$//')]"
if grep -q "\"config\"" /etc/zivpn/config.json 2>/dev/null; then
  sed -i -E "s/\"config\": ?\[[^\]]*\]/${new_config_str}/g" /etc/zivpn/config.json || true
else
  # fallback: append config key
  jq '. + {config: ['"$(printf '"%s",' "${config[@]}" | sed 's/,$//')"']}' /etc/zivpn/config.json >/tmp/config.json 2>/dev/null || true
  if [ -f /tmp/config.json ]; then mv /tmp/config.json /etc/zivpn/config.json; fi
fi

systemctl restart zivpn.service || true

echo -e "\n==> 9) Installing Admin Panel (Flask) for managing users & passwords"

ADMIN_DIR="/opt/zivpn-admin"
mkdir -p "$ADMIN_DIR"
chown root:root "$ADMIN_DIR"
chmod 755 "$ADMIN_DIR"

apt-get install -y python3 python3-venv python3-pip sqlite3 >/dev/null 2>&1 || true

python3 -m venv "$ADMIN_DIR/venv"
"$ADMIN_DIR/venv/bin/pip" install --upgrade pip >/dev/null 2>&1 || true
"$ADMIN_DIR/venv/bin/pip" install flask flask_login passlib[bcrypt] psutil jinja2 pytz sqlalchemy >/dev/null 2>&1 || true

DB_PATH="/etc/zivpn/admin.sqlite"
mkdir -p /etc/zivpn
if [ ! -f "$DB_PATH" ]; then
  sqlite3 "$DB_PATH" "VACUUM;" >/dev/null 2>&1 || true
fi
chown root:root "$DB_PATH"
chmod 640 "$DB_PATH"

# Write Flask app
cat <<'PY' > "$ADMIN_DIR/app.py"
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import sqlite3, os, hashlib, datetime, uuid, json, subprocess, psutil, pytz
from passlib.hash import bcrypt

APP_ROOT = os.path.dirname(os.path.abspath(__file__))
DB = "/etc/zivpn/admin.sqlite"
CONFIG_JSON = "/etc/zivpn/config.json"

app = Flask(__name__, static_folder='static', template_folder='templates')
app.secret_key = os.environ.get("ZIVPN_ADMIN_SECRET","zivpnsecret_"+str(uuid.uuid4()))

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

def get_db():
    conn = sqlite3.connect(DB, detect_types=sqlite3.PARSE_DECLTYPES|sqlite3.PARSE_COLNAMES)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password_hash TEXT,
        created_at TIMESTAMP
    )''')
    cur.execute('''CREATE TABLE IF NOT EXISTS vpn_passwords (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        password TEXT,
        created_at TIMESTAMP,
        expire_at TIMESTAMP
    )''')
    cur.execute('''CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        email TEXT,
        message TEXT,
        created_at TIMESTAMP
    )''')
    conn.commit()
    conn.close()

init_db()

class User(UserMixin):
    def __init__(self, id, username):
        self.id = id
        self.username = username

@login_manager.user_loader
def load_user(user_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, username FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    conn.close()
    if row:
        return User(row['id'], row['username'])
    return None

@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route("/signup", methods=["GET","POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if not username or not password:
            flash("username & password required")
            return redirect(url_for('signup'))
        conn = get_db()
        try:
            conn.execute("INSERT INTO users (username,password_hash,created_at) VALUES (?,?,?)",
                         (username, bcrypt.hash(password), datetime.datetime.utcnow()))
            conn.commit()
            flash("Account created. Please login.")
            return redirect(url_for('login'))
        except Exception as e:
            flash("username already exists or error")
            return redirect(url_for('signup'))
        finally:
            conn.close()
    return render_template("signup.html")

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method=="POST":
        username = request.form.get("username")
        password = request.form.get("password")
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT id,password_hash FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
        conn.close()
        if row and bcrypt.verify(password, row['password_hash']):
            user = User(row['id'], username)
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid credentials")
            return redirect(url_for('login'))
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route("/dashboard")
@login_required
def dashboard():
    utcnow = datetime.datetime.utcnow().replace(tzinfo=pytz.utc)
    server_time_utc = utcnow.strftime("%Y-%m-%d %H:%M:%S UTC")
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    cpu_percent = psutil.cpu_percent(interval=0.5)
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) as cnt FROM vpn_passwords")
    total_create = cur.fetchone()['cnt']
    cur.execute("SELECT COUNT(*) as cnt FROM vpn_passwords WHERE expire_at <= ?", (datetime.datetime.utcnow(),))
    offline_count = cur.fetchone()['cnt']
    cur.execute("SELECT id,password,created_at,expire_at FROM vpn_passwords ORDER BY id DESC LIMIT 20")
    recent = cur.fetchall()
    conn.close()
    return render_template("dashboard.html",
                           server_time=server_time_utc,
                           cpu_percent=cpu_percent,
                           mem_total=mem.total, mem_used=mem.used, mem_free=mem.available,
                           disk_total=disk.total, disk_used=disk.used, disk_free=disk.free,
                           total_create=total_create, offline_count=offline_count, recent=recent)

@app.route("/create_password", methods=["GET","POST"])
@login_required
def create_password():
    if request.method=="POST":
        password = request.form.get("password").strip()
        if not password:
            flash("Please provide a password")
            return redirect(url_for('create_password'))
        created = datetime.datetime.utcnow()
        expire = created + datetime.timedelta(days=5)  # **5 days expiry**
        conn = get_db()
        cur = conn.cursor()
        cur.execute("INSERT INTO vpn_passwords (password,created_at,expire_at) VALUES (?,?,?)",
                    (password, created, expire))
        conn.commit()
        conn.close()
        # update config.json -> add the password
        try:
            with open(CONFIG_JSON,'r') as f:
                cfg = json.load(f)
        except Exception:
            cfg = {}
        cfg.setdefault("config", [])
        if password not in cfg["config"]:
            cfg["config"].append(password)
            try:
                with open(CONFIG_JSON,'w') as f:
                    json.dump(cfg, f, indent=2)
                subprocess.run(["systemctl","restart","zivpn.service"], check=False)
            except Exception as e:
                app.logger.exception("Failed to write config.json: %s", e)
        # get server public IP for display
        try:
            import urllib.request
            ip = urllib.request.urlopen("https://ipv4.icanhazip.com", timeout=5).read().decode().strip()
        except Exception:
            ip = request.host.split(':')[0]
        expire_str = expire.strftime("%d-%m-%Y %H:%M UTC")
        # render a small page that triggers JS alert with details then redirect to dashboard
        return render_template("create_password_success.html", vpn_ip=ip, password=password, expire_date=expire_str)
    return render_template("create_password.html")

@app.route("/accounts")
@login_required
def accounts():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id,password,created_at,expire_at FROM vpn_passwords ORDER BY id DESC")
    rows = cur.fetchall()
    conn.close()
    return render_template("accounts.html", accounts=rows)

@app.route("/contact", methods=["GET","POST"])
@login_required
def contact():
    if request.method=="POST":
        name = request.form.get("name","")
        email = request.form.get("email","")
        message = request.form.get("message","")
        conn = get_db()
        cur = conn.cursor()
        cur.execute("INSERT INTO messages (name,email,message,created_at) VALUES (?,?,?,?)",
                    (name,email,message,datetime.datetime.utcnow()))
        conn.commit()
        conn.close()
        flash("Message sent to admin (stored)")
        return redirect(url_for('dashboard'))
    return render_template("contact.html")

@app.route("/donate")
@login_required
def donate():
    donate_link = os.environ.get("ZIVPN_DONATE_LINK", "https://example.com/donate")
    return render_template("donate.html", donate_link=donate_link)

@app.route("/_cleanup_expired")
@login_required
def cleanup():
    now = datetime.datetime.utcnow()
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT password FROM vpn_passwords WHERE expire_at <= ?", (now,))
    expired = [r['password'] for r in cur.fetchall()]
    conn.close()
    try:
        with open(CONFIG_JSON,'r') as f:
            cfg = json.load(f)
    except Exception:
        cfg = {}
    cfg.setdefault("config", [])
    initial = list(cfg["config"])
    cfg["config"] = [p for p in cfg["config"] if p not in expired]
    if cfg["config"] != initial:
        with open(CONFIG_JSON,'w') as f:
            json.dump(cfg, f, indent=2)
        subprocess.run(["systemctl","restart","zivpn.service"], check=False)
    return jsonify({"removed": expired}), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
PY

# Templates
TEMPL_DIR="$ADMIN_DIR/templates"
mkdir -p "$TEMPL_DIR"

# base.html
cat > "$TEMPL_DIR/base.html" <<'HTM'
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>ZIVPN Admin</title>
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <style>
    body{font-family:system-ui,Arial;background:#f7f7f9;color:#111;margin:0;padding:0}
    .topbar{display:flex;justify-content:space-between;align-items:center;padding:10px 20px;background:#111;color:white}
    .container{padding:20px}
    .card{background:white;padding:15px;border-radius:8px;box-shadow:0 2px 6px rgba(0,0,0,0.08);margin-bottom:12px}
    a.button{background:#0b74de;color:white;padding:8px 12px;border-radius:6px;text-decoration:none}
    .menu a{color:white;margin-left:12px;text-decoration:none}
    table{width:100%;border-collapse:collapse}
    th,td{padding:8px;border-bottom:1px solid #eee;text-align:left}
    .small{font-size:12px;color:#666}
  </style>
</head>
<body>
  <div class="topbar">
    <div><strong>ZIVPN Admin Panel</strong></div>
    <div class="menu">
      {% if current_user.is_authenticated %}
        <a href="{{ url_for('donate') }}" class="menu-link">Donate</a>
        <a href="{{ url_for('contact') }}" class="menu-link">Contact Admin</a>
        <a href="{{ url_for('logout') }}" class="menu-link">Logout</a>
      {% else %}
        <a href="{{ url_for('login') }}">Login</a>
        <a href="{{ url_for('signup') }}">Signup</a>
      {% endif %}
    </div>
  </div>
  <div class="container">
    {% with messages = get_flashed_messages() %}
      {% if messages %}
        <div class="card small">
          {% for m in messages %}<div>{{ m }}</div>{% endfor %}
        </div>
      {% endif %}
    {% endwith %}
    {% block content %}{% endblock %}
  </div>
</body>
</html>
HTM

# login.html
cat > "$TEMPL_DIR/login.html" <<'HTM'
{% extends "base.html" %}
{% block content %}
<div class="card">
  <h3>Login</h3>
  <form method="post">
    <div><label>Username</label><br><input name="username"></div>
    <div><label>Password</label><br><input type="password" name="password"></div>
    <div style="margin-top:10px"><button type="submit" class="button">Login</button></div>
  </form>
  <p class="small">Don't have an account? <a href="{{ url_for('signup') }}">Signup</a></p>
</div>
{% endblock %}
HTM

# signup.html
cat > "$TEMPL_DIR/signup.html" <<'HTM'
{% extends "base.html" %}
{% block content %}
<div class="card">
  <h3>Signup</h3>
  <form method="post">
    <div><label>Username</label><br><input name="username"></div>
    <div><label>Password</label><br><input type="password" name="password"></div>
    <div style="margin-top:10px"><button type="submit" class="button">Create account</button></div>
  </form>
</div>
{% endblock %}
HTM

# dashboard.html
cat > "$TEMPL_DIR/dashboard.html" <<'HTM'
{% extends "base.html" %}
{% block content %}
<h2>Dashboard</h2>
<div class="card">
  <div><strong>Server Time:</strong> {{ server_time }}</div>
  <div><strong>CPU Usage:</strong> {{ cpu_percent }}%</div>
  <div><strong>Memory:</strong> {{ (mem_used/1024/1024)|round(0) }} MB used / {{ (mem_total/1024/1024)|round(0) }} MB</div>
  <div><strong>Disk:</strong> {{ (disk_used/1024/1024/1024)|round(1) }} GB used / {{ (disk_total/1024/1024/1024)|round(1) }} GB</div>
</div>

<div class="card">
  <div><strong>Total Created Accounts:</strong> {{ total_create }}</div>
  <div><strong>Total Offline (expired) Accounts:</strong> {{ offline_count }}</div>
  <div style="margin-top:10px"><a class="button" href="{{ url_for('create_password') }}">Create Password (5 days)</a>
  <a style="margin-left:10px" href="{{ url_for('accounts') }}">View Accounts</a></div>
</div>

<div class="card">
  <h3>Recent Accounts</h3>
  <table>
    <tr><th>ID</th><th>Password</th><th>Created</th><th>Expire</th></tr>
    {% for r in recent %}
      <tr>
        <td>{{ r['id'] }}</td>
        <td>{{ r['password'] }}</td>
        <td>{{ r['created_at'] }}</td>
        <td>{{ r['expire_at'] }}</td>
      </tr>
    {% endfor %}
  </table>
</div>
{% endblock %}
HTM

# create_password.html
cat > "$TEMPL_DIR/create_password.html" <<'HTM'
{% extends "base.html" %}
{% block content %}
<div class="card">
  <h3>Create VPN Password (will expire in 5 days)</h3>
  <form method="post" id="createForm">
    <div><label>Password (plain text for users)</label><br><input name="password" id="pwdField"></div>
    <div style="margin-top:10px"><button type="submit" class="button">Create</button></div>
  </form>
</div>
{% endblock %}
HTM

# create_password_success.html -> triggers JS alert and redirect
cat > "$TEMPL_DIR/create_password_success.html" <<'HTM'
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Password Created</title>
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <style>
    body{font-family:system-ui,Arial;background:#f7f7f9;color:#111;margin:0;padding:20px}
    .card{background:white;padding:20px;border-radius:8px;box-shadow:0 2px 6px rgba(0,0,0,0.08)}
    .btn{padding:8px 10px;border-radius:6px;border:0;background:#0b74de;color:white;cursor:pointer}
    .info{white-space:pre-wrap;font-family:monospace}
  </style>
</head>
<body>
  <div class="card">
    <h3>Password Created</h3>
    <div class="info" id="infoBox">
Create Account Successfully ✅

✅ VPS IP : {{ vpn_ip }}
✅ Password : {{ password }}
✅ Expire Date : {{ expire_date }}
✅ One Password For 1 Device
    </div>
    <div style="margin-top:12px">
      <button class="btn" id="copyAll">Copy All</button>
      <button class="btn" id="copyIP">Copy IP</button>
      <button class="btn" id="copyPass">Copy Password</button>
      <button class="btn" id="goDash">Go to Dashboard</button>
    </div>
  </div>

<script>
function copyText(text){
  navigator.clipboard.writeText(text).then(function(){
    alert("Copied to clipboard");
  }, function(){
    alert("Copy failed");
  });
}

document.getElementById('copyAll').addEventListener('click', function(){
  copyText(document.getElementById('infoBox').innerText);
});
document.getElementById('copyIP').addEventListener('click', function(){
  copyText("{{ vpn_ip }}");
});
document.getElementById('copyPass').addEventListener('click', function(){
  copyText("{{ password }}");
});
document.getElementById('goDash').addEventListener('click', function(){
  window.location.href = "/dashboard";
});

// Also show immediate alert as requested
alert(
`Create Account Successfully ✅

✅ VPS IP : {{ vpn_ip }}
✅ Password : {{ password }}
✅ Expire Date : {{ expire_date }}
✅ One Password For 1 Device`
);
</script>
</body>
</html>
HTM

# accounts.html
cat > "$TEMPL_DIR/accounts.html" <<'HTM'
{% extends "base.html" %}
{% block content %}
<div class="card">
  <h3>All Accounts</h3>
  <table>
    <tr><th>ID</th><th>Password</th><th>Created</th><th>Expire</th></tr>
    {% for a in accounts %}
      <tr>
        <td>{{ a['id'] }}</td><td>{{ a['password'] }}</td><td>{{ a['created_at'] }}</td><td>{{ a['expire_at'] }}</td>
      </tr>
    {% endfor %}
  </table>
</div>
{% endblock %}
HTM

# contact.html
cat > "$TEMPL_DIR/contact.html" <<'HTM'
{% extends "base.html" %}
{% block content %}
<div class="card">
  <h3>Contact Admin</h3>
  <form method="post">
    <div><label>Your name</label><br><input name="name"></div>
    <div><label>Your email</label><br><input name="email"></div>
    <div><label>Message</label><br><textarea name="message" rows="5"></textarea></div>
    <div style="margin-top:10px"><button type="submit" class="button">Send</button></div>
  </form>
</div>
{% endblock %}
HTM

# donate.html
cat > "$TEMPL_DIR/donate.html" <<'HTM'
{% extends "base.html" %}
{% block content %}
<div class="card">
  <h3>Donate</h3>
  <p>If you wish to donate, visit: <a href="{{ donate_link }}" target="_blank">{{ donate_link }}</a></p>
</div>
{% endblock %}
HTM

chown -R root:root "$ADMIN_DIR"
chmod -R 755 "$ADMIN_DIR"

# systemd service for admin panel
cat <<'SERVICE' > /etc/systemd/system/zivpn-admin.service
[Unit]
Description=ZIVPN Admin Panel (Flask)
After=network.target

[Service]
User=root
WorkingDirectory=/opt/zivpn-admin
Environment=PATH=/opt/zivpn-admin/venv/bin
ExecStart=/opt/zivpn-admin/venv/bin/python /opt/zivpn-admin/app.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable zivpn-admin.service
systemctl start zivpn-admin.service || true

# cleanup timer
cat <<'CLEAN' > /etc/systemd/system/zivpn-cleanup.service
[Unit]
Description=ZIVPN cleanup expired passwords

[Service]
Type=oneshot
ExecStart=/bin/bash -lc '/opt/zivpn-admin/venv/bin/python - <<PY
import urllib.request, sys
try:
    urllib.request.urlopen("http://127.0.0.1:8000/_cleanup_expired", timeout=10).read()
except:
    pass
PY'
CLEAN

cat <<'TIMER' > /etc/systemd/system/zivpn-cleanup.timer
[Unit]
Description=Run ZIVPN cleanup daily

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
TIMER

systemctl daemon-reload
systemctl enable --now zivpn-cleanup.timer || true

echo -e "\n==> Final notes and printing access info"

SERVER_IP=$(curl -s ipv4.icanhazip.com || echo "YOUR_SERVER_IP")
echo ""
echo "=============================================="
echo " ZIVPN UDP + ADMIN PANEL INSTALLED SUCCESS"
echo "=============================================="
echo " Admin Panel   : http://$SERVER_IP:8000"
echo " Admin Username: (please signup via the panel)"
echo " Admin Password: (create via signup)"
echo "=============================================="
echo "To access the panel: visit http://$SERVER_IP:8000 and Signup to create your admin account."
echo "Create Password button will produce a popup alert and copy buttons as requested."
echo "Database: /etc/zivpn/admin.sqlite"
echo "Config JSON: /etc/zivpn/config.json"
echo ""
echo "Installation complete."
