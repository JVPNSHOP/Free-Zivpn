#!/bin/bash
# install-zivpn-full.sh
# Fully fixed ZIVPN UDP + Admin Panel installer
# - Stops existing zivpn service before download (avoid "Text file busy")
# - BusyBox / Android terminal compatible (no read -s)
# - Truncates admin password to bcrypt 72-byte limit
# - Guards against apt/dpkg locks and venv issues
# - Auto-creates admin user, shows creds (temp), auto-deletes creds after 24h
# - Create-password expiry = 5 days with popup + copy buttons
# - Optional nginx + Let's Encrypt (provide domain)
# Run as root

set -e
export DEBIAN_FRONTEND=noninteractive

echo "=== ZIVPN FULL INSTALLER (fixed) ==="

# helper: safe apt/dpkg
safe_apt_prepare() {
  echo "[*] Ensuring apt/dpkg not blocked..."
  rm -f /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/cache/apt/archives/lock || true
  dpkg --configure -a || true
  apt --fix-broken install -y || true
}

# Prompt admin creds (plain read)
read -p "Admin username (default: admin): " ADMIN_USER
ADMIN_USER=${ADMIN_USER:-admin}
echo -n "Admin password (default: admin123): "
read ADMIN_PASS
ADMIN_PASS=${ADMIN_PASS:-admin123}

read -p "Domain for HTTPS/NGINX (leave blank to skip): " DOMAIN
if [ -n "$DOMAIN" ]; then
  read -p "Email for Let's Encrypt (default admin@$DOMAIN): " LE_EMAIL
  LE_EMAIL=${LE_EMAIL:-admin@"$DOMAIN"}
fi

# Truncate admin password to 72 bytes for bcrypt safety (utf-8 safe)
ADMIN_PASS_TRUNC=$(
python3 - <<PY
s = """$ADMIN_PASS""".encode('utf-8')[:72]
print(s.decode('utf-8', errors='ignore'))
PY
)
ADMIN_PASS="$ADMIN_PASS_TRUNC"

echo "[*] Admin username: $ADMIN_USER"
echo "[*] (password shown at end and saved temporarily in /etc/zivpn/admin_creds.txt)"

# Prepare apt/dpkg
safe_apt_prepare
echo "[*] Updating packages..."
apt-get update -y
apt-get upgrade -y

# Ensure essential packages
safe_apt_prepare
apt-get install -y python3 python3-venv python3-distutils python3-pip sqlite3 nginx certbot python3-certbot-nginx wget unzip git iptables || true

# Stop and remove any existing zivpn binary/service to avoid "Text file busy"
if systemctl list-units --full -all | grep -q zivpn.service; then
  echo "[*] Stopping existing zivpn service..."
  systemctl stop zivpn.service || true
fi
if [ -f /usr/local/bin/zivpn ]; then
  echo "[*] Removing existing /usr/local/bin/zivpn to allow fresh download..."
  rm -f /usr/local/bin/zivpn || true
fi

# Download zivpn binary with retries and IPv4-only fallback
ZIVPN_BIN_URL="https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-amd64"
DL_OK=0
for i in 1 2 3; do
  echo "[*] Download attempt $i ..."
  if wget -q --timeout=30 --tries=2 --inet4-only -O /usr/local/bin/zivpn "$ZIVPN_BIN_URL"; then
    DL_OK=1
    break
  fi
  sleep 1
done
if [ "$DL_OK" -ne 1 ]; then
  # fallback: try curl IPv4
  if command -v curl >/dev/null 2>&1; then
    echo "[*] Fallback to curl (IPv4)..."
    curl -4 -fsSL "$ZIVPN_BIN_URL" -o /usr/local/bin/zivpn || true
  fi
fi
if [ ! -f /usr/local/bin/zivpn ]; then
  echo "[!] Failed to download zivpn binary from GitHub (network or blocked). Exiting."
  exit 1
fi
chmod +x /usr/local/bin/zivpn

# Ensure /etc/zivpn exists and fetch config.json if possible
mkdir -p /etc/zivpn
wget -q --inet4-only -O /etc/zivpn/config.json https://raw.githubusercontent.com/zahidbd2/udp-zivpn/main/config.json || true

# Self-signed certs for zivpn (if missing)
if [ ! -f /etc/zivpn/zivpn.key ] || [ ! -f /etc/zivpn/zivpn.crt ]; then
  openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 \
    -subj "/C=US/ST=California/L=Los Angeles/O=ZIVPN/OU=IT/CN=zivpn" \
    -keyout /etc/zivpn/zivpn.key -out /etc/zivpn/zivpn.crt >/dev/null 2>&1 || true
fi

# Kernel tuning (best effort)
sysctl -w net.core.rmem_max=16777216 >/dev/null 2>&1 || true
sysctl -w net.core.wmem_max=16777216 >/dev/null 2>&1 || true

# Create systemd service for zivpn
cat >/etc/systemd/system/zivpn.service <<'UNIT'
[Unit]
Description=zivpn UDP Server
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
UNIT

systemctl daemon-reload
systemctl enable --now zivpn.service || true

# IPTABLES / UFW rules for UDP range
IFACE=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1 || echo eth0)
iptables -t nat -C PREROUTING -i "$IFACE" -p udp --dport 6000:19999 -j DNAT --to-destination :5667 2>/dev/null || \
  iptables -t nat -A PREROUTING -i "$IFACE" -p udp --dport 6000:19999 -j DNAT --to-destination :5667 || true

if command -v ufw >/dev/null 2>&1; then
  ufw allow 6000:19999/udp || true
  ufw allow 5667/udp || true
fi

rm -f zi.* >/dev/null 2>&1 || true

# Prompt initial config passwords (optional)
read -p "Enter initial ZIVPN passwords (comma separated) or press Enter to use 'zi': " input_config
if [ -n "$input_config" ]; then
  IFS=',' read -r -a CONFIG_PASS <<< "$input_config"
  if [ ${#CONFIG_PASS[@]} -eq 1 ]; then CONFIG_PASS+=(${CONFIG_PASS[0]}); fi
else
  CONFIG_PASS=("zi")
fi
NEW_CONFIG_STR="\"config\": [$(printf "\"%s\"," "${CONFIG_PASS[@]}" | sed 's/,$//')]"
if grep -q "\"config\"" /etc/zivpn/config.json 2>/dev/null; then
  sed -i -E "s/\"config\": ?\[[^\]]*\]/${NEW_CONFIG_STR}/g" /etc/zivpn/config.json || true
else
  if command -v jq >/dev/null 2>&1; then
    jq '. + {config: ['"$(printf '"%s",' "${CONFIG_PASS[@]}" | sed 's/,$//')"']}' /etc/zivpn/config.json >/tmp/config.json 2>/dev/null || true
    [ -f /tmp/config.json ] && mv /tmp/config.json /etc/zivpn/config.json
  else
    echo -e "\n${NEW_CONFIG_STR}" >> /etc/zivpn/config.json
  fi
fi

systemctl restart zivpn.service || true

# -------------------------
# Install Flask Admin Panel
echo "[*] Installing Flask admin panel..."
ADMIN_DIR="/opt/zivpn-admin"
rm -rf "$ADMIN_DIR"
mkdir -p "$ADMIN_DIR"
chown root:root "$ADMIN_DIR"
chmod 755 "$ADMIN_DIR"

# Ensure venv and distutils packages exist
safe_apt_prepare
apt-get install -y python3-venv python3-distutils || true

# Try create venv; on failure attempt repair and retry
if ! python3 -m venv "$ADMIN_DIR/venv"; then
  echo "[!] venv creation failed; attempting apt/dpkg repair and retry..."
  safe_apt_prepare
  apt-get install -y python3-venv python3-distutils || true
  python3 -m venv "$ADMIN_DIR/venv"
fi

"$ADMIN_DIR/venv/bin/pip" install --upgrade pip >/dev/null 2>&1 || true
"$ADMIN_DIR/venv/bin/pip" install flask flask_login passlib[bcrypt] psutil jinja2 pytz sqlalchemy >/dev/null 2>&1 || true

DB_PATH="/etc/zivpn/admin.sqlite"
mkdir -p /etc/zivpn
if [ ! -f "$DB_PATH" ]; then
  sqlite3 "$DB_PATH" "VACUUM;" >/dev/null 2>&1 || true
fi
chown root:root "$DB_PATH"
chmod 600 "$DB_PATH"

# Save creds file (temporary) - auto-delete later
CREDS_FILE="/etc/zivpn/admin_creds.txt"
echo "username=${ADMIN_USER}" > "$CREDS_FILE"
echo "password=${ADMIN_PASS}" >> "$CREDS_FILE"
chmod 600 "$CREDS_FILE"

# create bcrypt hashed password (via venv Python)
HASHED_PASS=$("$ADMIN_DIR/venv/bin/python3" - <<PY
from passlib.hash import bcrypt
print(bcrypt.hash("$ADMIN_PASS"))
PY
)

# init DB and insert admin
sqlite3 "$DB_PATH" <<SQL
CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password_hash TEXT, created_at TIMESTAMP);
CREATE TABLE IF NOT EXISTS vpn_passwords (id INTEGER PRIMARY KEY AUTOINCREMENT, password TEXT, created_at TIMESTAMP, expire_at TIMESTAMP);
CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, email TEXT, message TEXT, created_at TIMESTAMP);
INSERT OR IGNORE INTO users (username, password_hash, created_at) VALUES ("${ADMIN_USER}", "${HASHED_PASS}", datetime('now'));
SQL

# Write Flask app
cat > "$ADMIN_DIR/app.py" <<'PY'
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import sqlite3, os, datetime, json, subprocess, psutil, pytz
from passlib.hash import bcrypt

DB = "/etc/zivpn/admin.sqlite"
CONFIG_JSON = "/etc/zivpn/config.json"
CREDS_FILE = "/etc/zivpn/admin_creds.txt"

app = Flask(__name__, static_folder='static', template_folder='templates')
app.secret_key = os.environ.get("ZIVPN_ADMIN_SECRET","zivpnsecret_"+str(os.urandom(8)))

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

def get_db():
    conn = sqlite3.connect(DB, detect_types=sqlite3.PARSE_DECLTYPES|sqlite3.PARSE_COLNAMES)
    conn.row_factory = sqlite3.Row
    return conn

def read_creds():
    data = {}
    try:
        if os.path.exists(CREDS_FILE):
            with open(CREDS_FILE,'r') as f:
                for line in f:
                    if '=' in line:
                        k,v = line.strip().split('=',1)
                        data[k]=v
    except:
        pass
    return data

class User(UserMixin):
    def __init__(self, id, username):
        self.id = id
        self.username = username

@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    row = db.execute("SELECT id,username FROM users WHERE id=?",(user_id,)).fetchone()
    db.close()
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
    if request.method=="POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if not username or not password:
            flash("username & password required")
            return redirect(url_for('signup'))
        db = get_db()
        try:
            db.execute("INSERT INTO users (username,password_hash,created_at) VALUES (?,?,?)",
                       (username, bcrypt.hash(password), datetime.datetime.utcnow()))
            db.commit()
            flash("Account created. Please login.")
            return redirect(url_for('login'))
        except Exception:
            flash("username already exists or error")
            return redirect(url_for('signup'))
        finally:
            db.close()
    return render_template("signup.html")

@app.route("/login", methods=["GET","POST"])
def login():
    admin_creds = read_creds()
    if request.method=="POST":
        username = request.form.get("username")
        password = request.form.get("password")
        db = get_db()
        row = db.execute("SELECT id,password_hash FROM users WHERE username=?", (username,)).fetchone()
        db.close()
        if row and bcrypt.verify(password, row['password_hash']):
            user = User(row['id'], username)
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid credentials")
            return redirect(url_for('login'))
    return render_template("login.html", admin_creds=admin_creds)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route("/dashboard")
@login_required
def dashboard():
    utcnow = datetime.datetime.utcnow().replace(tzinfo=pytz.utc)
    server_time = utcnow.strftime("%Y-%m-%d %H:%M:%S UTC")
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    cpu_percent = psutil.cpu_percent(interval=0.5)
    db = get_db()
    total_create = db.execute("SELECT COUNT(*) as cnt FROM vpn_passwords").fetchone()['cnt']
    offline_count = db.execute("SELECT COUNT(*) as cnt FROM vpn_passwords WHERE expire_at <= ?", (datetime.datetime.utcnow(),)).fetchone()['cnt']
    recent = db.execute("SELECT id,password,created_at,expire_at FROM vpn_passwords ORDER BY id DESC LIMIT 20").fetchall()
    db.close()
    return render_template("dashboard.html", server_time=server_time, cpu_percent=cpu_percent,
                           mem_total=mem.total, mem_used=mem.used, disk_total=disk.total, disk_used=disk.used,
                           total_create=total_create, offline_count=offline_count, recent=recent)

@app.route("/create_password", methods=["GET","POST"])
@login_required
def create_password():
    if request.method=="POST":
        password = request.form.get("password","").strip()
        if not password:
            flash("Please provide a password")
            return redirect(url_for('create_password'))
        created = datetime.datetime.utcnow()
        expire = created + datetime.timedelta(days=5)  # 5 days expiry
        db = get_db()
        db.execute("INSERT INTO vpn_passwords (password,created_at,expire_at) VALUES (?,?,?)",
                   (password, created, expire))
        db.commit()
        db.close()
        # update config.json
        try:
            with open(CONFIG_JSON,'r') as f:
                cfg = json.load(f)
        except:
            cfg = {}
        cfg.setdefault("config", [])
        if password not in cfg["config"]:
            cfg["config"].append(password)
            try:
                with open(CONFIG_JSON,'w') as f:
                    json.dump(cfg, f, indent=2)
                subprocess.run(["systemctl","restart","zivpn.service"], check=False)
            except Exception:
                pass
        # get public ip
        try:
            import urllib.request
            ip = urllib.request.urlopen("https://ipv4.icanhazip.com", timeout=5).read().decode().strip()
        except:
            ip = request.host.split(':')[0]
        expire_str = expire.strftime("%d-%m-%Y %H:%M UTC")
        return render_template("create_password_success.html", vpn_ip=ip, password=password, expire_date=expire_str)
    return render_template("create_password.html")

@app.route("/accounts")
@login_required
def accounts():
    db = get_db()
    rows = db.execute("SELECT id,password,created_at,expire_at FROM vpn_passwords ORDER BY id DESC").fetchall()
    db.close()
    return render_template("accounts.html", accounts=rows)

@app.route("/contact", methods=["GET","POST"])
@login_required
def contact():
    if request.method=="POST":
        name = request.form.get("name","")
        email = request.form.get("email","")
        message = request.form.get("message","")
        db = get_db()
        db.execute("INSERT INTO messages (name,email,message,created_at) VALUES (?,?,?,?)", (name,email,message,datetime.datetime.utcnow()))
        db.commit()
        db.close()
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
    db = get_db()
    expired = [r['password'] for r in db.execute("SELECT password FROM vpn_passwords WHERE expire_at <= ?", (now,)).fetchall()]
    db.close()
    try:
        with open(CONFIG_JSON,'r') as f:
            cfg = json.load(f)
    except:
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
    app.run(host="127.0.0.1", port=8000)
PY

# Templates (login/signup/dashboard/create_password/success/accounts/contact/donate)
TEMPL_DIR="$ADMIN_DIR/templates"
mkdir -p "$TEMPL_DIR"

cat > "$TEMPL_DIR/base.html" <<'HTM'
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>ZIVPN Admin</title>
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <style>
    body{font-family:system-ui,Arial,Helvetica;background:#f4f7fb;color:#0f172a;margin:0;padding:0}
    .topbar{display:flex;justify-content:space-between;align-items:center;padding:12px 20px;background:#0b74de;color:white}
    .container{padding:18px;max-width:1000px;margin:12px auto}
    .card{background:white;padding:18px;border-radius:10px;box-shadow:0 6px 18px rgba(15,23,42,0.06);margin-bottom:14px}
    .btn{background:#0b74de;color:white;padding:8px 12px;border-radius:8px;text-decoration:none;border:0;cursor:pointer}
    .menu a{color:white;margin-left:12px;text-decoration:none}
    table{width:100%;border-collapse:collapse}
    th,td{padding:10px;border-bottom:1px solid #eef2f7;text-align:left}
    .small{font-size:13px;color:#6b7280}
    .creds{background:#0b74de;color:white;padding:12px;border-radius:8px;margin-bottom:12px}
    input,textarea{width:100%;padding:8px;border:1px solid #e6eef8;border-radius:6px}
  </style>
</head>
<body>
  <div class="topbar">
    <div><strong>ZIVPN Admin Panel</strong></div>
    <div class="menu">
      {% if current_user.is_authenticated %}
        <a href="{{ url_for('donate') }}" class="menu-link">Donate</a>
        <a href="{{ url_for('contact') }}" class="menu-link">Contact</a>
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

cat > "$TEMPL_DIR/login.html" <<'HTM'
{% extends "base.html" %}
{% block content %}
{% if admin_creds %}
  <div class="creds">
    <strong>Installer Admin Credentials:</strong><br>
    Username: <code>{{ admin_creds.get('username') }}</code> &nbsp;
    Password: <code>{{ admin_creds.get('password') }}</code>
    <div class="small">(This will auto-delete after 24 hours. Remove manually after first login for security.)</div>
  </div>
{% endif %}
<div class="card">
  <h3>Login</h3>
  <form method="post">
    <div><label>Username</label><br><input name="username" value="{{ admin_creds.get('username') if admin_creds else '' }}"></div>
    <div style="margin-top:8px"><label>Password</label><br><input type="password" name="password" value="{{ admin_creds.get('password') if admin_creds else '' }}"></div>
    <div style="margin-top:12px"><button type="submit" class="btn">Login</button></div>
  </form>
  <p class="small">Don't have an account? <a href="{{ url_for('signup') }}">Signup</a></p>
</div>
{% endblock %}
HTM

cat > "$TEMPL_DIR/signup.html" <<'HTM'
{% extends "base.html" %}
{% block content %}
<div class="card">
  <h3>Signup</h3>
  <form method="post">
    <div><label>Username</label><br><input name="username"></div>
    <div style="margin-top:8px"><label>Password</label><br><input type="password" name="password"></div>
    <div style="margin-top:12px"><button type="submit" class="btn">Create account</button></div>
  </form>
</div>
{% endblock %}
HTM

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
  <div style="margin-top:10px"><a class="btn" href="{{ url_for('create_password') }}">Create Password (5 days)</a>
  <a style="margin-left:10px" class="btn" href="{{ url_for('accounts') }}">View Accounts</a></div>
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

cat > "$TEMPL_DIR/create_password.html" <<'HTM'
{% extends "base.html" %}
{% block content %}
<div class="card">
  <h3>Create VPN Password (will expire in 5 days)</h3>
  <form method="post" id="createForm">
    <div><label>Password (plain text for users)</label><br><input name="password" id="pwdField"></div>
    <div style="margin-top:10px"><button type="submit" class="btn">Create</button></div>
  </form>
</div>
{% endblock %}
HTM

cat > "$TEMPL_DIR/create_password_success.html" <<'HTM'
<!doctype html>
<html><head><meta charset="utf-8"><title>Password Created</title><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="font-family:system-ui,Arial;padding:20px;background:#f7f9fc">
  <div style="max-width:700px;margin:auto;background:white;padding:18px;border-radius:8px;box-shadow:0 6px 18px rgba(0,0,0,0.06)">
    <h3>Password Created</h3>
    <pre id="infoBox" style="font-family:monospace">
Create Account Successfully ✅

✅ VPS IP : {{ vpn_ip }}
✅ Password : {{ password }}
✅ Expire Date : {{ expire_date }}
✅ One Password For 1 Device
    </pre>
    <div style="margin-top:12px">
      <button onclick="copyAll()" style="padding:8px 12px;border-radius:6px;background:#0b74de;color:white;border:0">Copy All</button>
      <button onclick="copyIP()" style="padding:8px 12px;border-radius:6px;background:#0b74de;color:white;border:0">Copy IP</button>
      <button onclick="copyPass()" style="padding:8px 12px;border-radius:6px;background:#0b74de;color:white;border:0">Copy Password</button>
      <button onclick="location.href='/dashboard'" style="padding:8px 12px;border-radius:6px;background:#6b7280;color:white;border:0">Go to Dashboard</button>
    </div>
  </div>
<script>
function copyText(t){navigator.clipboard.writeText(t).then(()=>alert("Copied"),()=>alert("Copy failed"))}
function copyAll(){copyText(document.getElementById('infoBox').innerText)}
function copyIP(){copyText("{{ vpn_ip }}")}
function copyPass(){copyText("{{ password }}")}
alert(`Create Account Successfully ✅

✅ VPS IP : {{ vpn_ip }}
✅ Password : {{ password }}
✅ Expire Date : {{ expire_date }}
✅ One Password For 1 Device`);
</script>
</body></html>
HTM

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

cat > "$TEMPL_DIR/contact.html" <<'HTM'
{% extends "base.html" %}
{% block content %}
<div class="card">
  <h3>Contact Admin</h3>
  <form method="post">
    <div><label>Your name</label><br><input name="name"></div>
    <div style="margin-top:8px"><label>Your email</label><br><input name="email"></div>
    <div style="margin-top:8px"><label>Message</label><br><textarea name="message" rows="5"></textarea></div>
    <div style="margin-top:12px"><button class="btn" type="submit">Send</button></div>
  </form>
</div>
{% endblock %}
HTM

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
cat >/etc/systemd/system/zivpn-admin.service <<'SVC'
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
SVC

systemctl daemon-reload
systemctl enable --now zivpn-admin.service || true

# creds auto-delete timer (24h)
cat >/etc/systemd/system/zivpn-clear-creds.service <<'CLR'
[Unit]
Description=Remove install-created creds file

[Service]
Type=oneshot
ExecStart=/bin/bash -lc 'rm -f /etc/zivpn/admin_creds.txt || true; systemctl restart zivpn-admin.service || true'
CLR

cat >/etc/systemd/system/zivpn-clear-creds.timer <<'TMR'
[Unit]
Description=Run ZIVPN creds cleanup once after 24 hours

[Timer]
OnActiveSec=86400
Persistent=true

[Install]
WantedBy=timers.target
TMR

systemctl daemon-reload
systemctl enable --now zivpn-clear-creds.timer || true

# cleanup expired timer (daily)
cat >/etc/systemd/system/zivpn-cleanup.service <<'CLEAN'
[Unit]
Description=ZIVPN cleanup expired passwords

[Service]
Type=oneshot
ExecStart=/bin/bash -lc 'python3 - <<PY
import urllib.request
try:
    urllib.request.urlopen("http://127.0.0.1:8000/_cleanup_expired", timeout=10).read()
except:
    pass
PY'
CLEAN

cat >/etc/systemd/system/zivpn-cleanup.timer <<'TIMER'
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

# nginx & certbot (optional)
if [ -n "$DOMAIN" ]; then
  echo "[*] Configuring nginx for domain: $DOMAIN"
  cat >/etc/nginx/sites-available/zivpn <<NG
server {
    listen 80;
    server_name $DOMAIN;
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
}
NG
  ln -sf /etc/nginx/sites-available/zivpn /etc/nginx/sites-enabled/zivpn
  rm -f /etc/nginx/sites-enabled/default
  systemctl restart nginx || true

  certbot --nginx -n --agree-tos --email "$LE_EMAIL" -d "$DOMAIN" || echo "[!] certbot failed; check DNS & port 80"
fi

# final info
SERVER_IP=$(curl -s ipv4.icanhazip.com || echo "YOUR_SERVER_IP")
echo
echo "=============================================="
echo " ZIVPN UDP + ADMIN PANEL INSTALLED SUCCESS"
echo "=============================================="
if [ -n "$DOMAIN" ]; then
  echo " Panel URL     : https://$DOMAIN"
else
  echo " Panel URL     : http://$SERVER_IP:8000"
fi
echo " Admin Username: $ADMIN_USER"
echo " Admin Password: $ADMIN_PASS"
echo
echo "• Credentials displayed on login page while /etc/zivpn/admin_creds.txt exists."
echo "• /etc/zivpn/admin_creds.txt will be auto-deleted in 24h. Remove manually after first login:"
echo "  sudo rm -f /etc/zivpn/admin_creds.txt && sudo systemctl restart zivpn-admin.service"
echo "=============================================="
echo "Installation finished."
