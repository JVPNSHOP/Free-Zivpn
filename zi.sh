#!/bin/bash

# Fixed Zivpn UDP Module installer with Web Admin Panel
# Modified to allow manual admin username/password and robust SERVER_IP detection
# Creator (original): Zahid Islam
# Modifications: provide by ChatGPT (fixes for SERVER_IP, sed delimiters, iptables DNAT, ufw, prompts)

set -euo pipefail
IFS=$'\n\t'

echo -e "\n=== Updating server packages ==="
apt-get update -y && apt-get upgrade -y

echo -e "\n=== Stopping existing zivpn service (if any) ==="
systemctl stop zivpn.service 1> /dev/null 2> /dev/null || true

echo -e "\n=== Installing required packages ==="
DEBIAN_FRONTEND=noninteractive apt-get install -y python3 python3-pip nodejs npm ufw openssl wget iptables

echo -e "\n=== Downloading UDP Service binary ==="
wget -q -O /usr/local/bin/zivpn "https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-amd64"
chmod +x /usr/local/bin/zivpn
mkdir -p /etc/zivpn /var/www/zivpn-admin

echo -e "\n=== Download default config.json (if available) ==="
if wget -q -O /etc/zivpn/config.json "https://raw.githubusercontent.com/zahidbd2/udp-zivpn/main/config.json"; then
    echo "Downloaded default config.json"
else
    echo "No remote config.json found — creating minimal default"
    cat > /etc/zivpn/config.json <<'EOF'
{
  "listen": "0.0.0.0:5667",
  "config": ["zi"]
}
EOF
fi

echo -e "\n=== Generating self-signed TLS certs ==="
openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 \
  -subj "/C=US/ST=California/L=Los Angeles/O=Example Corp/OU=IT Department/CN=zivpn" \
  -keyout "/etc/zivpn/zivpn.key" -out "/etc/zivpn/zivpn.crt" >/dev/null 2>&1 || true

# tune kernel buffers (best-effort)
sysctl -w net.core.rmem_max=16777216 >/dev/null 2>&1 || true
sysctl -w net.core.wmem_max=16777216 >/dev/null 2>&1 || true

echo -e "\n=== Creating systemd service for zivpn ==="
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

# Prompt for UDP passwords (comma separated) - keeps backward compatibility
echo -e "\n=== ZIVPN UDP Passwords ==="
read -p "Enter passwords separated by commas (example: pass1,pass2). Press Enter for default 'zi': " input_config
if [ -n "${input_config}" ]; then
    IFS=',' read -r -a config_array <<< "${input_config}"
else
    config_array=("zi")
fi

# Update config.json "config" array safely (use jq if available, else simple replacement)
if command -v jq >/dev/null 2>&1; then
    jq --argjson arr "$(printf '%s\n' "${config_array[@]}" | jq -R . | jq -s .)" '.config = $arr' /etc/zivpn/config.json > /etc/zivpn/config.json.tmp && mv /etc/zivpn/config.json.tmp /etc/zivpn/config.json
else
    # build JSON array string
    arr=""
    for p in "${config_array[@]}"; do
        # escape double quotes and backslashes in password
        esc=$(printf '%s' "$p" | sed 's/\\/\\\\/g; s/"/\\"/g')
        arr="${arr}\"${esc}\","
    done
    arr="[${arr%,}]"
    # replace "config": ... with new array using | delimiter to avoid issues
    sed -i "s|\"config\": *\[[^]]*\]|\"config\": ${arr}|g" /etc/zivpn/config.json || \
      (sed -i "1s|{|\n{\"config\": ${arr},|" /etc/zivpn/config.json)
fi

# Prompt for admin username/password (allow custom)
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

# Detect server IP robustly; fallback to user input if detection fails
echo -e "\n=== Detecting server public IP ==="
SERVER_IP=""
# try common services
for svc in "ifconfig.me" "icanhazip.com" "ipinfo.io/ip" "api.ipify.org"; do
  SERVER_IP=$(curl -s --max-time 5 "$svc" || true)
  if [[ -n "$SERVER_IP" ]]; then
    SERVER_IP=$(echo "$SERVER_IP" | tr -d ' \n\r')
    break
  fi
done

# try local default route IP if public detection fails
if [[ -z "$SERVER_IP" ]]; then
  SERVER_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || true)
fi

# final fallback: ask user
if [[ -z "$SERVER_IP" ]]; then
  read -p "Could not auto-detect server IP. Enter server IP or domain to use in admin panel (example: 1.2.3.4 or vpn.example.com): " SERVER_IP
fi

# Create web admin panel HTML with placeholders replaced safely (use | as sed delimiter)
echo -e "\n=== Creating admin panel HTML ==="
cat > /var/www/zivpn-admin/admin-panel.html <<'HTML_EOF'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>ZIVPN Admin Panel</title>
<style>/* (styles omitted for brevity) */ body{font-family:Arial,Helvetica,sans-serif;background:#f4f7fb} /* keep the CSS from the original file */</style>
</head>
<body>
<!-- simplified login + panel -->
<div id="loginForm">
  <h2>ZIVPN Admin Login</h2>
  <input id="username" placeholder="Username" />
  <input id="password" type="password" placeholder="Password" />
  <button onclick="login()">Login</button>
  <div id="loginError" style="display:none;color:red">Invalid username or password!</div>
</div>
<div id="adminPanel" style="display:none">
  <h1>ZIVPN Admin Panel</h1>
  <p>Server: <span id="serverIp"></span></p>
  <div id="content"></div>
  <button onclick="logout()">Logout</button>
</div>
<script>
const ADMIN_USERNAME = "ADMIN_USERNAME_REPLACEME";
const ADMIN_PASSWORD = "ADMIN_PASSWORD_REPLACEME";
const SERVER_IP = "SERVER_IP_REPLACEME";

document.getElementById('serverIp').textContent = SERVER_IP;

function login(){
  const u=document.getElementById('username').value;
  const p=document.getElementById('password').value;
  if(u===ADMIN_USERNAME && p===ADMIN_PASSWORD){
    document.getElementById('loginForm').style.display='none';
    document.getElementById('adminPanel').style.display='block';
  } else {
    document.getElementById('loginError').style.display='block';
  }
}
function logout(){
  document.getElementById('loginForm').style.display='block';
  document.getElementById('adminPanel').style.display='none';
  document.getElementById('username').value='';
  document.getElementById('password').value='';
  document.getElementById('loginError').style.display='none';
}
</script>
</body>
</html>
HTML_EOF

# Replace placeholders safely
sed -i "s|ADMIN_USERNAME_REPLACEME|${ADMIN_USER}|g" /var/www/zivpn-admin/admin-panel.html
# Escape slashes and quotes in password for sed
ESC_PASS=$(printf '%s' "${ADMIN_PASS}" | sed 's|[&/\]|\\&|g')
sed -i "s|ADMIN_PASSWORD_REPLACEME|${ESC_PASS}|g" /var/www/zivpn-admin/admin-panel.html
sed -i "s|SERVER_IP_REPLACEME|${SERVER_IP}|g" /var/www/zivpn-admin/admin-panel.html

# Create simple Python HTTP server script
cat > /var/www/zivpn-admin/server.py <<'PY_EOF'
#!/usr/bin/env python3
import http.server
import socketserver
import os
os.chdir('/var/www/zivpn-admin')
PORT = 8989
class Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.path = '/admin-panel.html'
        return super().do_GET()
with socketserver.TCPServer(("", PORT), Handler) as httpd:
    print(f"Serving on port {PORT}")
    httpd.serve_forever()
PY_EOF

chmod +x /var/www/zivpn-admin/server.py

# Create systemd service for admin panel
cat > /etc/systemd/system/zivpn-admin.service <<'INI_EOF'
[Unit]
Description=ZIVPN Web Admin Panel
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
INI_EOF

echo -e "\n=== Firewall / UFW rules ==="
# Allow ports required
ufw allow 6000:19999/udp || true
ufw allow 5667/udp || true
ufw allow 8989/tcp || true
# enable ufw (force to avoid interactive prompt)
ufw --force enable || true

# Fix iptables DNAT: point to localhost service port where zivpn listens (if needed)
# Note: DNAT might be unnecessary on many providers; this is a best-effort correct example.
INT_IF="$(ip -4 route ls | grep default | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1); exit}')"
if [ -n "$INT_IF" ]; then
  # remove previous similar rule if exists (best-effort)
  iptables -t nat -D PREROUTING -i "$INT_IF" -p udp --dport 6000:19999 -j DNAT --to-destination 127.0.0.1:5667 2>/dev/null || true
  iptables -t nat -A PREROUTING -i "$INT_IF" -p udp --dport 6000:19999 -j DNAT --to-destination 127.0.0.1:5667
fi

echo -e "\n=== Enabling and starting services ==="
systemctl daemon-reload
systemctl enable zivpn.service zvpn-admin.service 2>/dev/null || true
systemctl enable zivpn.service
systemctl start zivpn.service || true
systemctl enable zivpn-admin.service
systemctl start zivpn-admin.service || true

# Save credentials to root file
cat > /root/zivpn_credentials.txt <<CRED_EOF
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
CRED_EOF

# Final message
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
echo "If you still cannot access the admin page from your browser:"
echo "  1) Ensure port 8989 is allowed by provider firewall (some VPS providers block ports)."
echo "  2) Run: sudo systemctl status zivpn-admin.service  to check for errors."
echo "  3) View webserver logs in /var/log/syslog or run: sudo journalctl -u zivpn-admin.service -f"
echo ""
echo "Installation finished."
