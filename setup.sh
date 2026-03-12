#!/bin/bash
# ==========================================================================
# Cathexis IRCd — Install & Boot Setup Script
# ==========================================================================
# Usage:
#   sudo ./setup.sh [--prefix /home/ircd] [--user ircd] [--no-systemd]
#
# This script:
#   1. Creates the ircd system user (if it doesn't exist)
#   2. Runs ./configure && make && make install
#   3. Installs ircd.conf with generated cloaking keys
#   4. Creates ircd.motd
#   5. Installs systemd service for boot startup
#   6. Enables and starts the service
#
# Prerequisites:
#   - gcc, make, flex, bison (or this is run from a pre-built tree)
#   - openssl (for key generation)
#   - Root access (for user creation and systemd)
# ==========================================================================

set -e

# --- Defaults ---
PREFIX="/home/ircd"
IRCD_USER="ircd"
IRCD_GROUP="ircd"
INSTALL_SYSTEMD=1
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# --- Parse arguments ---
while [[ $# -gt 0 ]]; do
  case "$1" in
    --prefix)     PREFIX="$2"; shift 2 ;;
    --user)       IRCD_USER="$2"; IRCD_GROUP="$2"; shift 2 ;;
    --no-systemd) INSTALL_SYSTEMD=0; shift ;;
    --help)
      echo "Usage: $0 [--prefix /home/ircd] [--user ircd] [--no-systemd]"
      exit 0 ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

LIB_DIR="$PREFIX/lib"
BIN_DIR="$PREFIX/bin"

echo "==========================================="
echo " Cathexis IRCd Setup"
echo "==========================================="
echo "  Prefix:   $PREFIX"
echo "  User:     $IRCD_USER"
echo "  Systemd:  $([ $INSTALL_SYSTEMD -eq 1 ] && echo yes || echo no)"
echo "==========================================="
echo ""

# --- Step 1: Create system user ---
echo "[1/6] Creating system user '$IRCD_USER'..."
if id "$IRCD_USER" &>/dev/null; then
  echo "  User '$IRCD_USER' already exists."
else
  useradd --system --home-dir "$PREFIX" --shell /usr/sbin/nologin \
          --comment "Cathexis IRCd" "$IRCD_USER" 2>/dev/null || \
  useradd -r -d "$PREFIX" -s /usr/sbin/nologin -c "Cathexis IRCd" "$IRCD_USER"
  echo "  Created system user '$IRCD_USER'."
fi

# --- Step 2: Build and install ---
echo "[2/6] Building and installing..."
cd "$SCRIPT_DIR"

if [ ! -f configure ]; then
  echo "  ERROR: Run this script from the Cathexis source directory."
  exit 1
fi

if [ ! -f ircd/ircd ] || [ ! -f "$BIN_DIR/ircd"* 2>/dev/null ]; then
  ./configure --prefix="$PREFIX" --disable-ssl 2>&1 | tail -3
  make -j"$(nproc)" 2>&1 | tail -3
  make install 2>&1 | tail -3
  echo "  Build complete."
else
  echo "  Binary already exists, skipping build."
  # Still run install to update
  make install 2>&1 | tail -3
fi

# --- Step 3: Generate cloaking keys and install config ---
echo "[3/6] Installing configuration..."

if [ -f "$LIB_DIR/ircd.conf" ]; then
  echo "  ircd.conf already exists — not overwriting."
  echo "  To use the new config template, see: $SCRIPT_DIR/ircd.conf"
else
  # Generate unique cloaking keys
  if command -v openssl &>/dev/null; then
    KEY1=$(openssl rand -hex 32)
    KEY2=$(openssl rand -hex 32)
    KEY3=$(openssl rand -hex 32)
  else
    # Fallback: use /dev/urandom
    KEY1=$(head -c 32 /dev/urandom | od -A n -t x1 | tr -d ' \n')
    KEY2=$(head -c 32 /dev/urandom | od -A n -t x1 | tr -d ' \n')
    KEY3=$(head -c 32 /dev/urandom | od -A n -t x1 | tr -d ' \n')
  fi

  # Copy and customize the config
  cp "$SCRIPT_DIR/ircd.conf" "$LIB_DIR/ircd.conf"
  sed -i "s/CHANGE_ME_GENERATE_WITH_openssl_rand_hex_32/$KEY1/" "$LIB_DIR/ircd.conf"
  # Second occurrence
  sed -i "0,/CHANGE_ME_GENERATE_WITH_openssl_rand_hex_32/s/CHANGE_ME_GENERATE_WITH_openssl_rand_hex_32/$KEY2/" "$LIB_DIR/ircd.conf"
  # Third occurrence
  sed -i "0,/CHANGE_ME_GENERATE_WITH_openssl_rand_hex_32/s/CHANGE_ME_GENERATE_WITH_openssl_rand_hex_32/$KEY3/" "$LIB_DIR/ircd.conf"

  echo "  Installed ircd.conf with unique cloaking keys."
fi

# --- Step 4: Create MOTD ---
echo "[4/6] Creating MOTD..."
if [ ! -f "$LIB_DIR/ircd.motd" ]; then
  cat > "$LIB_DIR/ircd.motd" << 'MOTDEOF'
 ___      _   _            _
/ __|__ _| |_| |_  _____ _(_)___
| (__/ _` |  _| ' \/ -_) \ / (_-<
\___\__,_|\__|_||_\___/_\_\_/__/

Welcome to CathexisNet!

 * This server runs Cathexis IRCd 1.1.0
 * Website:   https://example.com
 * Rules:     /RULES
 * Register:  /MSG NickServ REGISTER <password> <email>
 * Help:      /HELP

By connecting to this server you agree to abide by our
network policies. Abuse will result in removal.

Enjoy your stay!
MOTDEOF
  echo "  Created default ircd.motd."
else
  echo "  ircd.motd already exists."
fi

# --- Step 5: Set ownership ---
echo "[5/6] Setting file ownership..."
chown -R "$IRCD_USER:$IRCD_GROUP" "$PREFIX"
# Binary needs to be executable
chmod 755 "$BIN_DIR"
find "$BIN_DIR" -type f -exec chmod 755 {} \;
# Config should be readable only by the ircd user
chmod 600 "$LIB_DIR/ircd.conf"
chmod 644 "$LIB_DIR/ircd.motd"
echo "  Ownership set to $IRCD_USER:$IRCD_GROUP"

# --- Step 6: Install systemd service ---
if [ $INSTALL_SYSTEMD -eq 1 ]; then
  echo "[6/6] Installing systemd service..."

  # Generate the service file with correct paths and user
  cat > /etc/systemd/system/cathexis.service << SVCEOF
[Unit]
Description=Cathexis IRC Daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=forking
User=$IRCD_USER
Group=$IRCD_GROUP
WorkingDirectory=$LIB_DIR
ExecStart=$BIN_DIR/ircd -f $LIB_DIR/ircd.conf
ExecReload=/bin/kill -HUP \$MAINPID
PIDFile=$LIB_DIR/ircd.pid
LimitNOFILE=16384
Restart=on-failure
RestartSec=10
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=no
ReadWritePaths=$LIB_DIR
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes

[Install]
WantedBy=multi-user.target
SVCEOF

  systemctl daemon-reload
  systemctl enable cathexis
  echo "  Service installed and enabled for boot."
  echo ""
  echo "  Start now:   sudo systemctl start cathexis"
  echo "  View logs:   sudo journalctl -u cathexis -f"
  echo "  Status:      sudo systemctl status cathexis"
  echo "  Reload conf: sudo systemctl reload cathexis"
  echo "  Stop:        sudo systemctl stop cathexis"
else
  echo "[6/6] Skipping systemd (--no-systemd)."
  echo ""
  echo "  Start manually: su -s /bin/sh $IRCD_USER -c '$BIN_DIR/ircd -f $LIB_DIR/ircd.conf'"
fi

echo ""
echo "==========================================="
echo " Setup Complete!"
echo "==========================================="
echo ""
echo " BEFORE STARTING, edit $LIB_DIR/ircd.conf:"
echo "   1. Change General { name, description, numeric }"
echo "   2. Change Admin { Location, Contact }"
echo "   3. Change the Operator password (use umkpasswd):"
echo "      $BIN_DIR/umkpasswd bcrypt <your-password>"
echo "   4. Verify cloaking keys were generated"
echo ""
echo " Then: sudo systemctl start cathexis"
echo ""
