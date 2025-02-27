#!/bin/bash

LOG_FILE="/var/log/lynis-report.dat"
TEMP_FILE="/tmp/lynis_warnings.txt"
BANNER_TEXT="Unauthorized access to this system is prohibited. All activities may be monitored and reported."
SSH_CONFIG="/etc/ssh/sshd_config"
LOGIN_DEFS="/etc/login.defs"
PASSWORD_HASH_ROUNDS=100000
PAM_CONFIG="/etc/pam.d/common-password"

echo "[+] Extracting Lynis warnings and suggestions..."
grep -E 'warning|suggestion' "$LOG_FILE" > "$TEMP_FILE"

echo "[+] Found potential issues:"
cat "$TEMP_FILE"

echo -e "\n[+] Starting automatic fixes...\n"

# Function to update or add a setting in a config file
update_config() {
    local FILE=$1
    local PARAMETER=$2
    local VALUE=$3
    if grep -q "^$PARAMETER" "$FILE"; then
        sudo sed -i "s/^$PARAMETER.*/$PARAMETER $VALUE/" "$FILE"
    else
        echo "$PARAMETER $VALUE" | sudo tee -a "$FILE"
    fi
}

# Configure password hashing rounds
if grep -q "Configure password hashing rounds" "$TEMP_FILE"; then
    echo "[FIX] Configuring password hashing rounds to $PASSWORD_HASH_ROUNDS..."
    update_config "$LOGIN_DEFS" "SHA_CRYPT_MIN_ROUNDS" "$PASSWORD_HASH_ROUNDS"
    update_config "$LOGIN_DEFS" "SHA_CRYPT_MAX_ROUNDS" "$PASSWORD_HASH_ROUNDS"
fi

# Update System (if recommended)
if grep -q "update your system" "$TEMP_FILE"; then
    echo "[FIX] Updating system packages..."
    sudo apt update && sudo apt upgrade -y
fi

# Secure /tmp (if recommended)
if grep -q "consider mounting /tmp with noexec" "$TEMP_FILE"; then
    echo "[FIX] Securing /tmp partition..."
    sudo mount -o remount,noexec,nosuid,nodev /tmp
fi

# Disable root SSH login (if suggested)
if grep -q "PermitRootLogin" "$TEMP_FILE"; then
    echo "[FIX] Disabling root SSH login..."
    sudo sed -i 's/^PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
    sudo systemctl restart sshd
fi

# Disable unused network services (example for cups)
if grep -q "CUPS is active but not needed" "$TEMP_FILE"; then
    echo "[FIX] Disabling CUPS (printer service)..."
    sudo systemctl stop cups && sudo systemctl disable cups
fi

# Restrict permissions on critical files
if grep -q "consider stricter permissions on /etc/passwd" "$TEMP_FILE"; then
    echo "[FIX] Restricting permissions on /etc/passwd..."
    sudo chmod 644 /etc/passwd
fi

# Disable unnecessary network protocols
# Check for dccp protocol
PROTO=dccp
if grep -q "Determine if protocol '$PROTO' is really needed" "$TEMP_FILE"; then
    if grep -q "# lynis block list" /etc/modprobe.d/blacklist.conf; then
        echo "[FIXED] Skipping, already blocked $PROTO"
    else
        echo "[FIX] Disabling $PROTO protocol..."
        sudo modprobe -r $PROTO
        echo "blacklist $PROTO" | sudo tee -a /etc/modprobe.d/blacklist.conf
    fi
fi

# Check for sctp protocol
PROTO=sctp
if grep -q "Determine if protocol '$PROTO' is really needed" "$TEMP_FILE"; then
    if grep -q "# lynis block list" /etc/modprobe.d/blacklist.conf; then
        echo "[FIXED] Skipping, already blocked $PROTO"
    else
        echo "[FIX] Disabling $PROTO protocol..."
        sudo modprobe -r $PROTO
        echo "blacklist $PROTO" | sudo tee -a /etc/modprobe.d/blacklist.conf
    fi
fi

# Check for rds protocol
PROTO=rds
if grep -q "Determine if protocol '$PROTO' is really needed" "$TEMP_FILE"; then
    if grep -q "# lynis block list" /etc/modprobe.d/blacklist.conf; then
        echo "[FIXED] Skipping, already blocked $PROTO"
    else
        echo "[FIX] Disabling $PROTO protocol..."
        sudo modprobe -r $PROTO
        echo "blacklist $PROTO" | sudo tee -a /etc/modprobe.d/blacklist.conf
    fi
fi

# Check for tipc protocol
PROTO=tipc
if grep -q "Determine if protocol '$PROTO' is really needed" "$TEMP_FILE"; then
    if grep -q "# lynis block list" /etc/modprobe.d/blacklist.conf; then
        echo "[FIXED] Skipping, already blocked $PROTO"
    else
        echo "[FIX] Disabling $PROTO protocol..."
        sudo modprobe -r $PROTO
        echo "blacklist $PROTO" | sudo tee -a /etc/modprobe.d/blacklist.conf
    fi
fi

# Run APT
if grep -q "|Update your system with apt-get" "$TEMP_FILE"; then
    echo "[FIX] Running apt update..."
    apt update
    echo "[FIX] Running apt upgrade and automatically installing all patches..."
    apt upgrade -y
fi

# Add a legal banner to /etc/issue
if grep -q "Add a legal banner to /etc/issue" "$TEMP_FILE"; then
    echo "[FIX] Adding legal banner to /etc/issue..."
    echo "$BANNER_TEXT" | sudo tee /etc/issue
fi

# Add a legal banner to /etc/issue.net
if grep -q "Add legal banner to /etc/issue.net" "$TEMP_FILE"; then
    echo "[FIX] Adding legal banner to /etc/issue.net..."
    echo "$BANNER_TEXT" | sudo tee /etc/issue.net
fi

# Harden SSH configuration
if grep -q "Consider hardening SSH configuration" "$TEMP_FILE"; then
    echo "[+] Hardening SSH configuration..."

    # Function to update SSH config safely
    update_ssh_config() {
        local PARAMETER=$1
        local VALUE=$2
        if grep -q "^$PARAMETER" $SSH_CONFIG; then
            sudo sed -i "s/^$PARAMETER.*/$PARAMETER $VALUE/" $SSH_CONFIG
        else
            echo "$PARAMETER $VALUE" | sudo tee -a $SSH_CONFIG
        fi
    }

    update_ssh_config "AllowTcpForwarding" "no"
    update_ssh_config "ClientAliveCountMax" "2"
    update_ssh_config "LogLevel" "VERBOSE"
    update_ssh_config "MaxAuthTries" "3"
    update_ssh_config "MaxSessions" "2"
    update_ssh_config "TCPKeepAlive" "no"
    update_ssh_config "X11Forwarding" "no"
    update_ssh_config "AllowAgentForwarding" "no"

    # Custom SSH Port Change (requires manual input)
    if grep -q "Consider hardening SSH configuration.*Port" "$TEMP_FILE"; then
        echo -e "\n[MANUAL] Change SSH Port: Edit /etc/ssh/sshd_config and update the 'Port' setting manually."
    fi

    echo "[FIX] Restarting SSH service..."
    sudo systemctl restart ssh
fi

# Configure password policies
if grep -q "Configure minimum password age" "$TEMP_FILE"; then
    echo "[FIX] Setting minimum password age..."
    update_config "$LOGIN_DEFS" "PASS_MIN_DAYS" "1"
fi

if grep -q "Configure maximum password age" "$TEMP_FILE"; then
    echo "[FIX] Setting maximum password age..."
    update_config "$LOGIN_DEFS" "PASS_MAX_DAYS" "90"
fi

# Set default umask to 027
if grep -q "Default umask in /etc/login.defs could be more strict" "$TEMP_FILE"; then
    echo "[FIX] Setting default umask to 027..."
    update_config "$LOGIN_DEFS" "UMASK" "027"
fi

# Install debsums for package verification
if grep -q "Install debsums utility" "$TEMP_FILE"; then
    echo "[FIX] Installing debsums for package verification..."
    sudo apt install -y debsums
    echo "[*] Running debsums for potentially modified files..."
    debsums -c
fi

# Install apt-show-versions for patch management
if grep -q "Install package apt-show-versions" "$TEMP_FILE"; then
    echo "[FIX] Installing apt-show-versions for patch management..."
    sudo apt install -y apt-show-versions
fi

# Install and configure PAM password strength module
if grep -q "Install a PAM module for password strength testing" "$TEMP_FILE"; then
    echo "[FIX] Installing libpam-passwdqc for password strength enforcement..."
    sudo apt install -y libpam-passwdqc
    echo "[FIX] Enforcing stricter password rules..."

    if ! grep -q "pam_passwdqc.so" "$PAM_CONFIG"; then
        echo "password required pam_passwdqc.so min=12,10,8,7,6 retry=3" | sudo tee -a "$PAM_CONFIG"
    else
        sudo sed -i "s/^password.*pam_passwdqc.*/password required pam_passwdqc.so min=12,10,8,7,6 retry=3/" "$PAM_CONFIG"
    fi
fi

echo -e "\n[+] Auto-fixes applied. Review changes manually where necessary!"

