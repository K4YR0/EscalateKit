# EscalateKit - Advanced Linux Privilege Escalation Framework

```
    ███████╗███████╗ ██████╗ █████╗ ██╗      █████╗ ████████╗███████╗██╗  ██╗██╗████████╗
    ██╔════╝██╔════╝██╔════╝██╔══██╗██║     ██╔══██╗╚══██╔══╝██╔════╝██║ ██╔╝██║╚══██╔══╝
    █████╗  ███████╗██║     ███████║██║     ███████║   ██║   █████╗  █████╔╝ ██║   ██║   
    ██╔══╝  ╚════██║██║     ██╔══██║██║     ██╔══██║   ██║   ██╔══╝  ██╔═██╗ ██║   ██║   
    ███████╗███████║╚██████╗██║  ██║███████╗██║  ██║   ██║   ███████╗██║  ██╗██║   ██║   
    ╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝   ╚═╝   
```

![EscalateKit Logo](https://img.shields.io/badge/EscalateKit-v1.0-red?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Linux-blue?style=for-the-badge)
![License](https://img.shields.io/badge/License-Educational-green?style=for-the-badge)

**A comprehensive post-exploitation framework for automated privilege escalation on Linux systems**

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Documentation](#-documentation)

---

## 🎯 Overview

EscalateKit is a powerful, modular privilege escalation framework designed for penetration testers, red teamers, and security researchers. It automates the discovery and exploitation of privilege escalation vectors on Linux systems through comprehensive reconnaissance, intelligent exploit suggestion, and automated payload generation.

### ⚠️ Legal Disclaimer
This tool is intended for **educational purposes** and **authorized penetration testing** only. Users are responsible for ensuring they have proper authorization before using this tool on any system.

## ✨ Features

- **🔍 Shell Enhancement**: TTY upgrades and shell stabilization
- **🕵️ Reconnaissance**: System enumeration, SUID/SGID discovery, capability analysis
- **🎯 Exploitation**: Automated vulnerability detection and exploit generation  
- **🔒 Persistence**: SSH keys, cron jobs, systemd services
- **👻 Evasion**: Log cleanup, timestomping, track covering
- **📊 Reporting**: JSON, HTML, CSV export with detailed analysis

## 🚀 Installation

```bash
# Clone and setup
git clone https://github.com/yourusername/EscalateKit.git
cd EscalateKit
chmod +x escalatekit.sh

# Verify installation
./escalatekit.sh -h
```

## 📖 Usage

### Basic Commands
```bash
# Full analysis
./escalatekit.sh -m all

# Specific modules
./escalatekit.sh -m recon,exploit

# Quiet mode
./escalatekit.sh -q -m recon

# Export results
./escalatekit.sh -m all -o json,html

# Parallel execution
./escalatekit.sh -f -m all -v
```

### Available Modules

| Module | Description |
|--------|-------------|
| `shell` | TTY upgrade and shell stabilization |
| `recon` | System reconnaissance and enumeration |
| `exploit` | Vulnerability detection and exploit generation |
| `persist` | Persistence mechanism creation |
| `evade` | Evasion and cleanup techniques |

## 📚 Documentation

### Command Options
```
./escalatekit.sh [OPTIONS]

-h, --help          Display help message and exit
-f, --fork          Execute modules using fork processes for parallel execution
-t, --thread        Execute modules using threads for parallel execution
-s, --subshell      Execute modules in a subshell (isolated environment)
-l, --log DIR       Specify a custom directory for log files
-r, --restore       Clean up artifacts and restore altered configurations
-v, --verbose       Enable verbose output mode
-m, --modules LIST  Specify modules to run (shell,recon,exploit,persist,evade,all)
-o, --output FORMAT Export results in specified format (json,html,csv)
-q, --quiet         Minimal output for stealthy operation
```

### Output Structure
```
/tmp/.escalatekit_results/
├── shell/
│   └── upgrade_options.txt        # Shell upgrade methods
├── recon/
│   ├── system_info.txt            # Basic system information
│   ├── network_info.txt           # Network configuration
│   ├── sudo_privs.txt             # Sudo privileges analysis
│   ├── suid_files.txt             # SUID binary enumeration
│   ├── capabilities.txt           # File capabilities check
│   ├── cron_jobs.txt              # Cron job analysis
│   ├── writable_files.txt         # Writable files discovery
│   └── kernel_exploits.txt        # Kernel vulnerability assessment
├── exploit/
│   ├── suggestions.txt            # Exploitation recommendations
│   ├── detailed_analysis.txt      # Comprehensive vulnerability analysis
│   └── templates/                 # Ready-to-use exploit scripts
│       ├── master_exploit.sh      # Master exploit menu
│       ├── sudo_*_exploit.sh      # Sudo-based exploits
│       ├── suid_*_exploit.sh      # SUID binary exploits
│       ├── cron_*_exploit.sh      # Cron job exploits
│       ├── systemd_service_exploit.sh  # Service file exploits
│       ├── docker_group_exploit.sh     # Docker group exploits
│       ├── lxd_group_exploit.sh        # LXD group exploits
│       └── kernel_exploit_helper.sh    # Kernel exploit helper
├── persist/
│   ├── ssh_key.txt                # SSH key persistence analysis
│   ├── cron_job.txt               # Cron job persistence setup
│   ├── systemd_service.txt        # Systemd service persistence
│   ├── startup_file.txt           # Startup file persistence
│   ├── add_ssh_key.sh             # Interactive SSH key installer
│   ├── generate_ssh_keys.sh       # SSH key pair generator
│   ├── add_cron_job.sh            # Cron job persistence script
│   ├── add_systemd_service.sh     # Systemd service installer
│   └── add_startup_file.sh        # Startup file modifier
├── evade/
│   ├── cleanup_logs.txt           # Log cleanup analysis
│   ├── timestomp.txt              # Timestomping guidance
│   ├── cover_tracks.txt           # Track covering methods
│   ├── clean_logs.sh              # Log cleanup script
│   ├── timestomp.sh               # File timestamp manipulation
│   └── cover_tracks.sh            # Comprehensive cleanup script
└── export/
    ├── results.json               # JSON format export
    ├── results.html               # HTML report
    └── results.csv                # CSV format export
```

### Log Files
```
Default log locations:
- Primary: /var/log/escalatekit/history.log
- Fallback: /tmp/.escalatekit_logs/history.log
- Custom: Specified with -l option
```

## 🔧 Detection Capabilities

- **Kernel Exploits**: Dirty COW, PwnKit, DirtyPipe, GameOver(lay), Looney Tunables
- **SUID/Sudo Abuse**: GTFOBins integration, misconfiguration detection
- **Group Privileges**: Docker, LXD, disk, shadow, and other dangerous groups
- **Service Exploitation**: Writable systemd services, cron scripts
- **Capabilities**: Dangerous capability analysis
- **File Permissions**: Critical writable system files

## 🎯 Interactive Features

- **Password Handling**: Smart sudo enumeration with password management
- **Parallel Execution**: Fork, thread, and subshell execution modes
- **Progress Indicators**: Loading animations and status updates
- **Template Generation**: Automated exploit script creation
- **Export Options**: Multiple output formats for reporting

## 🤝 Contributing

```bash
git clone https://github.com/yourusername/EscalateKit.git
cd EscalateKit
git checkout -b feature/new-module
# Make changes and submit PR
```

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [GTFOBins](https://gtfobins.github.io/) for exploitation techniques
- Linux security community for vulnerability research

---

<div align="center">

**Made with ❤️ by [K4YR0]**

*Star ⭐ this repository if you find it helpful!*

</div>
