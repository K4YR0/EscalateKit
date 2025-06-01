# EscalateKit - Post-Exploitation Automation Tool

    ███████╗███████╗ ██████╗ █████╗ ██╗      █████╗ ████████╗███████╗██╗  ██╗██╗████████╗
    ██╔════╝██╔════╝██╔════╝██╔══██╗██║     ██╔══██╗╚══██╔══╝██╔════╝██║ ██╔╝██║╚══██╔══╝
    █████╗  ███████╗██║     ███████║██║     ███████║   ██║   █████╗  █████╔╝ ██║   ██║   
    ██╔══╝  ╚════██║██║     ██╔══██║██║     ██╔══██║   ██║   ██╔══╝  ██╔═██╗ ██║   ██║   
    ███████╗███████║╚██████╗██║  ██║███████╗██║  ██║   ██║   ███████╗██║  ██╗██║   ██║   
    ╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝   ╚═╝   

A comprehensive **privilege escalation** and **post-exploitation** tool for Linux systems. Designed for penetration testers and red teamers to automate reconnaissance, exploitation, persistence, and evasion.

---

## 🔥 Features
- **Privilege Escalation Detection**  
  - SUID/SGID binaries  
  - Sudo misconfigurations  
  - Kernel exploits (CVE checks)  
  - Writable files/cron jobs  
  - Capabilities abuse  

- **Persistence Mechanisms**  
  - SSH key injection  
  - Cron job backdoors  
  - Systemd service persistence  
  - Startup script modification  

- **Evasion & Cleanup**  
  - Log cleaning (`auth.log`, `bash_history`)  
  - Timestomping (file timestamp spoofing)  
  - Self-destruct option  

- **Exportable Reports**  
  - JSON, HTML, CSV output formats  

- **Parallel Execution**  
  - Fork/thread/subshell modes for faster scans  

---

## 🛠 Installation
### Method 1: Direct Download
```bash
curl -sL https://raw.githubusercontent.com/K4YR0/EscalateKit/main/escalatekit.sh -o escalatekit.sh
chmod +x escalatekit.sh
sudo ./escalatekit.sh
```

### Method 2: Clone Repository
```bash
git clone https://github.com/K4YR0/EscalateKit.git
cd EscalateKit
chmod +x escalatekit.sh
sudo ./escalatekit.sh
```

---

## 📌 Usage
### Basic Scan (All Modules)
```bash
sudo ./escalatekit.sh
```

### Selective Modules
```bash
sudo ./escalatekit.sh -m recon,exploit  # Only run recon and exploit
```

### Parallel Execution (Faster)
```bash
sudo ./escalatekit.sh -f  # Fork mode
sudo ./escalatekit.sh -t  # Thread mode (requires GNU Parallel)
```

### Export Results
```bash
sudo ./escalatekit.sh -o html,json  # Generate HTML and JSON reports
```

### Stealth Mode (Minimal Output)
```bash
sudo ./escalatekit.sh -q
```

---

## 📂 Output Structure
Results are saved to `/tmp/.escalatekit_results/` by default:  
```
/tmp/.escalatekit_results/
├── recon/           # System info, SUID files, cron jobs, etc.
├── exploit/         # Suggested exploits + templates
├── persist/         # Persistence scripts (SSH, cron, systemd)
├── evade/           # Log cleaning/timestomping tools
└── export/          # JSON/HTML/CSV reports
```

---

## 🚀 Example Workflow
1. **Run Full Scan**  
   ```bash
   sudo ./escalatekit.sh -f -o html
   ```
2. **Review Exploits**  
   Check `exploit/suggestions.txt` for privilege escalation paths.  
3. **Establish Persistence**  
   Use generated scripts in `persist/` (e.g., `add_ssh_key.sh`).  
4. **Clean Up**  
   ```bash
   ./evade/cover_tracks.sh  # Remove traces
   ```

---

## ⚠ Legal & Ethics
- **For authorized penetration testing and educational purposes only.**  
- Unauthorized use against systems you don’t own is illegal.  
- The developer assumes no liability for misuse.  

---

## 📜 License
MIT License - See [LICENSE](LICENSE).

