# Hacking Terminal Simulator

A fully-featured Linux terminal emulator built in JavaScript with realistic command behavior, virtual filesystem, SSH simulation, and extensive hacking tools.


## Examples

See the `demo/index.html` file for a complete working example.

See it live at www.brainphreak.net 

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/F2F35TO7X)

## Core Features

- **Virtual Filesystem:** Complete directory structure with /home, /etc, /usr/bin, /var, and more
- **Multi-User System:** Switch between users with su/sudo, persistent user sessions
- **Command History:** Arrow keys to navigate through command history (per-user)
- **Tab Completion:** Auto-complete commands and file paths
- **Environment Variables:** PATH, HOME, USER, CWD, OLDPWD support
- **Piping:** Chain commands together using pipes (|)
- **Output Redirection:** Redirect output with > and >>
- **SSH Simulation:** Connect to remote hosts with persistent sessions
- **Interactive Commands:** Commands like more, less, top with keyboard navigation
- **Ctrl+C Support:** Interrupt long-running commands

## File Operations

- `ls` - List directory contents (-l for long format, -a for hidden files)
- `cd` - Change directory (supports ~, .., -, absolute/relative paths)
- `pwd` - Print working directory
- `cat` - Display file contents (supports piping)
- `head` - Show first N lines (-n flag, default 10)
- `tail` - Show last N lines (-n flag, default 10)
- `more` - Paginate file contents (space for next page, q to quit)
- `less` - Enhanced pager (currently aliases to more)
- `touch` - Create empty files
- `find` - Search for files (-name pattern, -type f/d)
- `grep` - Search file contents with regex patterns (supports piping)
- `chmod` - Change file permissions (simulated)
- `chown` - Change file ownership (simulated)
- `tar` - Create/extract archives (-czf to create, -xzf to extract, -v for verbose)
- `gzip` - Compress/decompress files (-d to decompress)

## Network Tools

- `ping` - Test network connectivity with realistic RTT and packet loss
- `nmap` - Port scanner with service detection (-p for ports, -sV for services)
- `traceroute` - Trace network path to destination
- `tcpdump` - Network packet analyzer
- `ssh` - Secure shell to remote hosts (creates persistent sessions)
- `scp` - Secure copy files between hosts
- `curl` - Transfer data from URLs (-I for headers, -o for output file)
- `wget` - Download files with animated progress bar (-O for output)
- `nc` - Netcat for port scanning (-zv), listening (-l -p), and banner grabbing
- `telnet` - Connect to services and view banners
- `ifconfig` - Display network interface configuration (shows eth0, lo, wlan0)
- `netstat` - Show network connections (dynamic based on activity)
- `route` - Display routing table
- `whois` - Domain registration information lookup
- `nslookup` - DNS query tool
- `dig` - Advanced DNS lookup (A, AAAA, MX, NS, TXT, SOA records)
- `host` - Simple DNS lookup (-t for record type)
- `arp` - View ARP table with MAC addresses
- `iptables` - Firewall configuration (simulated)

## Wireless Tools

- `iwconfig` - Display wireless network interface configuration
- `airodump-ng` - WiFi packet capture tool for WPA2 handshake collection
  - Full-screen real-time display with live beacon/data counters
  - `-w prefix` - Write capture file (required for handshake capture)
  - `-c channel` - Target specific channel
  - `--bssid MAC` - Filter by specific access point
  - Automatically captures WPA2 handshakes from networks with clients
  - Shows handshake capture indicator: `[ WPA handshake: BSSID ]`
  - Press Ctrl+C to stop and save capture file
- `aircrack-ng` - WPA/WPA2 password cracker using dictionary attacks
  - `-w wordlist` - Specify wordlist file (e.g., /usr/share/wordlists/common.txt)
  - `-b bssid` - Target specific access point
  - `-e essid` - Target specific network name
  - Cracks WiFi passwords from captured handshake files
  - Shows real-time progress and key when found

## Available WiFi Networks

| ESSID | BSSID | Channel | Password | Has Clients |
|-------|-------|---------|----------|-------------|
| SecureNet-5G | 00:14:6C:7E:40:80 | 36 | securenet123 | No |
| HomeNetwork | A4:08:F5:2D:39:E1 | 6 | password123 | Yes |
| CoffeeShop | C8:3A:35:B0:24:68 | 11 | coffeeshop | No |
| Guest_WiFi | F4:EC:38:D1:5A:7C | 1 | guestwifi | Yes |

## Security & Hacking Tools

- `john` - John the Ripper password cracker
  - `--wordlist=FILE` - Use wordlist for dictionary attack (required)
  - `--show` - Display previously cracked passwords
  - Cracks /etc/shadow format with SHA-512 hashes
  - Animated progress with realistic speed metrics
  - Wordlist: /usr/share/wordlists/common.txt (600+ passwords)
  - Supports Ctrl+C to abort cracking
- `hashcat` - GPU-based password cracker (simulates dictionary attacks)
- `strings` - Extract printable strings from binaries (includes hidden flags)
- `base64` - Encode/decode base64 (-d to decode)
- `md5sum` - Calculate MD5 hashes of files
- `sha256sum` - Calculate SHA256 hashes of files
- `openssl` - Cryptography toolkit
  - `openssl version` - Show version (-a for all info)
  - `openssl rand` - Generate random data (-hex, -base64)
  - `openssl s_client` - SSL/TLS client (-connect host:port)
  - `openssl passwd` - Generate password hashes
  - `openssl base64` - Base64 encoding/decoding

## System Information

- `whoami` - Display current username
- `hostname` - Show system hostname
- `uname` - Print system information (-a for all)
- `date` - Display current date and time
- `w` - Show who is logged in and what they're doing
- `who` - Display logged-in users
- `ps` - List running processes
- `top` - Interactive process viewer (P for CPU sort, M for memory, N for PID, R to refresh, q to quit)
- `history` - View command history

## User Management

- `su` - Switch user (requires password authentication)
- `sudo` - Execute commands as root
- `useradd` - Add new users (root only, -p for password)
- `exit` - Exit current user session or close terminal

## Package Management

- `apt` - Debian package manager (install, update, upgrade, remove)
- `dpkg` - Low-level package manager (-l to list, -i to install)

## Other Utilities

- `echo` - Display text or variables
- `clear` - Clear terminal screen
- `export` - Set environment variables
- `env` - Display all environment variables
- `bash` - Start new bash shell
- `which` - Locate command executables in PATH
- `help` - Display available commands

## Advanced Features

### Piping Examples

```bash
# View large file with pagination
cat /etc/passwd | more

# Search and paginate
ls -la | grep "txt" | more

# Get first 5 lines
cat file.txt | head -5

# Search and show last matches
cat log.txt | grep "error" | tail -10

# Complex pipeline
ls -la | grep "\\.txt" | head -20 | grep "user"

# Pipe network output
nmap google.com | grep "open"

# With output redirection
cat file.txt | grep "pattern" > output.txt
```

### SSH Features

- **Persistent Sessions:** SSH connections maintain separate filesystem state
- **Hidden Files:** Each SSH target contains unique hidden files with sensitive data
- **Easter Eggs:** Special files on hostname-specific servers:
  - **gibson:** .wargames, HACK_THE_PLANET.txt
  - **matrix:** .red_pill, .rabbit_hole
  - **fsociety/ecorp:** .fsociety.dat, wellick_notes.txt
- **Exposed Secrets:** Find .env files, .passwords.txt, shadow.bak, .bash_history with sensitive commands

### DNS & Network Simulation

- **Consistent IPs:** Hostnames resolve to the same IP every time using hash-based generation
- **DNS Cache:** Recently queried domains are cached and appear in netstat/arp
- **Service Detection:** nmap and nc detect realistic service banners
- **Well-Known Hosts:** google.com, github.com, stackoverflow.com have realistic public IPs

### Password Cracking Simulation

- **john:** Cracks shadow file format with common passwords (123456, password, admin, letmein, etc.)
- **hashcat:** Simulates GPU cracking with OpenCL detection and rockyou.txt dictionary
- **Realistic Output:** Animated progress with speed metrics and statistics

## File System Structure

```
/
├── home/
│   ├── root/          (root user home)
│   ├── user/          (regular user)
│   └── brainphreak/   (main user)
├── etc/
│   ├── hosts          (hostname to IP mappings)
│   ├── passwd         (user accounts)
│   ├── shadow         (password hashes)
│   └── sudoers        (sudo permissions)
├── usr/
│   ├── bin/           (executables)
│   └── share/         (shared data)
├── var/
│   └── log/           (system logs)
├── tmp/               (temporary files)
└── bin/               (essential binaries)
```

## Default Users & Passwords

| Username | Password | Permissions | Notes |
|----------|----------|-------------|-------|
| user | 123456 | Sudo access | Default login, can crack with john |
| brainphreak | letmein | Sudo access | Can crack with john |
| root | password | Full access | Can crack with john |

*All passwords are in /usr/share/wordlists/common.txt and can be cracked from /etc/shadow using john*

## Tips & Tricks

- **Tab Completion:** Press Tab to auto-complete commands and file paths
- **Command History:** Use Up/Down arrows to cycle through previous commands
- **Interrupt:** Press Ctrl+C to stop running commands like ping, wget, john, hashcat
- **Hidden Files:** Use `ls -a` to view hidden files (starting with .)
- **Variables:** Use $USER, $HOME, $PATH in commands
- **Change Directory:** Use `cd -` to go back to previous directory
- **Home Shortcut:** Use `cd ~` or just `cd` to go home
- **SSH Exploration:** Try ssh to different hostnames to find easter eggs
- **Password Cracking:** SSH to servers, find shadow files, use john/hashcat to crack

## Example Workflow: Hack a Server

```bash
# 1. Scan for open SSH port
nmap -p 22 target.com

# 2. Connect via SSH
ssh admin@target.com

# 3. Look for hidden files
ls -la

# 4. Find password files
cat .passwords.txt
cat shadow.bak

# 5. Download the shadow file (exit SSH first)
exit
scp admin@target.com:shadow.bak ./

# 6. Crack passwords with wordlist
john --wordlist=/usr/share/wordlists/common.txt /etc/shadow

# 7. View cracked passwords
john --show /etc/shadow

# 8. Login as root with cracked password
su root
```

## Example Workflow: Crack WiFi Password

```bash
# 1. Check wireless interface
iwconfig

# 2. Scan for WiFi networks
sudo airodump-ng wlan0

# 3. Target specific network and capture handshake
sudo airodump-ng -w capture --bssid A4:08:F5:2D:39:E1 wlan0

# 4. Wait for handshake capture (shows: [ WPA handshake: A4:08:F5:2D:39:E1 ])
# Press Ctrl+C when handshake is captured

# 5. Crack the WiFi password
aircrack-ng -w /usr/share/wordlists/common.txt capture-01.cap

# 6. WiFi password found: password123
```

## Technical Implementation

- **Language:** Vanilla JavaScript (ES6 modules)
- **Architecture:** Command pattern with async/await for all commands
- **Filesystem:** In-memory JSON structure with full POSIX-like paths
- **Persistence:** Command history saved per-user, DNS cache maintained globally
- **Determinism:** Hash-based pseudo-random generation for consistent IPs and data
- **DOM Manipulation:** Direct DOM updates for interactive commands

## Browser Support

- Chrome/Edge 90+
- Firefox 88+
- Safari 14+
- Opera 76+

Requires ES6 module support.

## License

Open Source GNU GPLv3 - please credit brainphreak.net

## Support

For issues, questions, or contributions, brainphreak@brainphreak.net
