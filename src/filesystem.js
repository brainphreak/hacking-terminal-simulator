/* ============================================================================
   TERMINAL KIT - Virtual Filesystem
   Adapted from brainphreak.net for theblackpacket
   ============================================================================ */

function generateTimestamp() {
    const now = new Date();
    const year = now.getFullYear();
    const month = (now.getMonth() + 1).toString().padStart(2, '0');
    const day = now.getDate().toString().padStart(2, '0');
    const hours = now.getHours().toString().padStart(2, '0');
    const minutes = now.getMinutes().toString().padStart(2, '0');
    return `${year}-${month}-${day} ${hours}:${minutes}`;
}

const defaultTimestamp = generateTimestamp();

const filesystem = {
    '/': {
        type: 'directory',
        owner: 'root',
        group: 'root',
        size: 4096,
        lastModified: defaultTimestamp,
        contents: {
            'home': {
                type: 'directory',
                owner: 'root',
                group: 'root',
                size: 4096,
                lastModified: defaultTimestamp,
                contents: {
                    'root': {
                        type: 'directory',
                        owner: 'root',
                        group: 'root',
                        size: 4096,
                        lastModified: defaultTimestamp,
                        contents: {
                            '.bash_history': { type: 'file', owner: 'root', group: 'root', size: 0, lastModified: defaultTimestamp, content: '' },
                            'Documents': { type: 'directory', owner: 'root', group: 'root', size: 4096, lastModified: defaultTimestamp, contents: {} },
                            'Downloads': { type: 'directory', owner: 'root', group: 'root', size: 4096, lastModified: defaultTimestamp, contents: {} },
                            'Music': { type: 'directory', owner: 'root', group: 'root', size: 4096, lastModified: defaultTimestamp, contents: {} },
                            'Pictures': { type: 'directory', owner: 'root', group: 'root', size: 4096, lastModified: defaultTimestamp, contents: {} },
                            'Videos': { type: 'directory', owner: 'root', group: 'root', size: 4096, lastModified: defaultTimestamp, contents: {} }
                        }
                    },
                    'user': {
                        type: 'directory',
                        owner: 'user',
                        group: 'user',
                        size: 4096,
                        lastModified: defaultTimestamp,
                        contents: {
                            '.bash_history': { type: 'file', owner: 'user', group: 'user', size: 0, lastModified: defaultTimestamp, content: '' },
                            'notes.txt': { type: 'file', owner: 'user', group: 'user', size: 2048, lastModified: defaultTimestamp, content: `============================================
  THE BLACK PACKET TERMINAL - HACKER'S GUIDE
============================================

HACKING TOOLS
-------------
aircrack-ng <capture_file>
    Crack WiFi passwords from captured handshakes.
    Try: aircrack-ng capture.cap

john <hash_file> --wordlist=<wordlist>
    Crack password hashes (MD5, SHA, etc.)
    Try: john hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt

hashcat <hash> <wordlist>
    GPU-accelerated password cracking.

nmap <target>
    Network scanner - discover hosts and services.
    Try: nmap gibson.ellingson.com

ssh <user>@<host>
    Connect to remote systems via SSH.
    Try: ssh root@wopr.norad.gov

strings <file>
    Extract readable text from binary files.

base64 -d <file>
    Decode base64 encoded data.

md5sum / sha256sum <file>
    Generate or verify file checksums.


EASTER EGGS - SSH INTO THESE HOSTS
----------------------------------
gibson.ellingson.com    - Hackers (1995) - "Hack the Planet!"
matrix.metacortex.net   - The Matrix - Follow the white rabbit
wopr.norad.gov          - WarGames (1983) - "Shall we play a game?"
fsociety.org            - Mr. Robot - Join the revolution

Explore their home directories for hidden files!
Look for files starting with "." (dotfiles)


SECRET COMMANDS
---------------
cmatrix         - Enter the Matrix
sl              - Surprise!
cowsay <text>   - Moo
figlet <text>   - ASCII art text
lolcat          - Rainbow colors
fortune         - Random wisdom
hollywood       - Hacker movie mode


TIPS
----
- Use 'ls -la' to see hidden files
- Check /etc/shadow for password hashes
- Read .bash_history files for clues
- Use 'cat' or 'less' to read files
- Tab completion works for commands and paths
- Arrow keys navigate command history
- Use '>' to redirect output to a file
- Use '>>' to append to a file


Remember: Curiosity is not a crime.

- The Black Packet Crew
` },
                            'Documents': { type: 'directory', owner: 'user', group: 'user', size: 4096, lastModified: defaultTimestamp, contents: {} },
                            'Downloads': { type: 'directory', owner: 'user', group: 'user', size: 4096, lastModified: defaultTimestamp, contents: {} }
                        }
                    },
                    'blackpacket': {
                        type: 'directory',
                        owner: 'blackpacket',
                        group: 'blackpacket',
                        size: 4096,
                        lastModified: defaultTimestamp,
                        contents: {
                            '.bash_history': { type: 'file', owner: 'blackpacket', group: 'blackpacket', size: 0, lastModified: defaultTimestamp, content: '' },
                            'Documents': { type: 'directory', owner: 'blackpacket', group: 'blackpacket', size: 4096, lastModified: defaultTimestamp, contents: {
                                'readme.txt': { type: 'file', owner: 'blackpacket', group: 'blackpacket', size: 256, lastModified: defaultTimestamp, content: `Welcome to The Black Packet Terminal

This is a simulated Linux terminal environment.
Type 'help' to see available commands.

Remember: Curiosity is not a crime.

- The Black Packet Crew` }
                            }},
                            'Downloads': { type: 'directory', owner: 'blackpacket', group: 'blackpacket', size: 4096, lastModified: defaultTimestamp, contents: {} },
                            'Music': { type: 'directory', owner: 'blackpacket', group: 'blackpacket', size: 4096, lastModified: defaultTimestamp, contents: {} },
                            'Pictures': { type: 'directory', owner: 'blackpacket', group: 'blackpacket', size: 4096, lastModified: defaultTimestamp, contents: {} },
                            'Videos': { type: 'directory', owner: 'blackpacket', group: 'blackpacket', size: 4096, lastModified: defaultTimestamp, contents: {} },
                            'tools': { type: 'directory', owner: 'blackpacket', group: 'blackpacket', size: 4096, lastModified: defaultTimestamp, contents: {
                                'scanner.py': { type: 'file', owner: 'blackpacket', group: 'blackpacket', size: 150, lastModified: defaultTimestamp, content: `#!/usr/bin/env python3
# Black Packet Network Scanner v1.0
import socket
import sys

def scan(target, ports):
    for port in ports:
        try:
            s = socket.socket()
            s.settimeout(1)
            s.connect((target, port))
            print(f"[+] Port {port} is open")
            s.close()
        except:
            pass

if __name__ == "__main__":
    print("Black Packet Scanner - Use responsibly")` }
                            }}
                        }
                    }
                }
            },
            'etc': {
                type: 'directory',
                owner: 'root',
                group: 'root',
                size: 4096,
                lastModified: defaultTimestamp,
                contents: {
                    'hosts': { type: 'file', owner: 'root', group: 'root', size: 120, lastModified: defaultTimestamp, content: `127.0.0.1        localhost
::1              localhost
192.168.1.100    blackpacket
10.0.0.1         gateway` },
                    'passwd': { type: 'file', owner: 'root', group: 'root', size: 200, lastModified: defaultTimestamp, content: `root:x:0:0:root:/home/root:/bin/bash
user:x:1000:1000:User Account:/home/user:/bin/bash
blackpacket:x:1001:1001:Black Packet:/home/blackpacket:/bin/bash` },
                    'shadow': { type: 'file', owner: 'root', group: 'shadow', size: 150, lastModified: defaultTimestamp, content: `root:$6$salt$5H0tMmUm7cxX8uQn3q9w1rY4vP2lK6jD8fE3gB9hN7sA4mT1vR0pL5kJ6hG8fD3s:19000:0:99999:7:::
user:$6$salt$2F8kLmPq3rT5nY9wX1vU7hJ4gD6sA8mB2cN1vM9rT4pL6hK8jF5gD3sA1nM7vR9p:19000:0:99999:7:::
blackpacket:$6$salt$3N9mPr2tY5wV8xU1hK7jL4gF6sD8aM2bC3nV1mR9tP4lH6kJ8fG5dS3aM7nV1rP9:19000:0:99999:7:::` },
                    'sudoers': { type: 'file', owner: 'root', group: 'root', size: 100, lastModified: defaultTimestamp, content: `# Sudoers file
root    ALL=(ALL:ALL) ALL
user    ALL=(ALL:ALL) ALL
blackpacket    ALL=(ALL:ALL) ALL` },
                    'motd': { type: 'file', owner: 'root', group: 'root', size: 200, lastModified: defaultTimestamp, content: `
 ████████╗██╗  ██╗███████╗    ██████╗ ██╗      █████╗  ██████╗██╗  ██╗
 ╚══██╔══╝██║  ██║██╔════╝    ██╔══██╗██║     ██╔══██╗██╔════╝██║ ██╔╝
    ██║   ███████║█████╗      ██████╔╝██║     ███████║██║     █████╔╝
    ██║   ██╔══██║██╔══╝      ██╔══██╗██║     ██╔══██║██║     ██╔═██╗
    ██║   ██║  ██║███████╗    ██████╔╝███████╗██║  ██║╚██████╗██║  ██╗
    ╚═╝   ╚═╝  ╚═╝╚══════╝    ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
                        ██████╗  █████╗  ██████╗██╗  ██╗███████╗████████╗
                        ██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝╚══██╔══╝
                        ██████╔╝███████║██║     █████╔╝ █████╗     ██║
                        ██╔═══╝ ██╔══██║██║     ██╔═██╗ ██╔══╝     ██║
                        ██║     ██║  ██║╚██████╗██║  ██╗███████╗   ██║
                        ╚═╝     ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝

                     CURIOSITY IS NOT A CRIME

` }
                }
            },
            'bin': {
                type: 'directory',
                owner: 'root',
                group: 'root',
                size: 4096,
                lastModified: defaultTimestamp,
                contents: {
                    'ls': { type: 'file', owner: 'root', group: 'root', size: 154624, lastModified: defaultTimestamp, content: 'ELF executable' },
                    'cd': { type: 'file', owner: 'root', group: 'root', size: 12, lastModified: defaultTimestamp, content: 'ELF executable' },
                    'pwd': { type: 'file', owner: 'root', group: 'root', size: 101296, lastModified: defaultTimestamp, content: 'ELF executable' },
                    'cat': { type: 'file', owner: 'root', group: 'root', size: 118992, lastModified: defaultTimestamp, content: 'ELF executable' },
                    'echo': { type: 'file', owner: 'root', group: 'root', size: 101136, lastModified: defaultTimestamp, content: 'ELF executable' },
                    'clear': { type: 'file', owner: 'root', group: 'root', size: 10000, lastModified: defaultTimestamp, content: 'ELF executable' },
                    'whoami': { type: 'file', owner: 'root', group: 'root', size: 12, lastModified: defaultTimestamp, content: 'ELF executable' },
                    'date': { type: 'file', owner: 'root', group: 'root', size: 12, lastModified: defaultTimestamp, content: 'ELF executable' },
                    'uname': { type: 'file', owner: 'root', group: 'root', size: 12, lastModified: defaultTimestamp, content: 'ELF executable' },
                    'ping': { type: 'file', owner: 'root', group: 'root', size: 60000, lastModified: defaultTimestamp, content: 'ELF executable' },
                    'w': { type: 'file', owner: 'root', group: 'root', size: 12, lastModified: defaultTimestamp, content: 'ELF executable' },
                    'who': { type: 'file', owner: 'root', group: 'root', size: 12, lastModified: defaultTimestamp, content: 'ELF executable' },
                    'ps': { type: 'file', owner: 'root', group: 'root', size: 170816, lastModified: defaultTimestamp, content: 'ELF executable' },
                    'chmod': { type: 'file', owner: 'root', group: 'root', size: 120656, lastModified: defaultTimestamp, content: 'ELF executable' },
                    'chown': { type: 'file', owner: 'root', group: 'root', size: 100000, lastModified: defaultTimestamp, content: 'ELF executable' },
                    'grep': { type: 'file', owner: 'root', group: 'root', size: 150000, lastModified: defaultTimestamp, content: 'ELF executable' },
                    'more': { type: 'file', owner: 'root', group: 'root', size: 80000, lastModified: defaultTimestamp, content: 'ELF executable' },
                    'less': { type: 'file', owner: 'root', group: 'root', size: 120000, lastModified: defaultTimestamp, content: 'ELF executable' },
                    'hostname': { type: 'file', owner: 'root', group: 'root', size: 101184, lastModified: defaultTimestamp, content: 'ELF executable' },
                    'bash': { type: 'file', owner: 'root', group: 'root', size: 100000, lastModified: defaultTimestamp, content: 'ELF executable' },
                    'which': { type: 'file', owner: 'root', group: 'root', size: 12, lastModified: defaultTimestamp, content: 'ELF executable' },
                    'su': { type: 'file', owner: 'root', group: 'root', size: 60000, lastModified: defaultTimestamp, content: 'ELF executable' },
                    'sudo': { type: 'file', owner: 'root', group: 'root', size: 160000, lastModified: defaultTimestamp, content: 'ELF executable' },
                    'useradd': { type: 'file', owner: 'root', group: 'root', size: 120000, lastModified: defaultTimestamp, content: 'ELF executable' },
                    'help': { type: 'file', owner: 'root', group: 'root', size: 12000, lastModified: defaultTimestamp, content: 'ELF executable' },
                    'mkdir': { type: 'file', owner: 'root', group: 'root', size: 80000, lastModified: defaultTimestamp, content: 'ELF executable' },
                    'rm': { type: 'file', owner: 'root', group: 'root', size: 90000, lastModified: defaultTimestamp, content: 'ELF executable' },
                    'cp': { type: 'file', owner: 'root', group: 'root', size: 95000, lastModified: defaultTimestamp, content: 'ELF executable' },
                    'mv': { type: 'file', owner: 'root', group: 'root', size: 88000, lastModified: defaultTimestamp, content: 'ELF executable' }
                }
            },
            'usr': {
                type: 'directory',
                owner: 'root',
                group: 'root',
                size: 4096,
                lastModified: defaultTimestamp,
                contents: {
                    'bin': {
                        type: 'directory',
                        owner: 'root',
                        group: 'root',
                        size: 4096,
                        lastModified: defaultTimestamp,
                        contents: {
                            'nmap': { type: 'file', owner: 'root', group: 'root', size: 1000000, lastModified: defaultTimestamp, content: 'ELF executable' },
                            'top': { type: 'file', owner: 'root', group: 'root', size: 241184, lastModified: defaultTimestamp, content: 'ELF executable' },
                            'ssh': { type: 'file', owner: 'root', group: 'root', size: 1557568, lastModified: defaultTimestamp, content: 'ELF executable' },
                            'scp': { type: 'file', owner: 'root', group: 'root', size: 12, lastModified: defaultTimestamp, content: 'ELF executable' },
                            'curl': { type: 'file', owner: 'root', group: 'root', size: 552624, lastModified: defaultTimestamp, content: 'ELF executable' },
                            'wget': { type: 'file', owner: 'root', group: 'root', size: 300000, lastModified: defaultTimestamp, content: 'ELF executable' },
                            'find': { type: 'file', owner: 'root', group: 'root', size: 171280, lastModified: defaultTimestamp, content: 'ELF executable' },
                            'tar': { type: 'file', owner: 'root', group: 'root', size: 274784, lastModified: defaultTimestamp, content: 'ELF executable' },
                            'nc': { type: 'file', owner: 'root', group: 'root', size: 45000, lastModified: defaultTimestamp, content: 'ELF executable' },
                            'john': { type: 'file', owner: 'root', group: 'root', size: 890000, lastModified: defaultTimestamp, content: 'ELF executable' },
                            'hashcat': { type: 'file', owner: 'root', group: 'root', size: 1200000, lastModified: defaultTimestamp, content: 'ELF executable' },
                            'base64': { type: 'file', owner: 'root', group: 'root', size: 38000, lastModified: defaultTimestamp, content: 'ELF executable' },
                            'md5sum': { type: 'file', owner: 'root', group: 'root', size: 42000, lastModified: defaultTimestamp, content: 'ELF executable' },
                            'sha256sum': { type: 'file', owner: 'root', group: 'root', size: 46000, lastModified: defaultTimestamp, content: 'ELF executable' },
                            'strings': { type: 'file', owner: 'root', group: 'root', size: 52000, lastModified: defaultTimestamp, content: 'ELF executable' },
                            'dig': { type: 'file', owner: 'root', group: 'root', size: 186000, lastModified: defaultTimestamp, content: 'ELF executable' },
                            'host': { type: 'file', owner: 'root', group: 'root', size: 48000, lastModified: defaultTimestamp, content: 'ELF executable' },
                            'arp': { type: 'file', owner: 'root', group: 'root', size: 54000, lastModified: defaultTimestamp, content: 'ELF executable' },
                            'telnet': { type: 'file', owner: 'root', group: 'root', size: 92000, lastModified: defaultTimestamp, content: 'ELF executable' },
                            'openssl': { type: 'file', owner: 'root', group: 'root', size: 685000, lastModified: defaultTimestamp, content: 'ELF executable' },
                            'head': { type: 'file', owner: 'root', group: 'root', size: 42000, lastModified: defaultTimestamp, content: 'ELF executable' },
                            'tail': { type: 'file', owner: 'root', group: 'root', size: 44000, lastModified: defaultTimestamp, content: 'ELF executable' },
                            'gzip': { type: 'file', owner: 'root', group: 'root', size: 171728, lastModified: defaultTimestamp, content: 'ELF executable' },
                            'apt': { type: 'file', owner: 'root', group: 'root', size: 500000, lastModified: defaultTimestamp, content: 'ELF executable' },
                            'dpkg': { type: 'file', owner: 'root', group: 'root', size: 800000, lastModified: defaultTimestamp, content: 'ELF executable' },
                            'history': { type: 'file', owner: 'root', group: 'root', size: 50000, lastModified: defaultTimestamp, content: 'ELF executable' },
                            'whois': { type: 'file', owner: 'root', group: 'root', size: 135312, lastModified: defaultTimestamp, content: 'ELF executable' },
                            'nslookup': { type: 'file', owner: 'root', group: 'root', size: 4235872, lastModified: defaultTimestamp, content: 'ELF executable' },
                            'touch': { type: 'file', owner: 'root', group: 'root', size: 101792, lastModified: defaultTimestamp, content: 'ELF executable' },
                            'iwconfig': { type: 'file', owner: 'root', group: 'root', size: 128000, lastModified: defaultTimestamp, content: 'ELF executable' },
                            'airodump-ng': { type: 'file', owner: 'root', group: 'root', size: 256000, lastModified: defaultTimestamp, content: 'ELF executable' },
                            'aircrack-ng': { type: 'file', owner: 'root', group: 'root', size: 384000, lastModified: defaultTimestamp, content: 'ELF executable' },
                            'hydra': { type: 'file', owner: 'root', group: 'root', size: 420000, lastModified: defaultTimestamp, content: 'ELF executable' },
                            'nikto': { type: 'file', owner: 'root', group: 'root', size: 350000, lastModified: defaultTimestamp, content: 'ELF executable' },
                            'sqlmap': { type: 'file', owner: 'root', group: 'root', size: 780000, lastModified: defaultTimestamp, content: 'ELF executable' },
                            'metasploit': { type: 'file', owner: 'root', group: 'root', size: 2500000, lastModified: defaultTimestamp, content: 'ELF executable' },
                            'burpsuite': { type: 'file', owner: 'root', group: 'root', size: 1800000, lastModified: defaultTimestamp, content: 'ELF executable' },
                            'wireshark': { type: 'file', owner: 'root', group: 'root', size: 3200000, lastModified: defaultTimestamp, content: 'ELF executable' }
                        }
                    },
                    'share': {
                        type: 'directory',
                        owner: 'root',
                        group: 'root',
                        size: 4096,
                        lastModified: defaultTimestamp,
                        contents: {
                            'wordlists': {
                                type: 'directory',
                                owner: 'root',
                                group: 'root',
                                size: 4096,
                                lastModified: defaultTimestamp,
                                contents: {
                                    'common.txt': {
                                        type: 'file',
                                        owner: 'root',
                                        group: 'root',
                                        size: 1500,
                                        lastModified: defaultTimestamp,
                                        content: `password
123456
12345678
qwerty
abc123
monkey
letmein
trustno1
dragon
baseball
iloveyou
master
sunshine
ashley
shadow
superman
password1
123123
admin
root
toor
passw0rd
administrator
guest
test
changeme
default
secret
alpine
public
private
securenet123
password123
coffeeshop
guestwifi
admin123
corp2024
secure123
blackpacket
curiosity
hacker
security
network
packet
cyber`
                                    },
                                    'rockyou-sample.txt': {
                                        type: 'file',
                                        owner: 'root',
                                        group: 'root',
                                        size: 800,
                                        lastModified: defaultTimestamp,
                                        content: `123456
password
12345678
qwerty
abc123
123456789
111111
1234567
iloveyou
adobe123
123123
sunshine
princess
azerty
trustno1
000000
password1`
                                    }
                                }
                            }
                        }
                    }
                }
            },
            'sbin': {
                type: 'directory',
                owner: 'root',
                group: 'root',
                size: 4096,
                lastModified: defaultTimestamp,
                contents: {
                    'ifconfig': { type: 'file', owner: 'root', group: 'root', size: 253024, lastModified: defaultTimestamp, content: 'ELF executable' },
                    'netstat': { type: 'file', owner: 'root', group: 'root', size: 400976, lastModified: defaultTimestamp, content: 'ELF executable' },
                    'route': { type: 'file', owner: 'root', group: 'root', size: 169904, lastModified: defaultTimestamp, content: 'ELF executable' },
                    'iptables': { type: 'file', owner: 'root', group: 'root', size: 200000, lastModified: defaultTimestamp, content: 'ELF executable' },
                    'traceroute': { type: 'file', owner: 'root', group: 'root', size: 172048, lastModified: defaultTimestamp, content: 'ELF executable' },
                    'tcpdump': { type: 'file', owner: 'root', group: 'root', size: 2350224, lastModified: defaultTimestamp, content: 'ELF executable' }
                }
            },
            'proc': {
                type: 'directory',
                owner: 'root',
                group: 'root',
                size: 4096,
                lastModified: defaultTimestamp,
                contents: {
                    'version': {
                        type: 'file',
                        owner: 'root', group: 'root', size: 104, lastModified: defaultTimestamp,
                        content: 'Linux version 5.15.0-blackpacket (gcc version 11.2.0) #1 SMP PREEMPT The Black Packet'
                    },
                    'cpuinfo': {
                        type: 'file',
                        owner: 'root', group: 'root', size: 247, lastModified: defaultTimestamp,
                        content: `processor	: 0
vendor_id	: GenuineIntel
cpu family	: 6
model		: 142
model name	: Intel(R) Core(TM) i7-8565U CPU @ 1.80GHz
stepping	: 12
cpu MHz		: 1992.002
cache size	: 8192 KB
bogomips	: 3984.00`
                    },
                    'meminfo': {
                        type: 'file',
                        owner: 'root', group: 'root', size: 133, lastModified: defaultTimestamp,
                        content: `MemTotal:       16384000 kB
MemFree:        10240000 kB
MemAvailable:   12800000 kB
Buffers:          256000 kB
Cached:          2048000 kB
SwapTotal:       8192000 kB
SwapFree:        8192000 kB`
                    },
                    'loadavg': {
                        type: 'file',
                        owner: 'root', group: 'root', size: 23, lastModified: defaultTimestamp,
                        content: '0.08 0.12 0.15 2/512 31337'
                    }
                }
            },
            'dev': {
                type: 'directory',
                owner: 'root',
                group: 'root',
                size: 4096,
                lastModified: defaultTimestamp,
                contents: {
                    'null': { type: 'device', owner: 'root', group: 'root', size: 0, lastModified: defaultTimestamp, content: '' },
                    'zero': { type: 'device', owner: 'root', group: 'root', size: 0, lastModified: defaultTimestamp, content: '' },
                    'random': { type: 'device', owner: 'root', group: 'root', size: 0, lastModified: defaultTimestamp, content: '' },
                    'urandom': { type: 'device', owner: 'root', group: 'root', size: 0, lastModified: defaultTimestamp, content: '' },
                    'tty': { type: 'device', owner: 'root', group: 'root', size: 0, lastModified: defaultTimestamp, content: '' },
                    'console': { type: 'device', owner: 'root', group: 'root', size: 0, lastModified: defaultTimestamp, content: '' },
                    'sda': { type: 'device', owner: 'root', group: 'root', size: 0, lastModified: defaultTimestamp, content: '' },
                    'sda1': { type: 'device', owner: 'root', group: 'root', size: 0, lastModified: defaultTimestamp, content: '' },
                    'sda2': { type: 'device', owner: 'root', group: 'root', size: 0, lastModified: defaultTimestamp, content: '' }
                }
            },
            'tmp': {
                type: 'directory',
                owner: 'root',
                group: 'root',
                size: 4096,
                lastModified: defaultTimestamp,
                contents: {}
            },
            'var': {
                type: 'directory',
                owner: 'root',
                group: 'root',
                size: 4096,
                lastModified: defaultTimestamp,
                contents: {
                    'log': {
                        type: 'directory',
                        owner: 'root',
                        group: 'root',
                        size: 4096,
                        lastModified: defaultTimestamp,
                        contents: {
                            'syslog': { type: 'file', owner: 'root', group: 'root', size: 500, lastModified: defaultTimestamp, content: `Jan 15 08:00:01 blackpacket CRON[1234]: (root) CMD (run-parts /etc/cron.hourly)
Jan 15 08:15:32 blackpacket sshd[5678]: Accepted publickey for blackpacket from 192.168.1.50
Jan 15 08:30:00 blackpacket kernel: [UFW BLOCK] IN=eth0 SRC=10.0.0.5 DST=192.168.1.100
Jan 15 09:00:01 blackpacket systemd[1]: Started Daily apt upgrade and clean activities.` },
                            'auth.log': { type: 'file', owner: 'root', group: 'root', size: 300, lastModified: defaultTimestamp, content: `Jan 15 07:55:12 blackpacket sshd[4321]: Failed password for invalid user admin from 203.0.113.50
Jan 15 07:55:15 blackpacket sshd[4321]: Failed password for invalid user root from 203.0.113.50
Jan 15 08:15:32 blackpacket sshd[5678]: Accepted publickey for blackpacket from 192.168.1.50` }
                        }
                    },
                    'www': {
                        type: 'directory',
                        owner: 'www-data',
                        group: 'www-data',
                        size: 4096,
                        lastModified: defaultTimestamp,
                        contents: {
                            'html': {
                                type: 'directory',
                                owner: 'www-data',
                                group: 'www-data',
                                size: 4096,
                                lastModified: defaultTimestamp,
                                contents: {
                                    'index.html': { type: 'file', owner: 'www-data', group: 'www-data', size: 150, lastModified: defaultTimestamp, content: `<!DOCTYPE html>
<html>
<head><title>The Black Packet</title></head>
<body>
<h1>Welcome to The Black Packet</h1>
<p>Curiosity is not a crime.</p>
</body>
</html>` }
                                }
                            }
                        }
                    }
                }
            },
            'opt': {
                type: 'directory',
                owner: 'root',
                group: 'root',
                size: 4096,
                lastModified: defaultTimestamp,
                contents: {
                    'blackpacket': {
                        type: 'directory',
                        owner: 'root',
                        group: 'root',
                        size: 4096,
                        lastModified: defaultTimestamp,
                        contents: {
                            'tools': {
                                type: 'directory',
                                owner: 'root',
                                group: 'root',
                                size: 4096,
                                lastModified: defaultTimestamp,
                                contents: {
                                    'scanner.py': {
                                        type: 'file',
                                        owner: 'root', group: 'root', size: 256, lastModified: defaultTimestamp,
                                        content: `#!/usr/bin/env python3
# Black Packet Network Scanner v2.0
import socket
import sys
from concurrent.futures import ThreadPoolExecutor

def scan_port(target, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        result = s.connect_ex((target, port))
        s.close()
        return port if result == 0 else None
    except:
        return None

print("Black Packet Scanner - Curiosity is not a crime")`
                                    },
                                    'recon.sh': {
                                        type: 'file',
                                        owner: 'root', group: 'root', size: 180, lastModified: defaultTimestamp,
                                        content: `#!/bin/bash
# Black Packet Recon Script
echo "[*] Starting reconnaissance..."
echo "[*] Target: $1"
nmap -sV -sC $1
echo "[*] Recon complete"`
                                    }
                                }
                            },
                            'config': {
                                type: 'directory',
                                owner: 'root',
                                group: 'root',
                                size: 4096,
                                lastModified: defaultTimestamp,
                                contents: {
                                    'settings.conf': {
                                        type: 'file',
                                        owner: 'root', group: 'root', size: 100, lastModified: defaultTimestamp,
                                        content: `# Black Packet Configuration
DEBUG=false
LOG_LEVEL=info
MAX_THREADS=10
TIMEOUT=30`
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
};

// Environment variables
const environment = {
    PATH: '/bin:/usr/bin:/sbin:/usr/sbin',
    USER: 'user',
    LOGNAME: 'user',
    UID: '1000',
    GID: '1000',
    CWD: '/home/user',
    OLDPWD: '/',
    SHELL: '/bin/bash',
    HOME: '/home/user',
    HOSTNAME: 'blackpacket',
    TERM: 'xterm-256color',
    LANG: 'en_US.UTF-8'
};

// User database
const users = {
    root: { uid: '0', gid: '0', home: '/home/root', shell: '/bin/bash', password: 'toor' },
    user: { uid: '1000', gid: '1000', home: '/home/user', shell: '/bin/bash', password: 'password' },
    blackpacket: { uid: '1001', gid: '1001', home: '/home/blackpacket', shell: '/bin/bash', password: 'curiosity' }
};

// Sudoers list
const sudoers = ['root', 'user', 'blackpacket'];

// User stack for su/exit
let userStack = [];

// Current command history
let currentHistory = [];

// ============================================================================
// FILESYSTEM FUNCTIONS
// ============================================================================

function getDirectory(path) {
    if (path === '/') {
        return filesystem['/'];
    }

    const parts = path.split('/').filter(p => p !== '');
    let current = filesystem['/'];

    for (const part of parts) {
        if (current.contents && current.contents[part] && current.contents[part].type === 'directory') {
            current = current.contents[part];
        } else {
            return false;
        }
    }
    return current;
}

function getFile(path) {
    if (path === '/') {
        return false;
    }

    const parts = path.split('/').filter(p => p !== '');
    const fileName = parts.pop();
    let dirPath = '/' + parts.join('/');
    if (dirPath === '') dirPath = '/';

    const dir = getDirectory(dirPath);
    if (dir === false || !dir.contents || !dir.contents[fileName]) {
        return false;
    }

    return dir.contents[fileName];
}

function getItem(path) {
    // Try as file first
    const file = getFile(path);
    if (file) return file;

    // Try as directory
    return getDirectory(path);
}

function listDirectory(path, showHidden = false) {
    const dir = getDirectory(path);
    if (dir === false || dir.type !== 'directory') {
        return `ls: cannot access '${path}': No such file or directory`;
    }

    let contents = Object.keys(dir.contents || {});
    if (!showHidden) {
        contents = contents.filter(name => !name.startsWith('.'));
    }

    return contents.map(name => {
        const item = dir.contents[name];
        return {
            name: name,
            type: item.type,
            owner: item.owner,
            group: item.group,
            size: item.size,
            lastModified: item.lastModified
        };
    });
}

function changeDirectory(path, currentDirectory) {
    // Use resolvePath to handle all path types including ../.. and ../../
    let targetPath = resolvePath(path, currentDirectory);

    // Clean up path but preserve root
    targetPath = targetPath.replace(/\/+/g, '/');
    if (targetPath !== '/') {
        targetPath = targetPath.replace(/\/$/, '');
    }
    if (!targetPath) {
        targetPath = '/';
    }

    const dir = getDirectory(targetPath);
    if (dir === false || dir.type !== 'directory') {
        return false;
    }

    return targetPath;
}

function readFile(path, currentDirectory) {
    let filePath = resolvePath(path, currentDirectory);
    filePath = filePath.replace(/\/+/g, '/').replace(/\/$/, '') || '/';

    const file = getFile(filePath);
    if (file === false || file.type !== 'file') {
        return false;
    }

    return file.content;
}

function createFile(filename, content, append = false, currentDirectory, owner = null, group = null) {
    let filePath = resolvePath(filename, currentDirectory);
    filePath = filePath.replace(/\/+/g, '/').replace(/\/$/, '');

    const parts = filePath.split('/').filter(p => p !== '');
    const fileName = parts.pop();
    let dirPath = '/' + parts.join('/');
    if (dirPath === '') dirPath = '/';

    const dir = getDirectory(dirPath);
    if (dir === false || dir.type !== 'directory') {
        return false;
    }

    owner = owner || environment.USER;
    group = group || environment.USER;

    if (append && dir.contents[fileName]) {
        // Add newline before appending if existing content doesn't end with one
        const existingContent = dir.contents[fileName].content;
        const needsNewline = existingContent.length > 0 && !existingContent.endsWith('\n');
        dir.contents[fileName].content += (needsNewline ? '\n' : '') + content;
        dir.contents[fileName].size = dir.contents[fileName].content.length;
        dir.contents[fileName].lastModified = generateTimestamp();
    } else {
        dir.contents[fileName] = {
            type: 'file',
            owner: owner,
            group: group,
            size: content.length,
            lastModified: generateTimestamp(),
            content: content
        };
    }

    return true;
}

function createDirectory(path, currentDirectory) {
    let dirPath = resolvePath(path, currentDirectory);
    dirPath = dirPath.replace(/\/+/g, '/').replace(/\/$/, '');

    const parts = dirPath.split('/').filter(p => p !== '');
    const dirName = parts.pop();
    let parentPath = '/' + parts.join('/');
    if (parentPath === '') parentPath = '/';

    const parentDir = getDirectory(parentPath);
    if (parentDir === false || parentDir.type !== 'directory') {
        return { success: false, message: `mkdir: cannot create directory '${path}': No such file or directory` };
    }

    if (parentDir.contents[dirName]) {
        return { success: false, message: `mkdir: cannot create directory '${path}': File exists` };
    }

    parentDir.contents[dirName] = {
        type: 'directory',
        owner: environment.USER,
        group: environment.USER,
        size: 4096,
        lastModified: generateTimestamp(),
        contents: {}
    };

    return { success: true };
}

function deleteItem(path, currentDirectory, recursive = false) {
    let itemPath = resolvePath(path, currentDirectory);
    itemPath = itemPath.replace(/\/+/g, '/').replace(/\/$/, '');

    const parts = itemPath.split('/').filter(p => p !== '');
    const itemName = parts.pop();
    let parentPath = '/' + parts.join('/');
    if (parentPath === '') parentPath = '/';

    const parentDir = getDirectory(parentPath);
    if (parentDir === false || !parentDir.contents || !parentDir.contents[itemName]) {
        return { success: false, message: `rm: cannot remove '${path}': No such file or directory` };
    }

    const item = parentDir.contents[itemName];
    if (item.type === 'directory' && !recursive) {
        if (Object.keys(item.contents || {}).length > 0) {
            return { success: false, message: `rm: cannot remove '${path}': Is a directory` };
        }
    }

    delete parentDir.contents[itemName];
    return { success: true };
}

function resolvePath(path, currentDirectory) {
    // Handle empty path
    if (!path || path === '') {
        return currentDirectory;
    }

    // Handle . (current directory)
    if (path === '.') {
        return currentDirectory;
    }

    // Handle ./ prefix
    if (path.startsWith('./')) {
        path = path.substring(2);
        if (path === '') return currentDirectory;
    }

    let absolutePath;
    if (path.startsWith('/')) {
        absolutePath = path;
    } else if (path.startsWith('~')) {
        absolutePath = environment.HOME + path.substring(1);
    } else {
        absolutePath = currentDirectory === '/' ? `/${path}` : `${currentDirectory}/${path}`;
    }

    // Now resolve . and .. in the path
    const parts = absolutePath.split('/');
    const resolvedParts = [];

    for (const part of parts) {
        if (part === '' || part === '.') {
            // Skip empty parts and current directory references
            continue;
        } else if (part === '..') {
            // Go up one directory (pop from resolved parts)
            if (resolvedParts.length > 0) {
                resolvedParts.pop();
            }
        } else {
            resolvedParts.push(part);
        }
    }

    return '/' + resolvedParts.join('/');
}

// ============================================================================
// USER MANAGEMENT FUNCTIONS
// ============================================================================

function resetToInitialUser() {
    userStack = [];
    const defaultUser = users['user'];
    environment.USER = 'user';
    environment.LOGNAME = 'user';
    environment.UID = defaultUser.uid;
    environment.GID = defaultUser.gid;
    environment.HOME = defaultUser.home;
    environment.CWD = defaultUser.home;
    environment.SHELL = defaultUser.shell;

    const userHistory = loadUserHistory('user');
    currentHistory.length = 0;
    currentHistory.push(...userHistory);
}

function loadUserHistory(username) {
    const userInfo = users[username];
    if (!userInfo) return [];

    const historyPath = `${userInfo.home}/.bash_history`;
    const historyFile = getFile(historyPath);

    if (historyFile && historyFile.content) {
        return historyFile.content.split('\n').filter(line => line.trim() !== '');
    }

    return [];
}

function saveUserHistory(username, history) {
    const userInfo = users[username];
    if (!userInfo) return false;

    const historyPath = `${userInfo.home}/.bash_history`;
    const historyFile = getFile(historyPath);

    if (historyFile) {
        historyFile.content = history.join('\n');
        historyFile.size = historyFile.content.length;
        historyFile.lastModified = generateTimestamp();
        return true;
    }

    return false;
}

function getCurrentHistory() {
    return currentHistory;
}

function setCurrentHistory(history) {
    currentHistory.length = 0;
    currentHistory.push(...history);
}

function addToHistory(command) {
    if (command && command.trim() !== '') {
        currentHistory.unshift(command);
        saveUserHistory(environment.USER, currentHistory);
    }
}

function switchUser(username, pushToStack = true) {
    if (!users[username]) {
        return false;
    }

    saveUserHistory(environment.USER, currentHistory);

    if (pushToStack) {
        userStack.push({
            user: environment.USER,
            uid: environment.UID,
            gid: environment.GID,
            home: environment.HOME,
            cwd: environment.CWD,
            shell: environment.SHELL
        });
    }

    const user = users[username];
    environment.USER = username;
    environment.LOGNAME = username;
    environment.UID = user.uid;
    environment.GID = user.gid;
    environment.HOME = user.home;
    environment.CWD = user.home;
    environment.SHELL = user.shell;

    const newHistory = loadUserHistory(username);
    currentHistory.length = 0;
    currentHistory.push(...newHistory);

    return true;
}

function exitUser() {
    if (userStack.length === 0) {
        return null;
    }

    saveUserHistory(environment.USER, currentHistory);

    const previousUser = userStack.pop();
    environment.USER = previousUser.user;
    environment.UID = previousUser.uid;
    environment.GID = previousUser.gid;
    environment.HOME = previousUser.home;
    environment.CWD = previousUser.cwd;
    environment.SHELL = previousUser.shell;

    const prevHistory = loadUserHistory(previousUser.user);
    currentHistory.length = 0;
    currentHistory.push(...prevHistory);

    return previousUser.user;
}

function addUser(username, password = 'password') {
    if (users[username]) {
        return { success: false, message: `useradd: user '${username}' already exists` };
    }

    const existingUids = Object.values(users).map(u => parseInt(u.uid));
    const newUid = Math.max(...existingUids) + 1;

    users[username] = {
        uid: newUid.toString(),
        gid: newUid.toString(),
        home: `/home/${username}`,
        shell: '/bin/bash',
        password: password
    };

    const homeDir = getDirectory('/home');
    if (homeDir && homeDir.contents) {
        homeDir.contents[username] = {
            type: 'directory',
            owner: username,
            group: username,
            size: 4096,
            lastModified: generateTimestamp(),
            contents: {
                '.bash_history': {
                    type: 'file',
                    owner: username,
                    group: username,
                    size: 0,
                    lastModified: generateTimestamp(),
                    content: ''
                },
                'Documents': {
                    type: 'directory',
                    owner: username,
                    group: username,
                    size: 4096,
                    lastModified: generateTimestamp(),
                    contents: {}
                },
                'Downloads': {
                    type: 'directory',
                    owner: username,
                    group: username,
                    size: 4096,
                    lastModified: generateTimestamp(),
                    contents: {}
                }
            }
        };
    }

    return { success: true, message: `useradd: user '${username}' created with UID ${newUid}` };
}

function canUseSudo(username) {
    return sudoers.includes(username);
}

function verifyPassword(username, password) {
    if (!users[username]) {
        return false;
    }
    return users[username].password === password;
}

function getUserInfo(username) {
    return users[username] || null;
}

// ============================================================================
// EXPORTS
// ============================================================================

export {
    filesystem,
    environment,
    users,
    getDirectory,
    getFile,
    getItem,
    listDirectory,
    changeDirectory,
    readFile,
    createFile,
    createDirectory,
    deleteItem,
    resolvePath,
    generateTimestamp,
    resetToInitialUser,
    loadUserHistory,
    saveUserHistory,
    getCurrentHistory,
    setCurrentHistory,
    addToHistory,
    switchUser,
    exitUser,
    addUser,
    canUseSudo,
    verifyPassword,
    getUserInfo
};
