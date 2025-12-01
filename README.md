# Hacking Terminal Simulator

A standalone hacking terminal simulator that embeds directly into any webpage. No floating windows, no taskbar - just a fully functional Linux-like terminal that integrates seamlessly into your site.

![Hacking Terminal](https://img.shields.io/badge/version-1.0.0-green) ![License](https://img.shields.io/badge/license-GPLv3-blue)

## Live Demo

Open `demo/index.html` to see it in action!

**Live Site:** [theblackpacket.com](https://theblackpacket.com)

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/F2F35TO7X)

## Features

- **Embedded Terminal** - Renders directly into any container element
- **70+ Commands** - Full Linux-like command set
- **Hacking Tools** - aircrack-ng, john, hashcat, nmap, and more
- **SSH Easter Eggs** - Connect to movie-themed servers (Hackers, Matrix, WarGames, Mr. Robot)
- **Tab Completion** - Auto-complete commands and file paths
- **Command History** - Navigate with arrow keys
- **Multiple Themes** - Green, amber, blue, red, and white color schemes
- **Mobile Friendly** - Responsive design that works on all devices
- **Zero Dependencies** - No external libraries required

## Quick Start

### 1. Include the CSS

```html
<link rel="stylesheet" href="terminal-kit-embed/terminal-embed.css">
```

### 2. Create a Container

```html
<div id="terminal" style="width: 100%; height: 500px;"></div>
```

### 3. Initialize

```html
<script type="module">
    import { TerminalEmbed } from './terminal-kit-embed/index.js';

    TerminalEmbed.init('#terminal');
</script>
```

That's it! You now have a fully functional terminal embedded in your page.

## Installation

### Option 1: Direct Download

1. Download the `src/` folder
2. Rename it to `terminal-kit-embed/`
3. Place it in your project
4. Include CSS and JS as shown above

### Option 2: Clone Repository

```bash
git clone https://github.com/brainphreak/hacking-terminal-simulator.git
```

## Usage Examples

### Basic Usage

```html
<!DOCTYPE html>
<html>
<head>
    <link rel="stylesheet" href="terminal-kit-embed/terminal-embed.css">
    <style>
        #terminal {
            width: 800px;
            height: 500px;
            margin: 50px auto;
        }
    </style>
</head>
<body>
    <div id="terminal"></div>

    <script type="module">
        import { TerminalEmbed } from './terminal-kit-embed/index.js';
        TerminalEmbed.init('#terminal');
    </script>
</body>
</html>
```

### Auto-Initialization

Use the `data-terminal-embed` attribute for automatic initialization:

```html
<div data-terminal-embed style="width: 100%; height: 400px;"></div>

<script type="module" src="terminal-kit-embed/index.js"></script>
```

### Using Size Presets

```html
<div id="terminal" class="small"></div>  <!-- 300px height -->
<div id="terminal" class="medium"></div> <!-- 450px height -->
<div id="terminal" class="large"></div>  <!-- 600px height -->
```

### Fullscreen Mode

```html
<div id="terminal" class="fullscreen"></div>
```

### With Scanline Effect

```html
<div id="terminal" class="scanlines"></div>
```

## Themes

Add a theme class to change the terminal colors:

```html
<!-- Green (default) -->
<div id="terminal" class="theme-green"></div>

<!-- Amber/Orange -->
<div id="terminal" class="theme-amber"></div>

<!-- Blue/Cyan -->
<div id="terminal" class="theme-blue"></div>

<!-- Red -->
<div id="terminal" class="theme-red"></div>

<!-- White -->
<div id="terminal" class="theme-white"></div>
```

### Combining Classes

```html
<div id="terminal" class="theme-amber scanlines large"></div>
```

## API Reference

```javascript
// Initialize terminal in a container
TerminalEmbed.init('#container');
TerminalEmbed.init(document.getElementById('terminal'));

// Print output to terminal
TerminalEmbed.printOutput('Hello, World!');
TerminalEmbed.printOutput('Error!', 'terminal-embed-error');

// Focus the terminal input
TerminalEmbed.focus();

// Get the container element
const container = TerminalEmbed.getContainer();

// Check if initialized
if (TerminalEmbed.isInitialized()) { ... }
```

## Available Commands

### File Operations
`ls`, `cd`, `pwd`, `cat`, `head`, `tail`, `more`, `less`, `touch`, `mkdir`, `rm`, `cp`, `mv`, `find`, `grep`, `chmod`, `chown`, `tar`, `gzip`

### Network Tools
`ping`, `nmap`, `traceroute`, `ssh`, `scp`, `curl`, `wget`, `nc`, `telnet`, `ifconfig`, `netstat`, `whois`, `nslookup`, `dig`, `host`

### Wireless/Hacking Tools
`iwconfig`, `airodump-ng`, `aircrack-ng`, `john`, `hashcat`, `base64`, `md5sum`, `sha256sum`, `openssl`, `strings`

### System
`whoami`, `hostname`, `uname`, `date`, `ps`, `top`, `history`, `clear`, `help`

### User Management
`su`, `sudo`, `useradd`, `exit`

## Easter Eggs & Hacking Challenges

### WiFi Cracking

```bash
iwconfig
airodump-ng wlan0
airodump-ng -w capture --bssid AA:BB:CC:DD:EE:FF -c 6 wlan0
aircrack-ng -w /usr/share/wordlists/rockyou.txt capture-01.cap
```

### Password Cracking

```bash
cat /etc/shadow
john --wordlist=/usr/share/wordlists/rockyou.txt /etc/shadow
john --show /etc/shadow
```

### SSH to Movie Servers

```bash
# Hackers (1995)
ssh root@gibson.ellingson.com

# The Matrix (1999)
ssh neo@matrix.metacortex.com

# WarGames (1983)
ssh joshua@wopr.norad.gov

# Mr. Robot (2015)
ssh elliot@fsociety.org
```

### Base64 Encoded Secrets

```bash
ssh neo@matrix.metacortex.com
cat .encoded_message
echo "VGhlcmUgaXMgbm8gc3Bvb24u" | base64 -d
# Output: There is no spoon.
```

## Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `Enter` | Execute command |
| `Tab` | Auto-complete |
| `Up Arrow` | Previous command |
| `Down Arrow` | Next command |
| `Ctrl+C` | Interrupt command |
| `Ctrl+L` | Clear screen |

## File Structure

```
terminal-kit-embed/
├── index.js            # Main entry point
├── terminal-embed.js   # Terminal implementation
├── commands.js         # All command implementations
├── filesystem.js       # Virtual filesystem
└── terminal-embed.css  # Styles and themes
```

## Customization

### Custom Container Styling

```css
#my-terminal {
    width: 100%;
    max-width: 900px;
    height: 600px;
    margin: 0 auto;
    border-radius: 12px;
}
```

### Custom Welcome Message

Modify the `printWelcome()` function in `terminal-embed.js` to customize the welcome message.

### Adding Custom Commands

Add new commands to the `commands` object in `commands.js`:

```javascript
mycommand: {
    isBuiltin: false,
    execute: async (args, ctx) => {
        return 'Hello from my custom command!';
    }
}
```

## Browser Support

- Chrome 80+
- Firefox 75+
- Safari 13+
- Edge 80+
- Mobile Safari (iOS 13+)
- Chrome for Android

## Comparison: Embed vs Overlay

| Feature | Terminal Kit Embed | Terminal Kit (Overlay) |
|---------|-------------------|------------------------|
| Floating windows | No | Yes |
| Taskbar | No | Yes |
| Music player | No | Yes |
| Matrix rain | No | Yes |
| Embedded in page | Yes | Overlays page |
| Use case | In-page terminal | Desktop simulation |

## Related Projects

- [Terminal Kit](https://github.com/brainphreak/terminal-kit) - Full overlay version with taskbar, music player, and matrix rain

## License

This project is licensed under the GPLv3 License.

## Credits

Created by [brainphreak](https://brainphreak.net)

## Contributing

Contributions welcome! Please submit a Pull Request.
