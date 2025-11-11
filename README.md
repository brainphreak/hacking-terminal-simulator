# Standalone Terminal - Embeddable Linux Terminal Emulator

A fully functional, self-contained Linux terminal emulator that can be embedded in any website.

## Features

- **Zero Dependencies**: No external libraries required
- **Full Linux Command Support**: Includes ls, cd, cat, grep, ssh, nmap, and 50+ more commands
- **SSH Simulation**: Connect to simulated remote hosts
- **Tab Completion**: File and command auto-completion
- **Command History**: Navigate through command history with arrow keys
- **Virtual Filesystem**: Complete filesystem with /home, /etc, /bin, /usr, /var
- **User Management**: Support for su, sudo, useradd
- **Network Tools**: ping, traceroute, nmap, netstat, ifconfig
- **Customizable**: Easy to style and configure

## Quick Start

### 1. Include the Files

```html
<!DOCTYPE html>
<html>
<head>
    <link rel="stylesheet" href="css/terminal.css">
</head>
<body>
    <div id="my-terminal" style="width: 800px; height: 600px;"></div>

    <script type="module">
        import { StandaloneTerminal } from './js/standalone-terminal.js';

        const terminal = new StandaloneTerminal('my-terminal', {
            welcomeMessage: 'Welcome to My Terminal',
            helpMessage: "Type 'help' for commands"
        });
    </script>
</body>
</html>
```

### 2. File Structure

```
your-project/
├── css/
│   └── terminal.css
├── js/
│   ├── standalone-terminal.js
│   ├── terminal_commands.js
│   └── terminal_filesystem.js
└── index.html
```

## API Reference

### Constructor

```javascript
new StandaloneTerminal(containerId, options)
```

**Parameters:**
- `containerId` (string): The ID of the HTML element to render the terminal in
- `options` (object, optional):
  - `welcomeMessage` (string): Welcome message shown on startup
  - `helpMessage` (string): Help text shown on startup

**Example:**
```javascript
const terminal = new StandaloneTerminal('terminal-container', {
    welcomeMessage: 'Welcome to My Custom Terminal',
    helpMessage: 'Type help for commands'
});
```

### Methods

#### `reset()`
Resets the terminal to initial state, clearing all output and resetting to default user.

```javascript
terminal.reset();
```

#### `destroy()`
Removes the terminal from the DOM completely.

```javascript
terminal.destroy();
```

## Supported Commands

### File System
- `ls` - List directory contents
- `cd` - Change directory
- `pwd` - Print working directory
- `cat` - Display file contents
- `touch` - Create file
- `mkdir` - Create directory
- `rm` - Remove files/directories
- `cp` - Copy files
- `mv` - Move/rename files
- `find` - Search for files
- `grep` - Search file contents

### System
- `whoami` - Show current user
- `hostname` - Show system hostname
- `uname` - System information
- `ps` - Process list
- `top` - System monitor
- `kill` - Terminate processes
- `history` - Command history

### Network
- `ping` - Test network connectivity
- `ssh` - Connect to remote hosts
- `traceroute` - Trace network route
- `nmap` - Network scanner
- `netstat` - Network statistics
- `ifconfig` - Network interfaces
- `wget` - Download files
- `curl` - Transfer data

### User Management
- `su` - Switch user
- `sudo` - Execute as superuser
- `useradd` - Add user
- `passwd` - Change password
- `exit` - Exit current session

### Text Processing
- `more` - Paginate text
- `less` - Advanced paging
- `head` - Show file start
- `tail` - Show file end
- `wc` - Word count
- `sort` - Sort lines

### Utilities
- `echo` - Print text
- `clear` - Clear screen
- `help` - Show available commands
- `which` - Locate commands
- `env` - Show environment
- `export` - Set environment variables

## Customization

### Styling

The terminal can be styled using CSS. All classes are prefixed with `standalone-terminal-`:

```css
.standalone-terminal-container {
    /* Main container */
}

.standalone-terminal-body {
    /* Terminal content area */
    background-color: #000;
    color: #0f0;
}

.standalone-terminal-prompt {
    /* Command prompt */
    color: #0f0;
}

.standalone-terminal-output {
    /* Command output */
}
```

### Colors

Override the default green terminal theme:

```css
.standalone-terminal-body {
    background-color: #1a1a1a;
    color: #ffffff;
}

.standalone-terminal-prompt,
.standalone-terminal-input {
    color: #00bfff; /* Blue theme */
}
```

### Important: Prompt Spacing

The terminal uses precise spacing to prevent "wiggle" (text shifting when commands are entered). The key values are:

```css
.standalone-terminal-prompt {
    margin-right: 8.5px; /* Critical - prevents horizontal wiggle */
}

.standalone-terminal-input {
    margin-bottom: 0px; /* Critical - prevents vertical wiggle */
}
```

**Do not modify these values** unless you experience wiggle. If wiggle occurs, adjust by ±0.5px increments.

## Browser Support

- Chrome/Edge 90+
- Firefox 88+
- Safari 14+
- Opera 76+

Requires ES6 module support.

## License

Open Source GNU GPLv3 - please credit brainphreak.net

## Examples

See the `demo/index.html` file for a complete working example.

See it live at www.brainphreak.net 

### Embedded in a Dashboard

```html
<div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
    <div id="terminal-1"></div>
    <div id="terminal-2"></div>
</div>

<script type="module">
    import { StandaloneTerminal } from './js/standalone-terminal.js';

    new StandaloneTerminal('terminal-1');
    new StandaloneTerminal('terminal-2');
</script>
```

### With Custom Styling

```html
<style>
    #custom-terminal .standalone-terminal-body {
        background: linear-gradient(135deg, #1e3c72, #2a5298);
        font-family: 'Fira Code', monospace;
    }
</style>

<div id="custom-terminal"></div>
```

## Support

For issues, questions, or contributions, brainphreak@brainphreak.net
