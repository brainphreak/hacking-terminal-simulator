/**
 * Standalone Terminal - Embeddable Linux Terminal Emulator
 * No dependencies on external window management systems
 * Can be embedded in any webpage
 */

import { processCommand, listDirectory, resolvePath, environment } from './terminal_commands.js';
import { getDirectory, getFile, loadUserHistory, getCurrentHistory, setCurrentHistory, addToHistory, resetToInitialUser } from './terminal_filesystem.js';

class StandaloneTerminal {
    constructor(containerId, options = {}) {
        this.container = document.getElementById(containerId);
        if (!this.container) {
            throw new Error(`Container element with id "${containerId}" not found`);
        }

        this.options = {
            welcomeMessage: options.welcomeMessage || 'Welcome to Brainphreak Linux Terminal v1.0',
            helpMessage: options.helpMessage || "Type 'help' for available commands",
            ...options
        };

        this.currentInput = null;
        this.historyIndex = -1;
        this.lastTabCompletionOutput = null;

        // Initialize terminal
        this.init();
    }

    init() {
        // Reset to initial user state
        resetToInitialUser();

        // Create terminal HTML
        const terminalHTML = `
            <div class="standalone-terminal-container">
                <div class="standalone-terminal-body" tabindex="-1">
                    <div class="standalone-terminal-inner-content">
                        <div class="standalone-terminal-output">${this.options.welcomeMessage}</div>
                        <div class="standalone-terminal-output">${this.options.helpMessage}</div>
                        <div class="standalone-terminal-output"></div>
                    </div>
                </div>
            </div>
        `;

        this.container.innerHTML = terminalHTML;

        // Get references to elements
        this.terminalContainer = this.container.querySelector('.standalone-terminal-container');
        this.terminalBody = this.container.querySelector('.standalone-terminal-body');
        this.terminalInnerContent = this.container.querySelector('.standalone-terminal-inner-content');

        // Make terminal body focusable
        this.terminalBody.tabIndex = -1;

        // Load command history for current user
        const initialHistory = loadUserHistory(environment.USER);
        setCurrentHistory(initialHistory);
        this.commandHistory = getCurrentHistory();

        // Use global state to avoid closure issues
        window.isCommandRunning = false;
        window.isCommandInterrupted = false;

        // Set up event listeners
        this.setupEventListeners();

        // Add first input line
        this.addInputLine();
    }

    getDisplayPath(path) {
        if (path === environment.HOME) return '~';
        if (path.startsWith(environment.HOME + '/')) return '~' + path.substring(environment.HOME.length);
        return path;
    }

    updatePromptAndTitle() {
        const promptElements = this.terminalInnerContent.querySelectorAll('.standalone-terminal-prompt');
        promptElements.forEach(prompt => {
            prompt.textContent = `${environment.USER}@${environment.HOSTNAME}:${this.getDisplayPath(environment.CWD)}$ `;
        });
    }

    addInputLine() {
        const inputLine = document.createElement('div');
        inputLine.className = 'standalone-terminal-input-line';

        const prompt = document.createElement('span');
        prompt.className = 'standalone-terminal-prompt';
        prompt.textContent = `${environment.USER}@${environment.HOSTNAME}:${this.getDisplayPath(environment.CWD)}$ `;

        const input = document.createElement('input');
        input.className = 'standalone-terminal-input';
        input.type = 'text';

        inputLine.appendChild(prompt);
        inputLine.appendChild(input);
        this.terminalInnerContent.appendChild(inputLine);

        this.currentInput = input;
        input.focus();

        // Scroll to bottom
        requestAnimationFrame(() => {
            this.terminalBody.scrollTop = this.terminalBody.scrollHeight;
        });
    }

    setupEventListeners() {
        // Click to focus
        this.terminalBody.addEventListener('click', () => {
            if (this.currentInput) {
                this.currentInput.focus();
                this.currentInput.setSelectionRange(this.currentInput.value.length, this.currentInput.value.length);
            }
        });

        // Keyboard event handler
        this.terminalBody.addEventListener('keydown', async (e) => {
            await this.handleKeyDown(e);
        });
    }

    async handleKeyDown(e) {
        // Handle Ctrl+C
        if (e.ctrlKey && e.key === 'c') {
            if (window.isWaitingForKey) {
                return;
            }

            if (window.isCommandRunning) {
                window.isCommandInterrupted = true;
                const output = document.createElement('div');
                output.className = 'standalone-terminal-output';
                output.textContent = '^C';
                this.terminalInnerContent.appendChild(output);
                this.terminalBody.scrollTop = this.terminalBody.scrollHeight;
            } else {
                this.currentInput.value += '^C';
                this.currentInput.setAttribute('readonly', true);
                this.addInputLine();
            }
            return;
        }

        // Handle Arrow Up (history)
        if (e.key === 'ArrowUp') {
            e.preventDefault();
            if (this.commandHistory.length > 0) {
                if (this.historyIndex < this.commandHistory.length - 1) {
                    this.historyIndex++;
                    this.currentInput.value = this.commandHistory[this.historyIndex];
                    this.currentInput.focus();
                    setTimeout(() => this.currentInput.setSelectionRange(this.currentInput.value.length, this.currentInput.value.length), 0);
                }
            }
        }

        // Handle Arrow Down (history)
        else if (e.key === 'ArrowDown') {
            e.preventDefault();
            if (this.historyIndex > 0) {
                this.historyIndex--;
                this.currentInput.value = this.commandHistory[this.historyIndex];
                this.currentInput.focus();
                setTimeout(() => this.currentInput.setSelectionRange(this.currentInput.value.length, this.currentInput.value.length), 0);
            } else if (this.historyIndex === 0) {
                this.historyIndex = -1;
                this.currentInput.value = '';
            }
        }

        // Handle Tab (completion)
        else if (e.key === 'Tab') {
            e.preventDefault();
            this.handleTabCompletion();
        }

        // Handle Enter (execute command)
        else if (e.key === 'Enter') {
            e.preventDefault();
            await this.executeCommand();
        }
    }

    handleTabCompletion() {
        const input = this.currentInput.value;
        const parts = input.split(' ');
        let lastPart = parts[parts.length - 1];

        // Handle flag=value syntax
        let prefixBeforeEquals = '';
        if (lastPart.includes('=')) {
            const equalIndex = lastPart.lastIndexOf('=');
            prefixBeforeEquals = lastPart.substring(0, equalIndex + 1);
            lastPart = lastPart.substring(equalIndex + 1);
        }

        if (lastPart.length === 0) {
            return;
        }

        // Command completion logic
        if (parts.length === 1 && prefixBeforeEquals === '') {
            const PATH = environment.PATH.split(':');
            const allCommands = new Set();
            for (const p of PATH) {
                const dir = getDirectory(p);
                if (dir && dir.contents) {
                    Object.keys(dir.contents).forEach(name => {
                        const item = dir.contents[name];
                        if (item.type === 'file' && item.content === 'ELF executable') {
                            allCommands.add(name);
                        }
                    });
                }
            }
            const commandMatches = Array.from(allCommands).filter(cmd => cmd.startsWith(lastPart));
            if (commandMatches.length === 1) {
                this.currentInput.value = commandMatches[0];
                return;
            } else if (commandMatches.length > 1) {
                this.clearLastTabCompletion();
                const output = document.createElement('div');
                output.className = 'standalone-terminal-output';
                output.textContent = commandMatches.join('  ');
                this.terminalInnerContent.appendChild(output);
                this.terminalBody.scrollTop = this.terminalBody.scrollHeight;
                this.lastTabCompletionOutput = output;
                return;
            }
        }

        // Path completion logic
        const path = resolvePath(lastPart, environment.CWD);
        const lastSlashIndex = path.lastIndexOf('/');
        const dirPath = lastSlashIndex === 0 ? '/' : path.substring(0, lastSlashIndex) || environment.CWD;
        const prefix = path.substring(lastSlashIndex + 1);

        const showHidden = lastPart.startsWith('.') || prefix.startsWith('.');
        const dirContents = listDirectory(dirPath, showHidden);

        if (typeof dirContents === 'string') {
            return;
        }

        const matches = dirContents.filter(item => {
            if (showHidden) {
                return item.name.startsWith(prefix);
            }
            return !item.name.startsWith('.') && item.name.startsWith(prefix);
        });

        if (matches.length === 1) {
            const match = matches[0];
            const completion = match.name.substring(prefix.length);

            if (prefixBeforeEquals) {
                const beforeLastPart = parts.slice(0, -1).join(' ');
                const completedPath = prefixBeforeEquals + lastPart + completion;
                this.currentInput.value = beforeLastPart ? beforeLastPart + ' ' + completedPath : completedPath;
            } else {
                this.currentInput.value += completion;
            }

            if (match.type === 'directory') {
                this.currentInput.value += '/';
            }
        } else if (matches.length > 1) {
            this.clearLastTabCompletion();
            const output = document.createElement('div');
            output.className = 'standalone-terminal-output';
            output.textContent = matches.map(m => m.name).join('  ');
            this.terminalInnerContent.appendChild(output);
            this.terminalBody.scrollTop = this.terminalBody.scrollHeight;
            this.lastTabCompletionOutput = output;
        }
    }

    clearLastTabCompletion() {
        if (this.lastTabCompletionOutput && this.lastTabCompletionOutput.parentNode) {
            this.lastTabCompletionOutput.parentNode.removeChild(this.lastTabCompletionOutput);
            this.lastTabCompletionOutput = null;
        }
    }

    async executeCommand() {
        this.clearLastTabCompletion();

        const cmd = this.currentInput.value;
        this.currentInput.setAttribute('readonly', true);

        window.isCommandRunning = true;
        window.isCommandInterrupted = false;

        const { currentDirectory, previousDirectory } = await processCommand(cmd, {
            terminalInnerContent: this.terminalInnerContent,
            terminalBody: this.terminalBody,
            currentInput: this.currentInput,
            commandHistory: this.commandHistory,
            username: environment.USER,
            getDisplayPath: (path) => this.getDisplayPath(path),
            setNewCurrentDirectory: (newDir, oldDir) => {
                environment.CWD = newDir;
                environment.OLDPWD = oldDir;
            },
            waitKey: () => this.waitKey()
        });

        environment.CWD = currentDirectory;
        environment.OLDPWD = previousDirectory;

        window.isCommandRunning = false;

        this.addInputLine();
        this.historyIndex = -1;
    }

    waitKey() {
        return new Promise(resolve => {
            window.isWaitingForKey = true;

            const keydownHandler = (e) => {
                e.preventDefault();
                e.stopImmediatePropagation();
                this.terminalBody.removeEventListener('keydown', keydownHandler);
                window.isWaitingForKey = false;

                if (e.ctrlKey && e.key === 'c') {
                    resolve('CTRL_C');
                } else {
                    resolve(e.key);
                }
            };
            this.terminalBody.addEventListener('keydown', keydownHandler);
        });
    }

    // Public method to destroy terminal
    destroy() {
        this.container.innerHTML = '';
    }

    // Public method to reset terminal
    reset() {
        resetToInitialUser();
        this.terminalInnerContent.innerHTML = `
            <div class="standalone-terminal-output">${this.options.welcomeMessage}</div>
            <div class="standalone-terminal-output">${this.options.helpMessage}</div>
            <div class="standalone-terminal-output"></div>
        `;
        this.addInputLine();
    }
}

// Export for use in other modules or as a global
export { StandaloneTerminal };

// Also make it available globally if not using modules
if (typeof window !== 'undefined') {
    window.StandaloneTerminal = StandaloneTerminal;
}
