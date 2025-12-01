/* ============================================================================
   TERMINAL KIT - Embedded Terminal Module
   A standalone terminal that embeds directly into a container element
   ============================================================================ */

import { environment, resetToInitialUser, addToHistory, getCurrentHistory, listDirectory, resolvePath } from './filesystem.js';
import { processCommand, commands, commandHelp } from './commands.js';

// ============================================================================
// TERMINAL STATE
// ============================================================================

let terminalContainer = null;
let terminalBody = null;
let terminalInnerContent = null;

let commandHistory = [];
let historyIndex = -1;
let currentInputElement = null;
let tabCompletionElement = null;
let isCommandRunning = false;

// ============================================================================
// EXPORTS
// ============================================================================

export function getDisplayPath() {
    const home = environment.HOME;
    const cwd = environment.CWD;
    if (cwd === home) return '~';
    if (cwd.startsWith(home + '/')) return '~' + cwd.substring(home.length);
    return cwd;
}

// ============================================================================
// TERMINAL CREATION
// ============================================================================

export function createTerminal(containerSelector, options = {}) {
    const container = typeof containerSelector === 'string'
        ? document.querySelector(containerSelector)
        : containerSelector;

    if (!container) {
        console.error('[TerminalEmbed] Container not found:', containerSelector);
        return null;
    }

    terminalContainer = container;
    terminalContainer.classList.add('terminal-embed');

    // Create terminal body
    terminalBody = document.createElement('div');
    terminalBody.className = 'terminal-embed-body';
    terminalBody.tabIndex = 0;

    terminalInnerContent = document.createElement('div');
    terminalInnerContent.className = 'terminal-embed-inner';
    terminalBody.appendChild(terminalInnerContent);

    // Assemble terminal
    terminalContainer.appendChild(terminalBody);

    // Print welcome message
    printWelcome();

    // Create first prompt
    createNewPrompt();

    // Focus on click
    terminalBody.addEventListener('click', () => {
        if (currentInputElement) {
            currentInputElement.focus();
        }
    });

    // Add global keydown for Ctrl+C
    document.addEventListener('keydown', handleGlobalKeydown);

    console.log('[TerminalEmbed] Terminal created');
    return terminalContainer;
}

// ============================================================================
// WELCOME MESSAGE
// ============================================================================

function printWelcome() {
    const welcomeText = `
 _____ _____ ____  __  __ ___ _   _    _    _
|_   _| ____|  _ \\|  \\/  |_ _| \\ | |  / \\  | |
  | | |  _| | |_) | |\\/| || ||  \\| | / _ \\ | |
  | | | |___|  _ <| |  | || || |\\  |/ ___ \\| |___
  |_| |_____|_| \\_\\_|  |_|___|_| \\_/_/   \\_\\_____|

Welcome to Terminal Kit - Embedded Terminal
Type 'help' for available commands.
`;
    const pre = document.createElement('pre');
    pre.className = 'terminal-embed-welcome';
    pre.textContent = welcomeText;
    terminalInnerContent.appendChild(pre);
}

// ============================================================================
// PROMPT AND INPUT
// ============================================================================

function createNewPrompt() {
    const promptLine = document.createElement('div');
    promptLine.className = 'terminal-embed-prompt-line';

    const promptSpan = document.createElement('span');
    promptSpan.className = 'terminal-embed-prompt tk-terminal-prompt';
    promptSpan.innerHTML = `<span class="terminal-embed-user">${environment.USER}@${environment.HOSTNAME}</span>:<span class="terminal-embed-path">${getDisplayPath()}</span>$ `;

    const input = document.createElement('input');
    input.type = 'text';
    input.className = 'terminal-embed-input';
    input.spellcheck = false;
    input.autocomplete = 'off';
    input.autocapitalize = 'off';

    promptLine.appendChild(promptSpan);
    promptLine.appendChild(input);
    terminalInnerContent.appendChild(promptLine);

    currentInputElement = input;
    historyIndex = commandHistory.length;

    // Event listeners
    input.addEventListener('keydown', handleInputKeydown);
    input.focus();

    // Scroll to bottom
    terminalBody.scrollTop = terminalBody.scrollHeight;
}

async function handleInputKeydown(e) {
    if (isCommandRunning) {
        e.preventDefault();
        return;
    }

    switch (e.key) {
        case 'Enter':
            e.preventDefault();
            await executeCommand();
            break;

        case 'ArrowUp':
            e.preventDefault();
            navigateHistory(-1);
            break;

        case 'ArrowDown':
            e.preventDefault();
            navigateHistory(1);
            break;

        case 'Tab':
            e.preventDefault();
            performTabCompletion();
            break;

        case 'c':
            if (e.ctrlKey) {
                e.preventDefault();
                handleCtrlC();
            }
            break;

        case 'l':
            if (e.ctrlKey) {
                e.preventDefault();
                clearTerminal();
            }
            break;
    }
}

function handleGlobalKeydown(e) {
    if (e.ctrlKey && e.key === 'c' && isCommandRunning) {
        e.preventDefault();
        handleCtrlC();
    }
}

function handleCtrlC() {
    window.isCommandInterrupted = true;

    if (!isCommandRunning && currentInputElement) {
        // Print ^C and create new prompt
        const output = document.createElement('div');
        output.className = 'terminal-embed-output';
        output.textContent = '^C';
        terminalInnerContent.appendChild(output);

        currentInputElement.disabled = true;
        createNewPrompt();
    }
}

// ============================================================================
// COMMAND EXECUTION
// ============================================================================

async function executeCommand() {
    const command = currentInputElement.value.trim();
    currentInputElement.disabled = true;

    console.log('[TerminalEmbed] Executing command:', command);

    if (command) {
        commandHistory.push(command);
        addToHistory(command);
    }

    if (command === '') {
        createNewPrompt();
        return;
    }

    // Handle clear command specially
    if (command === 'clear') {
        clearTerminal();
        return;
    }

    isCommandRunning = true;
    window.isCommandInterrupted = false;

    try {
        const ctx = {
            outputElement: terminalInnerContent,
            terminalBody: terminalBody,
            terminalInnerContent: terminalInnerContent,
            currentInput: currentInputElement,
            commandHistory: commandHistory,
            username: environment.USER,
            getDisplayPath: getDisplayPath,
            getPromptText: () => `${environment.USER}@${environment.HOSTNAME}:${getDisplayPath()}$ `,
            setNewCurrentDirectory: (newDir, oldDir) => {
                environment.OLDPWD = oldDir;
                environment.CWD = newDir;
            },
            waitKey: async () => {
                return new Promise((resolve) => {
                    const handler = (e) => {
                        document.removeEventListener('keydown', handler);
                        resolve(e.key);
                    };
                    document.addEventListener('keydown', handler);
                });
            }
        };

        const result = await processCommand(command, ctx);
        console.log('[TerminalEmbed] Command result:', result ? result.substring(0, 100) : '(empty)');

        if (result && result.trim()) {
            const output = document.createElement('pre');
            output.className = 'terminal-embed-output';
            output.textContent = result;
            terminalInnerContent.appendChild(output);
        }
    } catch (err) {
        console.error('[TerminalEmbed] Command error:', err);
        const errorOutput = document.createElement('pre');
        errorOutput.className = 'terminal-embed-error';
        errorOutput.textContent = `Error: ${err.message}`;
        terminalInnerContent.appendChild(errorOutput);
    }

    isCommandRunning = false;
    createNewPrompt();
}

// ============================================================================
// HISTORY NAVIGATION
// ============================================================================

function navigateHistory(direction) {
    if (commandHistory.length === 0) return;

    historyIndex += direction;

    if (historyIndex < 0) {
        historyIndex = 0;
    } else if (historyIndex >= commandHistory.length) {
        historyIndex = commandHistory.length;
        currentInputElement.value = '';
        return;
    }

    currentInputElement.value = commandHistory[historyIndex];
    // Move cursor to end
    currentInputElement.setSelectionRange(
        currentInputElement.value.length,
        currentInputElement.value.length
    );
}

// ============================================================================
// TAB COMPLETION
// ============================================================================

function performTabCompletion() {
    const input = currentInputElement.value;
    const cursorPos = currentInputElement.selectionStart;
    const beforeCursor = input.substring(0, cursorPos);
    const parts = beforeCursor.split(/\s+/);
    const currentWord = parts[parts.length - 1];

    if (parts.length === 1) {
        // Complete command names
        const matches = Object.keys(commands).filter(cmd =>
            cmd.startsWith(currentWord.toLowerCase())
        );

        if (matches.length === 1) {
            const completed = matches[0] + ' ';
            currentInputElement.value = completed + input.substring(cursorPos);
            currentInputElement.setSelectionRange(completed.length, completed.length);
        } else if (matches.length > 1) {
            showCompletions(matches);
        }
    } else {
        // Complete file/directory names
        completeFilePath(currentWord, cursorPos, input);
    }
}

function completeFilePath(partial, cursorPos, fullInput) {
    let dirPath, prefix;

    if (partial.includes('/')) {
        const lastSlash = partial.lastIndexOf('/');
        dirPath = partial.substring(0, lastSlash) || '/';
        prefix = partial.substring(lastSlash + 1);

        // Resolve relative paths
        if (!dirPath.startsWith('/')) {
            dirPath = resolvePath(dirPath, environment.CWD);
        }
    } else {
        dirPath = environment.CWD;
        prefix = partial;
    }

    const items = listDirectory(dirPath, true);
    if (typeof items === 'string') return; // Error

    const matches = items
        .filter(item => item.name.startsWith(prefix))
        .map(item => item.name);

    if (matches.length === 1) {
        let completion = matches[0];
        const item = items.find(i => i.name === completion);
        if (item && item.type === 'directory') {
            completion += '/';
        }

        const beforeWord = fullInput.substring(0, cursorPos - partial.length);
        let newPath;
        if (partial.includes('/')) {
            const lastSlash = partial.lastIndexOf('/');
            newPath = partial.substring(0, lastSlash + 1) + completion;
        } else {
            newPath = completion;
        }

        const afterCursor = fullInput.substring(cursorPos);
        currentInputElement.value = beforeWord + newPath + afterCursor;
        const newPos = beforeWord.length + newPath.length;
        currentInputElement.setSelectionRange(newPos, newPos);
    } else if (matches.length > 1) {
        showCompletions(matches);
    }
}

function showCompletions(matches) {
    const output = document.createElement('div');
    output.className = 'terminal-embed-completions';
    output.textContent = matches.join('  ');
    terminalInnerContent.appendChild(output);
    terminalBody.scrollTop = terminalBody.scrollHeight;
}

// ============================================================================
// CLEAR TERMINAL
// ============================================================================

function clearTerminal() {
    terminalInnerContent.innerHTML = '';
    createNewPrompt();
}

// ============================================================================
// PUBLIC API
// ============================================================================

export function printOutput(text, className = 'terminal-embed-output') {
    const output = document.createElement('pre');
    output.className = className;
    output.textContent = text;
    terminalInnerContent.appendChild(output);
    terminalBody.scrollTop = terminalBody.scrollHeight;
}

export function focus() {
    if (currentInputElement) {
        currentInputElement.focus();
    }
}

export function getContainer() {
    return terminalContainer;
}
