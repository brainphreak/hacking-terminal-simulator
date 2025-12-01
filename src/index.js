/* ============================================================================
   TERMINAL KIT EMBED - Main Entry Point
   A standalone terminal that embeds directly into any webpage

   Usage:
   import { TerminalEmbed } from './terminal-kit-embed/index.js';

   TerminalEmbed.init('#terminal-container');
   // or
   TerminalEmbed.init(document.getElementById('my-terminal'));
   ============================================================================ */

import { createTerminal, printOutput, focus, getContainer, getDisplayPath } from './terminal-embed.js';

// ============================================================================
// TERMINAL EMBED CONFIGURATION
// ============================================================================

const defaultConfig = {
    welcomeMessage: true,
    focusOnInit: true
};

let isInitialized = false;
let currentConfig = null;

// ============================================================================
// INITIALIZATION
// ============================================================================

function init(containerSelector, config = {}) {
    if (isInitialized) {
        console.warn('[TerminalEmbed] Already initialized');
        return getContainer();
    }

    currentConfig = { ...defaultConfig, ...config };

    console.log('[TerminalEmbed] Initializing...');

    const terminal = createTerminal(containerSelector, currentConfig);

    if (terminal) {
        isInitialized = true;
        console.log('[TerminalEmbed] Initialization complete');

        if (currentConfig.focusOnInit) {
            focus();
        }
    }

    return terminal;
}

// ============================================================================
// PUBLIC API
// ============================================================================

const TerminalEmbed = {
    // Initialization
    init,

    // Terminal controls
    printOutput,
    focus,
    getContainer,

    // Status
    isInitialized: () => isInitialized,
    getConfig: () => currentConfig
};

// ============================================================================
// AUTO-INITIALIZATION
// ============================================================================

document.addEventListener('DOMContentLoaded', () => {
    // Look for elements with data-terminal-embed attribute
    const autoInitElements = document.querySelectorAll('[data-terminal-embed]');
    autoInitElements.forEach(el => {
        if (!isInitialized) {
            init(el);
        }
    });
});

// ============================================================================
// EXPORTS
// ============================================================================

export { TerminalEmbed };
export default TerminalEmbed;

// Expose to window for non-module usage
if (typeof window !== 'undefined') {
    window.TerminalEmbed = TerminalEmbed;
}
