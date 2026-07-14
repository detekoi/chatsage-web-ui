/* global lucide */

let actionToastTimer = null;

/**
 * Create a Lucide circle-check SVG element for inline success indicators.
 * @returns {SVGElement}
 */
export function createSuccessIcon() {
    // Lucide UMD exports icons as PascalCase keys (kebab-case is only for data-lucide attributes)
    const svg = window.lucide.createElement(window.lucide.icons.CircleCheck);
    svg.classList.add('inline-icon', 'inline-icon--success');
    return svg;
}

/**
 * Set an element's content to a success icon followed by a text message.
 * @param {HTMLElement} el - Target element
 * @param {string} text - Message text
 */
export function setSuccessMessage(el, text) {
    el.textContent = '';
    el.appendChild(createSuccessIcon());
    el.appendChild(document.createTextNode(' ' + text));
}

/**
 * Show the action message as a fixed toast notification that auto-dismisses.
 * @param {string} text - Message text
 * @param {'success'|'danger'|'info'|'warning'} type - Bootstrap alert type
 * @param {number} duration - Auto-dismiss delay in ms (0 = no auto-dismiss)
 */
export function showActionToast(text, type = 'info', duration = 4000) {
    const actionMessageEl = document.getElementById('action-message');
    if (!actionMessageEl) return;

    if (actionToastTimer) clearTimeout(actionToastTimer);
    actionMessageEl.textContent = text;
    actionMessageEl.className = `alert alert-${type} action-toast`;
    actionMessageEl.classList.remove('toast-fade-out');
    actionMessageEl.style.display = 'block';
    if (duration > 0) {
        actionToastTimer = setTimeout(() => {
            actionMessageEl.classList.add('toast-fade-out');
            setTimeout(() => {
                actionMessageEl.style.display = 'none';
                actionMessageEl.classList.remove('toast-fade-out');
            }, 400);
        }, duration);
    }
}

/**
 * Debounce a function call
 * @param {Function} fn 
 * @param {number} delay 
 * @returns {Function}
 */
export function debounce(fn, delay) {
    let timerId;
    return (...args) => {
        if (timerId) clearTimeout(timerId);
        timerId = setTimeout(() => fn(...args), delay);
    };
}

/**
 * Inserts variable text into an input field at the cursor position
 * @param {HTMLInputElement|HTMLTextAreaElement} input 
 * @param {string} text 
 */
export function insertAtCursor(input, text) {
    const start = input.selectionStart ?? input.value.length;
    const end = input.selectionEnd ?? input.value.length;
    input.focus();
    input.setRangeText(text, start, end, 'end');
}

/**
 * Sets up a click listener on a container of chips to insert their variable into an input
 * @param {string} containerSelector - Selector for the chip container (e.g., '.timer-chips')
 * @param {HTMLInputElement|HTMLTextAreaElement} targetInput - The input to insert text into
 */
export function setupChipInsertion(containerSelector, targetInput) {
    const container = document.querySelector(containerSelector);
    if (!container) return;

    container.addEventListener('click', (e) => {
        const chip = e.target.closest('.var-chip');
        if (!chip) return;
        const varText = chip.dataset.var;
        insertAtCursor(targetInput, varText);
    });
}
