import { t, formatNumber } from './i18n.js';
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
 * @param {'success'|'danger'|'info'|'warning'} type - alert variant, maps to .alert-<type>
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

/**
 * Sets up a listener on all numeric inputs to strip non-digits while preserving the caret position
 */
export function setupNumericInputs() {
    document.querySelectorAll('input[inputmode="numeric"]').forEach((input) => {
        input.addEventListener('input', () => {
            const originalValue = input.value;
            const digitsOnly = originalValue.replace(/\D/g, '');
            
            if (originalValue !== digitsOnly) {
                // Calculate how many non-digits were stripped *before* the current cursor position
                const selectionStart = input.selectionStart || 0;
                const textBeforeCursor = originalValue.substring(0, selectionStart);
                const nonDigitsBeforeCursor = (textBeforeCursor.match(/\D/g) || []).length;
                
                input.value = digitsOnly;
                
                // Restore cursor, shifting left by the number of invalid characters that were removed
                const newPos = Math.max(0, selectionStart - nonDigitsBeforeCursor);
                input.setSelectionRange(newPos, newPos);
            }
        });
    });
}

/**
 * Wires a live character counter to a text field.
 *
 * `maxlength` truncates silently, which is confusing on a long field — this
 * shows remaining budget and flags when the limit is reached. The counter is a
 * polite live region so screen readers announce it without interrupting typing.
 *
 * The limit is read from the field's `maxlength` attribute on each update rather
 * than captured here, so callers that learn the limit later (from an API) can
 * set the attribute and refresh without re-attaching a listener.
 *
 * Call this ONCE per field, during setup. It returns a refresh function to call
 * after changing the field's value programmatically — calling it again per load
 * would stack duplicate listeners on the same field.
 *
 * @param {HTMLTextAreaElement|HTMLInputElement} field
 * @param {HTMLElement} counterEl
 * @returns {() => void} Refresh function.
 */
export function setupCharCounter(field, counterEl) {
    if (!field || !counterEl) return () => {};

    counterEl.setAttribute('aria-live', 'polite');
    counterEl.setAttribute('aria-atomic', 'true');

    const update = () => {
        const maxLength = parseInt(field.getAttribute('maxlength'), 10);
        const used = field.value.length;
        counterEl.textContent = Number.isFinite(maxLength)
            ? t('label.charCounterMax', { used: formatNumber(used), max: formatNumber(maxLength) }, `${used} / ${maxLength} characters`)
            : t('label.charCounter', { used: formatNumber(used) }, `${used} characters`);
        counterEl.classList.toggle('char-counter--full', Number.isFinite(maxLength) && used >= maxLength);
    };

    field.addEventListener('input', update);
    update();
    return update;
}

/**
 * Inline add/edit form that unfolds in place. One form element serves both
 * the "Add" slot at the top of a card (its home, where it sits in the markup)
 * and every row's "Edit": open() moves the form next to the anchor row and
 * unfolds it there, close() folds it and parks it back home. Visible state is
 * the `hidden` attribute; the fold/unfold is a Web Animation, so no inline
 * styles are written. Its duration comes from the form's CSS `animation`
 * (see .cmd-form in chatsage-specific.css): `animation: none` there, from the
 * reduced-motion query or a stylesheet that disables animations, makes the
 * fold instant.
 */
export function setupInlineForm(formEl) {
    const home = { parent: formEl.parentNode, next: formEl.nextSibling };
    let hostRow = null;
    let trigger = null;
    let anim = null;

    // Milliseconds for the unfold, 0 when motion is switched off in CSS.
    function motionDuration() {
        const cs = getComputedStyle(formEl);
        if (cs.animationName === 'none') return 0;
        const raw = cs.animationDuration.split(',')[0].trim();
        const seconds = parseFloat(raw) || 0;
        return raw.endsWith('ms') ? seconds : seconds * 1000;
    }

    function settle() {
        if (anim) {
            anim.cancel();
            anim = null;
        }
        formEl.classList.remove('is-animating');
    }

    // Keyframes between folded (zero height, no vertical padding) and the
    // form's natural size at its current position.
    function keyframes() {
        const cs = getComputedStyle(formEl);
        const height = formEl.getBoundingClientRect().height;
        return {
            folded: { height: '0px', paddingTop: '0px', paddingBottom: '0px', opacity: 0 },
            unfolded: { height: `${height}px`, paddingTop: cs.paddingTop, paddingBottom: cs.paddingBottom, opacity: 1 },
        };
    }

    function place(row, button) {
        if (hostRow) hostRow.classList.remove('is-editing');
        if (trigger) trigger.setAttribute('aria-expanded', 'false');
        hostRow = row || null;
        trigger = button || null;
        if (hostRow) {
            hostRow.after(formEl);
            hostRow.classList.add('is-editing');
        } else {
            home.parent.insertBefore(formEl, home.next);
        }
        if (trigger) trigger.setAttribute('aria-expanded', 'true');
    }

    function reveal(animated) {
        formEl.scrollIntoView({ block: 'nearest', behavior: animated ? 'smooth' : 'auto' });
    }

    // Instantly hide the form and return it to its home slot. Also called
    // before a list re-render, which would otherwise wipe the form with the
    // rows it sits between.
    function park() {
        const lastTrigger = trigger;
        // Focus is worth returning when it is inside the form, or already
        // lost to the body (a disabled Save button drops it there).
        const active = document.activeElement;
        const hadFocus = !active || active === document.body || formEl.contains(active);
        settle();
        formEl.hidden = true;
        place(null, null);
        if (hadFocus && lastTrigger && lastTrigger.isConnected) lastTrigger.focus();
    }

    /**
     * Show the form. With `row` (a list item) the form unfolds directly under
     * that row; without it, in its home slot. `trigger` is the button that
     * opened it, for aria-expanded and focus return.
     */
    function open({ row = null, trigger: button = null } = {}) {
        const wasOpenHere = !formEl.hidden && (row || null) === hostRow;
        settle();
        place(row, button);
        formEl.hidden = false;
        if (wasOpenHere) return;
        const duration = motionDuration();
        if (!duration) {
            reveal(false);
            return;
        }
        const { folded, unfolded } = keyframes();
        formEl.classList.add('is-animating');
        anim = formEl.animate([folded, unfolded], { duration, easing: 'cubic-bezier(0.2, 0, 0, 1)' });
        anim.onfinish = () => {
            settle();
            reveal(true);
        };
    }

    function close() {
        if (formEl.hidden) return;
        settle();
        const duration = motionDuration();
        if (!duration) {
            park();
            return;
        }
        const { folded, unfolded } = keyframes();
        formEl.classList.add('is-animating');
        // fill: forwards holds the folded frame until park() hides the form;
        // otherwise the natural height shows for a frame before onfinish runs.
        // park() cancels the finished animation (settle) in the same task it
        // sets hidden, so the held frame never leaks into the next open.
        anim = formEl.animate([unfolded, folded], { duration: duration * 0.75, easing: 'cubic-bezier(0.4, 0, 1, 1)', fill: 'forwards' });
        anim.onfinish = park;
    }

    /**
     * After a list re-render replaced the row that was being edited, put
     * focus on the given element (its new Edit button) if nothing else took it.
     */
    function refocus(el) {
        const active = document.activeElement;
        if (el && (!active || active === document.body)) el.focus();
    }

    return { open, close, park, refocus };
}
