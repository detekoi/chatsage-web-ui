/**
 * AI preview: "what would the bot say?" for an unsaved AI custom command,
 * timed message, or check-in prompt.
 *
 * One helper serves all three forms. It owns the Preview button's visibility
 * (only while AI mode is on), the request, and rendering the result into the
 * form's preview panel. Status text and errors go through the form's own
 * message element via the `setMessage` callback so each section keeps its
 * existing styling.
 */

import { apiPost, AuthError, readJson } from './api.js';
import { DEV_MODE, mockDelay, mockPreview } from './dev-mocks.js';
import { t } from './i18n.js';

/**
 * @param {object} opts
 * @param {'command'|'timer'|'checkin'} opts.kind
 * @param {HTMLButtonElement} opts.button - The Preview button.
 * @param {HTMLElement} opts.panel - Container holding .ai-preview__text and .ai-preview__prompt.
 * @param {HTMLInputElement} opts.promptInput - The AI prompt field.
 * @param {HTMLInputElement} opts.toggle - The AI mode checkbox.
 * @param {HTMLInputElement|null} [opts.argsInput] - Optional sample-arguments field (commands only).
 * @param {() => string} [opts.getName] - Returns the command/timer name, for dedup keying.
 * @param {(text: string, type: 'muted'|'success'|'danger') => void} opts.setMessage - Writes form status.
 * @returns {{ reset: () => void, sync: () => void }}
 */
export function setupPreview({ kind, button, panel, promptInput, toggle, argsInput = null, getName = () => '', setMessage }) {
    const loadingEl = panel.querySelector('.ai-preview__loading');
    const resultEl = panel.querySelector('.ai-preview__result');
    const textEl = panel.querySelector('.ai-preview__text');
    const promptEl = panel.querySelector('.ai-preview__prompt');
    const detailsEl = panel.querySelector('details');
    const controls = [button, argsInput].filter(Boolean);
    // Identifies the latest run, so a reply from an earlier request cannot
    // land after the panel was reset or a newer request started.
    let currentRun = 0;

    function reset() {
        currentRun += 1; // a form open/close mid-request must not reopen the panel
        panel.hidden = true;
        loadingEl.hidden = true;
        resultEl.hidden = true;
        panel.removeAttribute('aria-busy');
        textEl.textContent = '';
        promptEl.textContent = '';
        if (detailsEl) detailsEl.open = false;
        if (argsInput) argsInput.value = '';
    }

    /** The shared progress bar, in place of the previous result while a new one generates. */
    function showLoading() {
        resultEl.hidden = true;
        loadingEl.hidden = false;
        panel.hidden = false;
        panel.setAttribute('aria-busy', 'true');
    }

    function hideLoading() {
        loadingEl.hidden = true;
        panel.removeAttribute('aria-busy');
        // Nothing to show: collapse the panel rather than leave an empty box.
        if (resultEl.hidden) panel.hidden = true;
    }

    /** Show the preview controls only while AI mode is on. */
    function sync() {
        const aiOn = toggle.checked;
        controls.forEach(el => { el.hidden = !aiOn; });
        if (!aiOn) {
            currentRun += 1; // invalidate any request still in flight
            reset();
        }
    }

    function render(preview) {
        textEl.textContent = preview.response || '';
        promptEl.textContent = preview.resolvedPrompt || '';
        resultEl.hidden = false;
        panel.hidden = false;
    }

    async function run() {
        const prompt = promptInput.value.trim();
        if (!prompt) {
            setMessage(t('validation.previewPromptRequired', {}, 'Enter an AI prompt, then select Preview.'), 'danger');
            promptInput.focus();
            return;
        }

        button.disabled = true;
        // The progress bar in the panel carries the status text; the form
        // message stays clear until there is an outcome to report.
        setMessage('', 'muted');
        showLoading();
        const runId = ++currentRun;

        try {
            let data;
            if (DEV_MODE) {
                await mockDelay(800);
                data = mockPreview(kind, prompt, argsInput ? argsInput.value.trim() : '');
            } else {
                const body = { kind, prompt, name: getName() || undefined };
                if (argsInput && argsInput.value.trim()) body.args = argsInput.value.trim();
                const res = await apiPost('/api/preview', body);
                data = await readJson(res);
            }

            // AI mode was switched off, the form closed, or a newer preview
            // started while this one was in flight: the panel was reset, keep it so.
            if (runId !== currentRun || !toggle.checked) return;

            hideLoading();
            if (data.success && data.preview) {
                render(data.preview);
                setMessage(t('status.previewReady', {}, 'The preview is ready.'), 'success');
            } else {
                // The bot may have resolved the prompt but produced nothing: still
                // worth showing what it was asked, next to the explanation.
                if (data.preview?.resolvedPrompt) {
                    render({ ...data.preview, response: '' });
                }
                setMessage(data.message || t('toast.previewFailed', {}, 'The preview failed. Try again.'), 'danger');
            }
        } catch (e) {
            if (runId !== currentRun || !toggle.checked) return;
            hideLoading();
            if (e instanceof AuthError) return;
            console.error('Error generating preview:', e);
            setMessage(t('toast.previewFailed', {}, 'The preview failed. Try again.'), 'danger');
        } finally {
            button.disabled = false;
        }
    }

    button.addEventListener('click', run);
    toggle.addEventListener('change', sync);
    sync();

    return { reset, sync };
}
