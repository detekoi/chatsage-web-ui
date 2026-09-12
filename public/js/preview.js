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
    const textEl = panel.querySelector('.ai-preview__text');
    const promptEl = panel.querySelector('.ai-preview__prompt');
    const detailsEl = panel.querySelector('details');
    const controls = [button, argsInput].filter(Boolean);

    function reset() {
        panel.hidden = true;
        textEl.textContent = '';
        promptEl.textContent = '';
        if (detailsEl) detailsEl.open = false;
        if (argsInput) argsInput.value = '';
    }

    /** Show the preview controls only while AI mode is on. */
    function sync() {
        const aiOn = toggle.checked;
        controls.forEach(el => { el.hidden = !aiOn; });
        if (!aiOn) reset();
    }

    function render(preview) {
        textEl.textContent = preview.response || '';
        promptEl.textContent = preview.resolvedPrompt || '';
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
        setMessage(t('status.previewing', {}, 'The AI writes a sample reply. This can take up to 30 seconds.'), 'muted');

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
