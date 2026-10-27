/**
 * Tabs for the Wildcat web UIs: the WAI-ARIA tabs pattern with automatic
 * activation. The arrow keys move the focus and open the tab; Home and End
 * go to the first and the last tab. Each app's `npm run sync:design-system`
 * copies this file to public/js/vendor/wc-tabs.js. Do not edit the copies.
 *
 * Markup (design-system.css section 10 styles it):
 *
 *   <ul class="nav nav-tabs" role="tablist" aria-label="…">
 *     <li class="nav-item" role="presentation">
 *       <button class="nav-link active" type="button" role="tab" id="tab-btn-games"
 *         aria-selected="true" aria-controls="tab-games">…</button>
 *     </li>
 *   </ul>
 *   …
 *   <div class="tab-pane" id="tab-games" role="tabpanel" aria-labelledby="tab-btn-games">…</div>
 *
 * Each panel id starts with "tab-". The URL hash names the open tab without
 * that prefix (#games opens #tab-games), so the browser has no element to
 * scroll to. A link or a reload with the hash opens the same tab.
 */

const PANEL_PREFIX = 'tab-';

/**
 * @param {HTMLElement} tablist - the [role="tablist"] element
 * @returns {{ open: (tab: HTMLElement) => void }}
 */
export function initTabs(tablist) {
    const tabs = [...tablist.querySelectorAll('[role="tab"]')];
    const panelOf = tab => document.getElementById(tab.getAttribute('aria-controls'));
    const hashOf = tab => tab.getAttribute('aria-controls').slice(PANEL_PREFIX.length);
    const fromHash = () => {
        const name = decodeURIComponent(location.hash.slice(1));
        return name ? tabs.find(tab => hashOf(tab) === name) : undefined;
    };

    function select(tab) {
        for (const other of tabs) {
            const selected = other === tab;
            other.classList.toggle('active', selected);
            other.setAttribute('aria-selected', String(selected));
            other.tabIndex = selected ? 0 : -1;
            panelOf(other).hidden = !selected;
        }
    }

    // replaceState, not location.hash: the tab is a view of the page, not a
    // new page, so it adds no history entry and fires no hashchange.
    function open(tab) {
        select(tab);
        history.replaceState(history.state, '', `#${hashOf(tab)}`);
    }

    for (const tab of tabs) {
        tab.addEventListener('click', () => open(tab));
        tab.addEventListener('keydown', event => {
            const i = tabs.indexOf(tab);
            // In a right-to-left page the first tab is on the right.
            const forward = getComputedStyle(tablist).direction === 'rtl' ? -1 : 1;
            let next;
            switch (event.key) {
                case 'ArrowRight': next = i + forward; break;
                case 'ArrowLeft': next = i - forward; break;
                case 'ArrowDown': next = i + 1; break;
                case 'ArrowUp': next = i - 1; break;
                case 'Home': next = 0; break;
                case 'End': next = tabs.length - 1; break;
                default: return;
            }
            event.preventDefault();
            const target = tabs[(next + tabs.length) % tabs.length];
            target.focus();
            open(target);
        });
    }

    window.addEventListener('hashchange', () => {
        const tab = fromHash();
        if (tab) select(tab);
    });

    select(fromHash() ?? tabs.find(tab => tab.getAttribute('aria-selected') === 'true') ?? tabs[0]);
    return { open };
}
