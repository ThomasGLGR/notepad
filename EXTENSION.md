# SOC capture extension

The existing Notepad++++ application can also run as a Chrome / Microsoft Edge Manifest V3 extension page. Send selected text or plain-text clipboard content, then return to the investigation. The standalone `index.html` still works directly from disk.

## Install and use

1. Extract `Notepad++++-SOC-Capture-1.3.0.zip` into a folder, or use this project folder directly.
2. Open `chrome://extensions` or `edge://extensions`, enable **Developer mode**, choose **Load unpacked**, and select the folder containing `manifest.json`.
3. Pin **Notepad++++ SOC Capture**. Click its icon to open the existing application. Subsequent clicks focus an existing Note Builder tab.
4. On a supported web page, select text and press **Ctrl + Shift + X** (**Command + Shift + X** on macOS). This sends only the selected text to Note Builder and copies it to the clipboard. An empty or unavailable selection leaves the clipboard unchanged.
5. Continue capturing in other tabs/windows, then return to Note Builder. The focused, visible instance imports pending captures automatically into Summary.

To send the existing clipboard, press **Ctrl + Alt + X** inside Note Builder or a web page activated by Ctrl + Shift + X or the extension icon. This reads only plain text, without reading the page selection or changing the clipboard. The activated-page listener lasts until navigation and requires the page itself to have focus. AltGr, held-key repeats and synthetic page events are excluded.

For a URL in the address bar, copy it normally, return to Note Builder and press Ctrl + Alt + X. The selection shortcut no longer infers a page URL or imports the previous clipboard.

The extension badge shows the number of captures awaiting acknowledgement. Its tooltip confirms capture or explains an empty selection, restricted page or full queue. Imported source captures remain saved internally with the investigation; Summary has no capture counter.

Only **Ctrl + Shift + X** is registered with Chrome/Edge; it can be checked at `chrome://extensions/shortcuts` or `edge://extensions/shortcuts`. Chrome prohibits Ctrl + Alt combinations for registered extension commands, so **Ctrl + Alt + X** uses the focused-page listener described above. Browser/OS shortcuts and other extensions can take precedence. All other custom application shortcuts and the capture context menu are removed; standard browser editing shortcuts remain available.

After updating an existing installation, reload the extension and open web pages, and allow the added clipboard-writing permission. If Chrome retains an old selection binding, set **Ctrl + Shift + X** on the shortcuts page.

Chrome / Chromium-based Edge 116 or newer is required, including `runtime.getContexts` for identifying the extension's own tabs. Installation may be controlled by an organization's extension policy.

## Permissions

| Permission / manifest entry | Purpose |
| --- | --- |
| `activeTab` | Temporary access to the source tab after the shortcut or action gesture. |
| `scripting` | Read selected text and limited field context; install the Ctrl + Alt + X listener and the local JSON receiver in an activated tab. |
| `storage` | Keep the temporary capture queue in `chrome.storage.session`. |
| `clipboardRead` | Read plain text only on Ctrl + Alt + X. |
| `clipboardWrite` | Copy selected text only on Ctrl + Shift + X. |
| `offscreen` | Create a local clipboard document and close it after each read or copy. |
| `commands` manifest entry | Register Ctrl + Shift + X; this is not an additional permission. |
| `content_scripts` on `https://CHANGEME/*` | Start the local JSON receiver on your SIEM pages so a userscript can send JSON without activating the extension first. Replace `CHANGEME` in `manifest.json` with your SIEM address (for example `siem.example.invalid/alerts`), then reload the extension; Chrome asks to approve access to that site once. Until then, activate the page with the extension icon or Ctrl + Shift + X. |

This content script is the only permanent page access: it installs the JSON receiver and nothing else (no selection, clipboard or page reading). Any script on those SIEM pages can send JSON to Note Builder. There are no host permissions, other content scripts, `<all_urls>`, `tabs`, analytics or cloud-sync permissions. The background worker uses the command event's supplied tab; it never searches for a source in a different window. An absent source tab is treated as unavailable.

The clipboard is read once per Ctrl + Alt + X request and written once after a successful Ctrl + Shift + X selection capture. Startup, focus, selection changes and timers never access it. Serialized, authenticated requests open a bundled offscreen HTML document, transfer only `text/plain`, clear its buffer and close the document. Clipboard HTML, images and files are not imported. Page scripts receive status only. If selection copying fails, the captured selection is retained and the tooltip reports the failure. An empty selection or a rejected queue entry does not overwrite the clipboard.

References: [activeTab](https://developer.chrome.com/docs/extensions/develop/concepts/activeTab), [commands and key requirements](https://developer.chrome.com/docs/extensions/reference/api/commands#key-combination-requirements), [offscreen clipboard documents](https://developer.chrome.com/docs/extensions/reference/api/offscreen), [storage.session](https://developer.chrome.com/docs/extensions/reference/api/storage), [runtime.getContexts](https://developer.chrome.com/docs/extensions/reference/api/runtime#method-getContexts).

## Queue and safe import

The service worker owns one queue per browser profile in `chrome.storage.session`. All source tabs/windows use this queue. Each record contains an ID, captured text, timestamp, tab/window IDs, page title, URL when available, bounded context and a capture method (`selection`, `clipboard` or `json`). Existing `page-url` records remain compatible with saved drafts. Metadata contains no page-wide scrape. For clipboard captures, tab/title/URL identify where the shortcut was invoked, not where the text was originally copied; that original source is unavailable. Clipboard text carries no inferred page field label.

Capture gestures and queue read/modify/write operations are serialized, so concurrent captures and acknowledgements cannot overwrite each other. A clipboard import immediately following a selection capture waits for its clipboard copy to finish. Captures are ordered by timestamp. Requests claim batches of up to 20 records with a token, owner and 30-second lease:

`pending → claimed → imported`

Claiming does not delete records. The worker checks the active tab and the browser's last focused window. A second Note Builder cannot take a live claim from a still-focused owner. A newly focused consumer can recover a claim whose owner lost focus; a reload in the same tab replaces the old client. Expired claims are available again.

Note Builder imports a candidate copy of its state through the existing parser, validates and saves it using Current Analysis, and only then acknowledges the claim. Only an acknowledgement with the correct owner, token and complete ID list removes that batch. Captures arriving after the claim remain pending. A failed save leaves the visible state unchanged and the captures available for retry.

Imported capture IDs and source metadata are saved with the investigation. If the page reloads after saving but before acknowledging, replaying those IDs is a no-op and the new page can acknowledge them. A duplicate value appears once, while every distinct capture retains its source internally. The Report contains visible investigation values, not capture URLs or provenance metadata.

Note Builder tabs share the existing Current Analysis draft. Extension tabs avoid saving unchanged stale snapshots; pending edits flush when an extension page loses focus. Captured inputs already saved by another tab of the same investigation are reused before the next capture import, without replacing this tab's Rule, Logs, Analysis or remediation selections. This is a single-investigation workspace, not independent investigations per open tab.

## JSON delivery

JSON objects and arrays from clipboard/selection captures use the same import engine as manual JSON input and `.json` files. The dotted field names remain literal. Objects inside arrays expose their own fields, without container/index prefixes. Distinct values get collision-free numeric suffixes, and duplicate field/value pairs are ignored. Multiline JSON strings remain editable and retain their line breaks. JSON source receipts are saved with the investigation.

The extension icon or selection shortcut also installs a local `window.postMessage` receiver in the activated page's main frame. On the SIEM pages declared in `manifest.json` (`https://CHANGEME/*` until you set it) the receiver starts automatically. The bundled userscript in `tampermonkey/` copies its table as JSON and sends it to Note Builder in the same click. Other scripts can use the same `window.postMessage` protocol. No shortcut or network service is added. See [JSON-IMPORT.md](JSON-IMPORT.md) for integration and the protocol.

Direct JSON sends work between windows in the same browser profile. One designated Note Builder receives JSON in the background without taking focus; ordinary text captures keep their focused-consumer workflow. An inactive Note Builder uses the latest shared draft before committing, preserving the latest notes. Failed saves remain pending and return a bounded error to the sender.

Each send has an ID and SHA-256 digest of canonical JSON. The session queue retains up to 5,000 send receipts after acknowledgement. Replays return their current status; an ID with different data/origin is rejected. The sender sees local receipt first and confirms `imported` only after the app saves and acknowledges. Browser restart/extension reload clears session receipts and pending data; successful app receipts remain in Current Analysis.

## Parsing and existing behavior

The extension transports text only. Capture classification lives in `js/extractors.js` / `js/parser.js`; ordinary Logs still parse explicit `key: value` / `key = value` lines exactly as before.

Unambiguous URLs, valid IPv4/IPv6 addresses, domains, email addresses, common hashes, executable names, paths and recognized command lines receive labels. **Date**, **UUID**, **SID**, **EDR Action** and **Country** are also supported:

- **Date**: valid `YYYY-MM-DD` and `DD/MM/YYYY`, `DD-MM-YYYY` or `DD.MM.YYYY` dates, optionally followed by a time and UTC/offset. Calendar days, leap years and time components are checked. Numeric epochs, partial dates and free-form date text are not guessed. Dates are neither reformatted nor converted to another time zone.
- **UUID**: the complete hexadecimal format with groups of 8-4-4-4-12 characters, also with braces or an `urn:uuid:` prefix. A bare 32-character hexadecimal value still has the existing Hash classification. See [RFC 9562](https://www.rfc-editor.org/rfc/rfc9562.html#section-4).
- **SID**: complete Windows `S-1-…` identifiers with bounded authority/subauthority values; malformed or incomplete strings remain Unknown. See [Microsoft SID syntax](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/c92a27b1-c772-4fa7-a432-15df5f1b66a1).
- **Country**: an upper-case ISO 3166-1 alpha-2 code such as `FR`, or a flag such as 🇫🇷 sent on its own (stored as `FR`). Lower-case words and country names keep their usual type; an explicit label such as `Pays: FR` keeps its own key.
- **EDR Action**: `Mitigated`, `Not mitigated`, `Unmitigated` and equivalent normalized mitigation wording. `Not mitigated` is written `Unmitigated` in Summary and in the report. Generic booleans or action words need an EDR/mitigation label, such as `EDR Action`, `edr_status` or `mitigation_status`. Original values are retained; the tool does not infer remediation success from unrelated text.

Bare `jdupont` and `PC-0042` stay **Unknown** unless a field label supports User or Hostname. Context is limited to 160 characters from input labels, `aria-label`, table headings, definition labels or a few direct nearby text nodes. Cross-origin frame context can be unavailable.

Distinct captured values use available keys such as `IP`, `IP 2`, `IP 3`, `Date 2` or `EDR Action 2`. Existing values and analyst-edited keys are retained. The Summary key inputs suggest all capture types and still accept custom names. Numbered capture fields still work with the existing remediation aliases. Captures never select tactics, Remediation or Recommendations, or write analyst Analysis. Selected remediation wording continues to resolve values through the existing engine.

Capture input is rendered as inert text. Rule, Logs, editing, ordering, copy buttons, report formatting, clipboard newline handling, Undo, defanging and autosave keep their existing workflows. New Investigation clears imported capture data from its draft; Undo can restore it. No AI functionality is added.

This checkout already has no **Save Report `.txt`** control, as described in README. The extension preserves that state and retains the existing Copy Report workflow.

## Limits

- Selection capture works on normal HTTP(S) pages. Browser-internal pages such as `chrome://` and `edge://`, other extensions and browser-restricted pages can prevent injection. Local files require the browser's **Allow access to file URLs** setting.
- The shortcut reads accessible frames. For selection inside an inaccessible frame, copy it normally and use Ctrl + Alt + X in Note Builder. Password inputs are excluded from scripted input selection capture.
- The selection shortcut requires selected text in the page. It never reads the address bar, infers its URL or falls back to importing clipboard text.
- Ctrl + Alt + X requires the extension page or an activated web page to have focus. Navigation removes that page's listener. It cannot run in the address bar, browser-internal pages or an unactivated page. Clipboard permissions or organization policy may prevent capture/copy; the standalone file page does not provide these extension shortcuts.
- Pending data is temporary: browser restart, extension reload/update/disable or removal clears `storage.session`. Worker suspension/restart alone does not clear it. Successfully imported data follows the existing persistent Current Analysis autosave.
- The queue allows at most 1,000 pending records / 3,000,000 selected-text characters and 500,000 characters per selection; browser storage quotas can impose an earlier limit. The parser's 200-value block limit, 2,000-record draft validation, 5,000-source provenance limit and 4,000,000-character autosave limit also apply. Oversized/unsavable imports are retained for retry, not silently truncated or acknowledged.
- The extension page has a different browser origin from `file://` or a hosted standalone page. Its Current Analysis draft is separate; existing standalone drafts are not migrated automatically.
- Separate browser profiles do not share pending captures. Multiple extension tabs are views of the single Current Analysis workspace; simultaneous independent investigations require separate profiles/workspaces.

## Validation

```sh
node --test tests/*.test.cjs
node tests/browser-check.cjs
node tests/extension-browser-check.cjs
```

The data tests cover concurrent captures, multi-window ownership, claims, reload/worker recovery, stale acknowledgements, storage failure, naming, conservative classification, provenance, defanging, parser limits, removal of old commands, restricted pages and message authentication. Clipboard tests cover selection-only capture/copy, clipboard-only import, unchanged clipboard on failed selection, permission refusal, serialized reads/writes, failed-response recovery, buffer cleanup, inert plain text and trusted keyboard events. The original browser suite covers button workflows, removed application shortcuts and clipboard behavior.

The MV3 browser suite loads the real extension into a fresh temporary Chrome profile and grants `activeTab` through a toolbar action. It exercises real script injection, table/input context, several tabs/windows, rapid switching, two Note Builder tabs, automatic import, reload before acknowledgement, duplicate provenance, failed autosave/retry, literal HTML and zero external requests. It seeds synthetic clipboard text before any read, verifies real offscreen reads/writes and closure, and sends trusted DevTools Ctrl + Alt + X events in both the tool and an activated page. Synthetic page keyboard events must not capture. The suite checks registration of only Ctrl + Shift + X and removal of context-menu permission.

Because headless Chrome reports every OS window as focused, the test supplies its chosen window to the worker's focus API while retaining real tab activity, storage, messages and injection. It simulates browser-UI document blur to verify that neither a URL nor stale selection is captured. Command handlers are exercised with their supplied event tabs; OS-level shortcut dispatch and Microsoft Edge should also be checked in the target desktop browser.

The MV3 harness requires a recent Chrome exposing the DevTools `Extensions.loadUnpacked` command and uses `--enable-unsafe-extension-debugging` in a disposable test profile. Set `SOC_BROWSER` to use another compatible executable. Debugging and `--no-sandbox` flags belong to automated tests, not normal extension use.

## Files and packaging

Created:

- `manifest.json`: MV3 declaration, six permissions and one registered shortcut.
- `extension/capture-data.js`: bounded shared metadata validation and supported capture types.
- `extension/capture-queue.js`: serialized session queue and acknowledgement lifecycle.
- `extension/selection.js`: selection/context reader injected on a user gesture.
- `extension/clipboard-client.js`, `extension/clipboard-reader.html`, `extension/clipboard-reader.js`: serialized one-time offscreen clipboard reads/writes.
- `extension/clipboard-shortcut.js`: trusted Ctrl + Alt + X listener in activated pages.
- `extension/service-worker.js`: shortcut/action handlers, JSON delivery and authenticated import transport.
- `js/json-import.js`: shared JSON validation and atomic field import.
- `extension/json-receiver.js`: same-page/origin receiver installed on activation.
- `extension/json-receiver-start.js`: starts that receiver automatically on the SIEM pages declared in `manifest.json`.
- `tampermonkey/optimus-export-json.user.js`: SIEM table exporter that copies the table and sends it directly.
- `JSON-IMPORT.md`: manual import, API and Tampermonkey integration.
- `js/extension-bridge.js`: visible/focused-page import requests and acknowledgements.
- `tests/extension.test.cjs`, `tests/clipboard-capture.test.cjs`, `tests/extension-browser-check.cjs`: extension validation.
- `scripts/package-extension.cjs`: archive packaging using an explicit file list.
- `EXTENSION.md`: installation, design and limits.

Modified: `index.html` (local scripts, key suggestions and hidden capture indicator), `js/app.js` (durable capture import and extension-only stale-save protection), `js/extractors.js` / `js/parser.js` (capture-only classification/import), `js/summary-data.js` / `js/storage.js` (optional capture metadata), `js/summary-editor.js` / `css/style.css` (precise insertion marker, grip dragging, auto-scroll and cancellation), `js/remediation-engine.js` (numbered capture aliases), and `README.md` (extension link and validation).

To build a shareable ZIP:

```sh
node scripts/package-extension.cjs
```

The default output is `../Notepad++++-SOC-Capture.zip`; an optional first argument supplies another output path. The packager refuses to overwrite an existing archive. Only the manifest, app assets, extension code and documentation are included. Tests, development scripts, Codex state, conversations, attachments and browser drafts are outside the packaging list.
