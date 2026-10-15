# Notepad++++

A compact investigation workspace. Open `index.html` directly in a browser; keep `css/` and `js/` beside it. No installation or build step is required.

An optional Chrome / Microsoft Edge capture extension opens the same application as an extension page. **Ctrl + Shift + X** sends selected text to Note Builder and copies that text to the clipboard. **Ctrl + Alt + X** sends only the existing plain-text clipboard to Note Builder, leaving it unchanged. Return to the focused Note Builder for automatic import. See [EXTENSION.md](EXTENSION.md) for installation, permissions and limitations.

Ctrl + Alt + X works inside the extension's Note Builder page and web pages activated through Ctrl + Shift + X or the extension icon, until navigation. Chrome prohibits Ctrl + Alt combinations for registered extension commands, so this shortcut requires the page itself to have focus. To send a URL from the address bar, copy it normally, return to Note Builder and press Ctrl + Alt + X.

Clipboard reading happens only on Ctrl + Alt + X; Ctrl + Shift + X only writes the selected text. Reload the extension and open web pages after updating, and allow the added clipboard-writing permission. Other application shortcuts and the capture context menu are removed. Standard browser editing shortcuts retain their usual behavior.

JSON objects and arrays can be pasted into Logs, opened from a `.json` file, or imported with `SOCNote.importJSON(data)`. Dotted field names stay literal; objects inside arrays expose their own fields without container prefixes. Distinct values receive suffixes, duplicates are ignored, and existing notes remain intact. The bundled userscript in `tampermonkey/` copies a SIEM alert table as JSON and sends it directly to the extension's Note Builder in the same click. The extension listens automatically on the SIEM address set in `manifest.json` (replace `CHANGEME`); elsewhere, activate the page with the extension icon first. A copied export also works through Ctrl + Alt + X. See [JSON-IMPORT.md](JSON-IMPORT.md) for other scripts.

## Layout and workflow

The header shows the logo to the left of **Notepad++++**, with New and Undo on the right. Below it, **Rule** and the **MITRE ATT&CK** selector share one line. The workspace has two equal columns: Logs and a taller Summary on the left, Analysis spanning their combined height on the right. Summary has at least 540 px of vertical space on desktop; windows 1100 px wide or less stack every card one above the other and give both Summary and Analysis a height of 560 px. Report spans the full width below them. Each card keeps its buttons in its heading.

Remediation and Recommendations are withdrawn from the page and from the report for now. Their catalogue, engine, editor and tests remain, and selections saved in a draft are kept. Setting `features.remediation` to `true` in `js/templates.js` brings both sections, their report block and their tactic rows back.

1. Paste or type the **Rule**. It becomes the report title immediately.
2. Choose **MITRE ATT&CK** tactics and techniques beside it; see below.
3. Paste logs into **Logs**, or use **Open** to read a local text file. Explicit `key: value` and `key = value` lines are extracted. **Add to summary**, or **Ctrl+Enter** while editing Logs, clears the input while preserving the submitted text and pairs. Enter alone inserts a line break.
4. Review **Summary**. Edit category titles and values side by side, with most of the row width reserved for the value. Drag the grip or a card onto a row within the left fifteenth of the full Summary width to place it above or below; a horizontal line marks the insertion point. Drop onto a category within the remaining fourteen fifteenths of Summary to insert as its first subcategory. Dropping onto a subcategory inserts directly below it with the same parent. The boundary is shared by all rows, including indented subcategories; their left margins also accept drops. Right-side gaps use the row immediately above the pointer. The parent card highlights, and an indented insertion line appears when dropping after a subcategory. The **+** immediately to the right of each top-level category’s drag grip opens a form below it to add a subcategory manually. **+ Category** still adds a top-level category. There is only one subcategory level: a child cannot receive children, and a category with children cannot be nested. When the requested drop is impossible, a full-width insertion line marks the first available top-level gap below the target’s complete group; dropping there keeps any children with their parent. Drag a child onto a top-level row within the left fifteenth of Summary to return it to the top level. Moving a parent carries its children; removing a parent keeps its children at the top level. The ServiceNow logo immediately to the left of Copy opens a page for that row’s value, including subcategories. Long lists scroll near an edge; Escape cancels a drag. Undo restores changes. Each distinct value appears once, and identical values group their keys. Deleting a value allows it to be imported again, including after draft recovery; Undo restores the deleted category. Copy controls copy only values.
5. Write **Analysis**. The report updates as Rule, MITRE ATT&CK, Summary or Analysis changes.
6. Use **Copy report**, then **New** for another alert.

New clears Rule, MITRE ATT&CK, Logs, Summary, Analysis, Report and the Current Analysis draft. Undo can restore a reset while the page remains open.

Dates and timestamps have a compact time-zone menu with **UTC** selected by default, UTC offsets and a blank option. The report adds the selection in parentheses, for example `timestamp: 2026-10-14T23:12:00Z (UTC)`. The blank option hides this annotation, including on subcategories. The selected zone is saved with the draft. This labels the value as written; value-only copies keep the original date or timestamp. Detection covers valid ISO and day/month/year dates, with optional times, plus Unix seconds or milliseconds under an explicit date/time key.

The interface uses neutral gray editable fields without dark resting borders. Read-only fields and non-editable backgrounds use light blue tints; read-only text remains selectable for copying. Disabled controls use a `not-allowed` cursor and readable text. All editable fields use 13 px text. Rule and MITRE ATT&CK use the same title typography as the other sections, with both labels, fields and the Tactics button on one row at desktop widths. The Raw Text block is removed from Logs; submitted sources remain in the draft, and native copying from pending Logs preserves original line endings. New uses the same primary style as Copy report. Buttons use three visual families: primary, secondary and transparent icon actions, each with clear hover, focus and active states. A thin focus ring replaces large input halos, and motion is removed when the system requests reduced motion. The browser checks measure interface text and placeholder contrast against the [WCAG enhanced contrast threshold of 7:1](https://www.w3.org/WAI/WCAG22/Understanding/contrast-enhanced.html), and keyboard focus against the [3:1 non-text contrast threshold](https://www.w3.org/WAI/WCAG22/Understanding/non-text-contrast.html). Layouts are checked from 320 to 1440 px. The interface styles preserve the Report’s 14 px font, colors and clipboard fidelity.

## Report copying

The report has three parts: the title (Rule), **SUMMARY** and **ANALYSIS**. One plain-text formatter supplies the preview and clipboard, so the preview's text is exactly the copied text.

- **Preview.** A white report in a 14 px monospace font, without filled sections. Each section heading is centered between two lines of 50 `=` characters. One blank line separates the title from the first separator. The rich copy also carries the 14 px monospace font.
- **Summary.** Selected MITRE ATT&CK tactics and techniques come first as one key/value line: `MITRE ATT&CK: Execution (TA0002), Valid Accounts (T1078)`. Values are separated by commas; each parenthesized ID from the bundled list links to its page on attack.mitre.org. IOC and technical values follow, one blank line apart, each keeping its own manually created subcategories and retained metadata directly under it. URLs do not generate a Domain detail line.
- **Analysis.** The analyst's text as written, paragraphs and line breaks included.
- **Plain text.** The centered headings and separators are included in the copy. Summary and Analysis each have one blank line after their banner. Sections and top-level Summary points are one blank line apart. Keys are bold in the preview and in the rich copy only; no Markdown markers are inserted. The editor and value copies have no added lines.

```text
Suspicious PowerShell Execution

==================================================
                     SUMMARY
==================================================

MITRE ATT&CK: Execution (TA0002), Command and Scripting Interpreter: PowerShell (T1059.001)

User: DOMAIN\jdupont

source.ip: 98.56.54.185 → VirusTotal
└── Country     : NL 🇳🇱

EDR Action: Unmitigated

==================================================
                     ANALYSIS
==================================================

Sign-ins and process activity reviewed.
```

**Links.** In the report's Summary, **→ VirusTotal** appears on the associated category's line and opens its report in a new tab. The plain-text copy keeps that label; the rich copy keeps its clickable URL. Event references (`event.url`, `event.reference`, `alert.url`, `rule.reference` holding an http(s) address) remain links showing their full address. Suspicious URLs such as `url.full` stay plain text; their VirusTotal report is clickable. MITRE IDs are links too, shown as the ID alone. A defanged reference is plain text.

**Unknown.** A key named `Unknown` (the key given to captured text of no recognized type) or a value that is exactly `Unknown` shows that word in red in the preview and in the rich copy, until the key is renamed or the value filled in. Nothing else changes color.

**Unmitigated.** The EDR status `Not mitigated` (also `NOT_MITIGATED`, `not-mitigated`) is written `Unmitigated` in Summary, value copies and the report. New values are stored that way; a draft saved earlier keeps its stored value and shows the new wording.

File export controls are currently removed. The working investigation is protected by the automatic Current Analysis recovery described below.

Copy buttons write plain text and, where supported, safe HTML with explicit line breaks. Report copying keeps bold keys, while line breaks, blank lines and indentation remain readable in rich editors without this page's CSS. Full and partial Report selections copied with Ctrl / ⌘ + C use the same HTML formatting and the report's own text, blank lines between sections included. Native Ctrl / ⌘ + C in Logs preserves the selected source’s original CRLF/CR/LF endings in the plain-text clipboard payload.

Clipboard fallbacks reuse the browser copy event to retain both formats before trying plain-text-only copying. If automatic report copying is denied, the report is selected for Ctrl / ⌘ + C; no report-copy modal or confirmation opens. Field and remediation copy buttons retain their manual-copy fallback.

## MITRE ATT&CK

The selector beside Rule holds the tactics and techniques of the investigation. Type an ID or part of a name (`T1059`, `1053.005`, `powershell`, `credential access`) and pick a suggestion with the mouse or with the arrow keys and Enter. Several IDs can be typed or pasted at once (`T1059, T1078 T1053.005`). An ID outside the bundled list is accepted as typed, optionally with a name: `T1999 - Internal technique`. **Tactics** opens a panel with the Enterprise tactics; one click selects or clears each.

Selections appear as chips with their ID and name. Remove one with its × button, or with Backspace in the empty field. Tactics are listed before techniques. They are saved with the Current Analysis draft, restored on reload, cleared by New and written at the start of the report's Summary.

The list in `js/mitre-data.js` is ATT&CK Enterprise v20.0 from MITRE's official STIX data: 15 tactics and 706 active techniques and sub-techniques. It is bundled; nothing is fetched.

## Logs cleaning

Text entering the tool is cleaned automatically:

- emojis and pictographs are removed, with the space that padded them;
- spaces and blank lines at the start and end of the text are removed.

Spaces inside a line, indentation after the first line, inner blank lines, line endings, and every character of commands, paths, URLs, addresses, hashes and timestamps are kept. `©`, `®` and `™` are kept as text.

This applies to text pasted into Logs, opened log files, submitted Logs (the source retained in the draft is the cleaned text), dropped text, extension captures and JSON string values. While typing in Logs the box is left alone; extracted values are cleaned as they are read. A JSON value made only of pictographs is ignored like an empty one. The extension keeps its own record of a capture as it was sent.

## Defanged URLs in Summary

A **DFN** toggle button appears immediately to the left of the VirusTotal logo on pairs whose value is a recognized URL. Its tooltip reads **Defanged URL**. It starts released; pressing it keeps it visibly depressed and presents `https://example.invalid/path` as `hxxps://example[.]invalid/path` in Summary, value copying, dragging to another field and the Report. Clicking it again releases it and restores the original presentation.

The original value and raw logs remain intact. Focusing the value field exposes the original URL for editing; leaving the field shows the selected presentation again. Already-defanged URLs remain stable without double neutralization. The button state is kept in the Current Analysis draft; non-URL values have no visible defanging option.

## IP, URL and file details

Summary cards no longer create predefined Country, Domain, Path or Hash controls. Subcategories are created with the **+** next to their parent’s drag grip or with drag and drop. **+ Category** adds a new top-level title and value. Their optional `parentId` is kept in Current Analysis recovery; older flat drafts remain flat. Reports show custom children directly under their parent with tree branches, and value-only copying follows that same order.

**ServiceNow.** Each category and subcategory has the bundled `servicenow.png` logo immediately to the left of Copy. It opens `https://CHANGEME?value=…` in a new tab, with the original stored value safely encoded as a query parameter. The link updates when the value is edited and does not depend on DFN or the VirusTotal eye. Replace `SERVICE_NOW_URL` in `js/summary-editor.js` when the real instance URL is available.

**VirusTotal.** The editor uses the bundled `virus-total.png` logo as its action link. The report displays a named **→ VirusTotal** link on the associated category's line for an IP, URL, hash or a file with a known hash. Links use `https://www.virustotal.com/gui/ip-address/{IP}`, `…/gui/file/{HASH}` or `…/gui/url/{ID}`, where `ID` is the unpadded URL-safe base64 of the exact URL. Defanged values are restored for the link only. Private, loopback and link-local addresses and categories without a recognized indicator have no associated report link. Nothing is sent until a link is opened; no API key is used.

The small eye button below the VirusTotal logo shows or hides that category's link in the report and its clipboard copies. An open eye means visible; a crossed-out eye means hidden. The logo remains available to open the report. This choice is saved with the category, follows moves and merges, and can be undone.

**Country flags.** When a value is an upper-case ISO 3166-1 alpha-2 country code such as `FR`, its flag appears in the VirusTotal logo position and the report reads `country: FR 🇫🇷`. Lower-case words (`in`, `no`) and country names are left alone. The same eye below the flag shows or hides it in the report and its copies; the flag stays visible in Summary, and copied values remain the bare code. The choice is saved with the category and can be undone. Flags are Unicode symbols: browsers without a flag font, such as Chrome on Windows, show the two letters instead.

Country, path and hash metadata already in drafts or supplied by JSON imports remains saved and appears in the report. A URL's automatic Domain detail is omitted from the report and its copies. No country is inferred from an address or domain. Dropping a file on the page adds a `File` category and computes its SHA256 locally (512 MB limit); the file is neither stored nor uploaded. Dropped text and JSON use the existing capture and import paths.

The report lists the details under their value. A line appears only when its detail exists:

```text
source.ip: 98.56.54.185 → VirusTotal
└── Country     : NL 🇳🇱

File: mail.txt → VirusTotal
├── Path        : C:\Users\j.dupont\Downloads\mail.txt
└── Hash SHA256 : e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

URL: hxxps://auth-office365-update[.]com/login → VirusTotal
└── Country     : FR 🇫🇷
```

Details belong to their own pair and are saved with the Current Analysis draft as optional `country`, `filePath` and `fileHash` fields. They follow the pair through reordering, re-parsing, merging, Undo and reload. Value-only copying is unchanged. JSON imports fill them from fields of the same object; see [JSON-IMPORT.md](JSON-IMPORT.md). Windows has no flag glyphs in its system emoji font, so Chrome and Edge on Windows draw a flag as its two letters.

## Current Analysis recovery

Current Analysis autosaves automatically to browser storage after changes to Rule, MITRE ATT&CK selections, raw input, parsed or edited pairs, remediation choices and text, Analysis and temporary template configuration. It also flushes when the page closes or becomes hidden. Reloading restores the unfinished workspace automatically.

This is a single browser recovery draft, not a permanent exported file. Autosave never triggers a download. The key is `soc-note-builder.current-analysis.v1`; New Investigation clears it. Existing older saved investigations are migrated. Catalogue preferences remain separate and are not deleted by a workspace reset.

Drafts use `schemaVersion: 4`, containing only the known working-state fields. Corrupt drafts are not overwritten automatically; New Investigation explicitly replaces them. Storage refusal, quota errors or an oversized draft are reported while the current interface remains usable. Browser storage is unencrypted and its availability in `file://` depends on the browser/profile.

## Existing data behavior

The parser recognizes explicit lines rather than inferring facts from arbitrary text. Extraction remains limited to 500,000 characters and 200 unique values per block; oversized input is retained. Submitted values survive subsequent imports, while edits and removals remain independent of the original logs. CRLF/CR line endings of the raw text are preserved.

Extension captures additionally recognize upper-case ISO country codes (or a flag sent on its own) under **Country**, complete dates/timestamps, UUIDs, Windows SIDs and mitigation statuses such as **Mitigated** / **Unmitigated** under **EDR Action**. Captured text keeps its original representation, apart from the cleaning and the Unmitigated wording described above. Generic values such as `true`, `false` or `Blocked` need an EDR/mitigation field label to receive that type. Distinct values receive numbered keys such as `Date 2` or `EDR Action 2`.

The withdrawn remediation catalogue contains 116 actions across its 14 configured tactics. Remediation actions remain analyst-selected. `{USER}`, `{HOST}`, `{IP}`, `{SRC_IP}`, `{DST_IP}`, `{DOMAIN}`, `{URL}`, `{HASH}`, `{FILE}` and `{PROCESS}` resolve through the existing aliases, including compatible French keys. Missing values use generic wording, and multiple matching values are retained. Network values in remediations are defanged without changing source data.

The category hierarchy preserves parsing, Analysis editing, remediation selections, defanging, recovery and value-only copying. Reports follow the chosen hierarchy and retain imported entity metadata. User text is rendered through text nodes and input values; it is never interpreted as HTML or executed. All scripts and styles are bundled, and CSP blocks external connections.

## Keyboard

| Shortcut | Action |
| --- | --- |
| Ctrl / ⌘ + Shift + X (extension) | Send selected text to Note Builder and copy it to the clipboard |
| Ctrl + Alt + X (extension page / activated web page) | Send existing clipboard text to Note Builder |

## Validation

Node is needed only for tests:

```sh
node --test tests/*.test.cjs
node tests/browser-check.cjs
node tests/extension-browser-check.cjs
```

There are 135 data tests, including 52 capture-extension and clipboard-reader tests, 13 JSON import tests, 8 country, VirusTotal and entity-detail tests and 6 cleaning, wording, MITRE ATT&CK and report tests. The Chrome checks cover computed text/placeholder and control contrast, editable/read-only/disabled states, keyboard focus, pressed buttons, reduced motion, 320–1440 px layouts, real mouse dragging, insertion markers, auto-scroll, cancellation, Undo, restored order and removal of old application shortcuts. They also cover both card drop zones, sibling ordering, pointer-based nesting on categories, subcategories and gaps, parent moves, nesting limits, automatic top-level fallback for impossible drops, manual category creation and nesting, detaching by drag and drop, deletion, hierarchy recovery, URL defanging, PNG VirusTotal controls, ServiceNow links on categories and subcategories, inline named report links, side-by-side titles and values, removed predefined detail controls, retained imported metadata, date/timestamp detection, UTC and blank time-zone choices, removal of the time-zone eye, compatibility with older hidden annotations, saved preferences, local hashing of a dropped file, the MITRE ATT&CK selector and tactics panel, cleaned Logs, report links, the red Unknown, older drafts, report and clipboard fidelity, Rule paste/title, source-file import, New Investigation clearing, and absence of file downloads, remote requests or JavaScript/CSP errors. The MV3 checks load the real extension and exercise automatic imports, Date/UUID/SID/EDR Action recovery, selection copying, clipboard-only import, trusted Ctrl + Alt + X in the tool and activated pages, acknowledgement recovery, JSON manual/file/clipboard import, direct delivery between windows, replay protection, failed-save recovery and registration of only the selection command.

Clipboard checks perform actual keyboard pastes into plain-text and rich-text editors isolated from the app's CSS, including multiline content, blank lines, indentation, partial selections and denied clipboard APIs.

Drag checks start from real mouse gestures and use DevTools drop coordinates and cancellation events, including the source's native `dragend` cleanup.

The browser harness uses `/usr/bin/google-chrome`; set `SOC_BROWSER` for another compatible executable.
