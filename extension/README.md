# Shadow AI Guardrail - Chrome extension (Manifest V3)

Checks prompts typed into AI chat sites with the organisation's guardrail
gateway **before** the site receives them.

Supported sites: ChatGPT (`chatgpt.com`, `chat.openai.com`), Claude (`claude.ai`),
Gemini (`gemini.google.com`), Microsoft Copilot (`copilot.microsoft.com`).

| Gateway decision | What the user sees |
|---|---|
| ALLOW | Nothing - the prompt is sent as usual |
| REDACT | Panel listing what was found (types only) and the redacted text; "Replace with redacted text" puts placeholders into the editor, then the user sends again |
| REQUIRE_APPROVAL | Not sent; told to use the company gateway where it can be approved |
| BLOCK | Not sent; told to remove the data |
| Gateway unavailable | Not sent (default), or - only if policy allows - the user may send it unchecked |

## Build and install (Windows PowerShell)

```powershell
cd extension
npm ci
npm run build          # -> extension\dist
.\scripts\check.ps1    # lint, typecheck, tests, build
```

Chrome → `chrome://extensions` → enable Developer mode → **Load unpacked** →
select `extension\dist`. Open the extension's options, enter the gateway address
(default `http://127.0.0.1:8000`) and an API key created in the dashboard under
**API keys**, then **Save and test**.

## Security design

- **The API key never reaches a web page.** Only the service worker holds it and
  calls the gateway; the content script sends the prompt text and receives a
  verdict. The key is kept only in `chrome.storage.session` (memory only, not
  readable by content scripts); it is never written to disk, so it must be
  entered again after a browser restart.
- **Least privilege:** permission `storage` only; host access to `127.0.0.1` /
  `localhost`; a remote gateway's origin is requested at runtime for that origin
  only, and must use HTTPS. Content scripts run only on the listed sites, top
  frame only. No `web_accessible_resources`, no `externally_connectable`, no
  remote code, strict extension-page CSP.
- **Sender checks:** the worker answers prompt checks only from its own content
  scripts on supported https sites (site taken from the sender URL), and status
  requests only from its own pages.
- **Fail closed:** no key, an unreachable gateway, an invalid response or an
  extension error all stop the prompt unless policy sets `failMode: allow`;
  prompts over 100,000 characters are always stopped.
- **No HTML from outside:** the panel is in a closed shadow root and is built with
  `textContent` only.
- **Only the user starts a check:** synthetic events from page scripts are stopped
  without contacting the gateway (no oracle, no audit entries in the user's name);
  a form submission counts as the user's only right after real input, because
  browsers mark script-started submissions as trusted.
- **Every editor counts:** a send is checked against all prompt editors in scope
  (the focused one, or every filled one), so an empty hidden editor cannot make
  it look empty.
- **Replays are text-bound:** after an ALLOW, the user's own send button is
  replayed only if the editors still hold exactly the approved text; the
  approval also covers the site's own follow-up events for 3 seconds.
- **No silent fallback:** an invalid configured gateway address means "not
  configured" (fail closed), never the localhost default.
- **Enterprise policy:** `gatewayUrl`, `failMode` and `enabled` can be pinned with
  Chrome policy (`managed_schema.json`).

## Limits (honest)

- **The AI site itself is outside the protection boundary.** It sees every
  keystroke and draft before any check; a malicious or compromised site page
  could send text by its own means (e.g. `fetch`), stop our events, or draw a
  fake panel. The extension protects users from *accidentally* sending data to a
  normal site, not from a hostile one.
- Editors or buttons inside shadow DOM, content in iframes (`all_frames: false`)
  and sites that send on `pointerdown`/`mousedown` are not intercepted.
- A check can still be triggered by page script within one second of real user
  input (the gesture window); outside it, script-started sends are stopped.
- The `source` label sent to the gateway (`extension:<site>`) is an
  unauthenticated hint: any API key holder can send any valid label, so per-site
  dashboard counts are indicative, not evidence.
- A remote `gatewayUrl` pinned by enterprise policy also needs its host
  permission granted by policy (e.g. `runtime_allowed_hosts`).

This is a guardrail against accidental leaks, not a control a determined user
cannot bypass: they can disable or remove the extension (unless policy forces
it), use another browser or device, or paste into a site that is not listed.
Only prompts typed into the recognised editor and sent with Enter, the send
button or form submission are checked - file uploads, images, voice input, and
pasted content that is sent by other means are not. Site selectors follow
third-party markup and need maintenance when sites change. Verified with unit
tests (jsdom) and in Chromium against pages that imitate the sites' editors
(textarea + form, contenteditable) with the real gateway - **not on the live
third-party sites**, which require accounts.
