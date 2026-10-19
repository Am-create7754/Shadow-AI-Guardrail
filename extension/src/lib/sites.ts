// Supported AI chat sites and where their prompt editor and send button live.
//
// These selectors follow third-party markup that changes without notice; they
// are best-effort and need maintenance. When a site's send button is not found,
// the guard still intercepts the Enter key and form submission in any matching
// editor, and an unrecognised editor is simply not guarded (see docs/STATUS.md).

export interface SiteAdapter {
  /** Stable id, also sent to the gateway as `extension:<id>`. */
  id: string
  hosts: readonly string[]
  /** Prompt editors (textarea or contenteditable). */
  editor: string
  /** Send buttons. */
  send: string
}

export const SITES: readonly SiteAdapter[] = [
  {
    id: 'chatgpt.com',
    hosts: ['chatgpt.com', 'chat.openai.com'],
    // The composer is a ProseMirror editor; it lost its #prompt-textarea id in
    // 2026-10 (found in a live test). Only the real composer: ChatGPT keeps a
    // hidden fallback <textarea> beside it, and its answers contain CodeMirror
    // (cm-content) editors that must not be taken for the prompt.
    editor: '#prompt-textarea, div.ProseMirror[contenteditable="true"]',
    send: 'button[data-testid="send-button"], #composer-submit-button, button[aria-label="Send prompt"], form button[type="submit"]',
  },
  {
    id: 'claude.ai',
    hosts: ['claude.ai'],
    editor: 'div.ProseMirror[contenteditable="true"], fieldset [contenteditable="true"]',
    send: 'button[aria-label="Send message"], button[aria-label="Send Message"]',
  },
  {
    id: 'gemini.google.com',
    hosts: ['gemini.google.com'],
    editor: 'rich-textarea .ql-editor, div.ql-editor[contenteditable="true"]',
    send: 'button.send-button, button[aria-label="Send message"]',
  },
  {
    id: 'copilot.microsoft.com',
    // copilot.microsoft.com redirects to copilot.com (found by the live check, 2026-10-18).
    hosts: ['copilot.microsoft.com', 'copilot.com'],
    editor: 'textarea#userInput, textarea[data-testid="composer-input"]',
    send: 'button[data-testid="submit-button"], button[aria-label="Submit message"]',
  },
]

/** Content-script match patterns for the manifest (kept in sync by a test). */
export const MATCH_PATTERNS: readonly string[] = SITES.flatMap((s) => s.hosts.map((h) => `https://${h}/*`))

export function siteForHost(hostname: string): SiteAdapter | null {
  const host = hostname.toLowerCase()
  return SITES.find((s) => s.hosts.includes(host)) ?? null
}

/** Site for a full URL - only https pages of a supported host count. */
export function siteForUrl(url: string | undefined): SiteAdapter | null {
  if (!url) return null
  try {
    const u = new URL(url)
    return u.protocol === 'https:' ? siteForHost(u.hostname) : null
  } catch {
    return null
  }
}
