import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { APPROVAL_MS, installGuard, type Guard } from './guard'
import type { Verdict } from './messages'
import type { Choice } from './panel'
import { SITES } from './sites'

const chatgpt = SITES.find((s) => s.id === 'chatgpt.com')!
const claude = SITES.find((s) => s.id === 'claude.ai')!

const decision = (action: 'ALLOW' | 'REDACT' | 'REQUIRE_APPROVAL' | 'BLOCK', sanitizedText: string | null = null): Verdict => ({
  kind: 'decision',
  action,
  sanitizedText,
  findings: action === 'ALLOW' ? [] : [{ entityType: 'PASSWORD', severity: 'HIGH' }],
  reasons: [],
  riskScore: 50,
})

/** A chat page like ChatGPT's: the site sends on form submit and on Enter. */
function chatPage() {
  document.body.innerHTML = `
    <form id="composer">
      <textarea id="prompt-textarea"></textarea>
      <button type="submit" data-testid="send-button">Send</button>
    </form>`
  const sent: string[] = []
  const form = document.getElementById('composer') as HTMLFormElement
  const editor = document.getElementById('prompt-textarea') as HTMLTextAreaElement
  form.addEventListener('submit', (e) => {
    e.preventDefault() // a single-page app
    sent.push(editor.value)
  })
  editor.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) {
      e.preventDefault()
      form.requestSubmit()
    }
  })
  return { sent, form, editor, button: form.querySelector('button')! }
}

// jsdom cannot create trusted events: the guard is told which ones the "user" made.
const trusted = new WeakSet<Event>()
const asUser = <E extends Event>(e: E): E => {
  trusted.add(e)
  return e
}
/** The user pressing Enter. */
const enter = (el: Element, init: KeyboardEventInit = {}) =>
  el.dispatchEvent(asUser(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true, cancelable: true, ...init })))
/** The user clicking. */
const click = (el: Element) => el.dispatchEvent(asUser(new MouseEvent('click', { bubbles: true, cancelable: true })))

let guard: Guard | null = null
afterEach(() => {
  guard?.stop()
  guard = null
  document.body.innerHTML = ''
})

function setup(verdict: Verdict | (() => Promise<Verdict>), choice: Choice = 'dismiss', site = chatgpt) {
  const inspect = vi.fn(typeof verdict === 'function' ? verdict : async () => verdict)
  const showPanel = vi.fn(async (_doc: Document, _verdict: Verdict) => choice)
  guard = installGuard({ win: window, site, inspect, showPanel, isTrusted: (e) => trusted.has(e) })
  return { inspect, showPanel }
}

const settle = () => new Promise((r) => setTimeout(r, 0))

describe('Enter in the prompt editor', () => {
  let page: ReturnType<typeof chatPage>
  beforeEach(() => {
    page = chatPage()
  })

  it('holds the prompt until the gateway allows it, then sends it exactly once', async () => {
    const { inspect } = setup(decision('ALLOW'))
    page.editor.value = 'How do I sort a list?'
    enter(page.editor)
    expect(page.sent).toEqual([]) // not sent before the verdict
    await settle()
    expect(inspect).toHaveBeenCalledWith('How do I sort a list?')
    expect(page.sent).toEqual(['How do I sort a list?'])
  })

  it('never sends a redacted prompt; replacing puts placeholders in the editor', async () => {
    const { showPanel } = setup(decision('REDACT', 'db_password=[PASSWORD_1]'), 'replace')
    page.editor.value = 'db_password=hunter2hunter'
    enter(page.editor)
    await settle()
    expect(showPanel).toHaveBeenCalledOnce()
    expect(page.sent).toEqual([])
    expect(page.editor.value).toBe('db_password=[PASSWORD_1]')
  })

  it.each(['BLOCK', 'REQUIRE_APPROVAL'] as const)('does not send on %s and keeps the text for editing', async (action) => {
    const { showPanel } = setup(decision(action))
    page.editor.value = 'card 4111 1111 1111 1111'
    enter(page.editor)
    await settle()
    expect(showPanel).toHaveBeenCalledOnce()
    expect(page.sent).toEqual([])
    expect(page.editor.value).toBe('card 4111 1111 1111 1111')
  })

  it('lets Shift+Enter (new line) and IME composition through untouched', async () => {
    const { inspect } = setup(decision('ALLOW'))
    page.editor.value = 'line'
    expect(enter(page.editor, { shiftKey: true })).toBe(true)
    expect(enter(page.editor, { isComposing: true })).toBe(true)
    await settle()
    expect(inspect).not.toHaveBeenCalled()
  })

  it('does not replay if the text changed while waiting for the verdict', async () => {
    let resolve!: (v: Verdict) => void
    setup(() => new Promise<Verdict>((r) => (resolve = r)))
    page.editor.value = 'harmless'
    enter(page.editor)
    page.editor.value = 'harmless plus db_password=hunter2hunter' // page script or user edit
    resolve(decision('ALLOW'))
    await settle()
    expect(page.sent).toEqual([])
  })

  it('swallows repeated sends while a check is running', async () => {
    let resolve!: (v: Verdict) => void
    const { inspect } = setup(() => new Promise<Verdict>((r) => (resolve = r)))
    page.editor.value = 'hello'
    enter(page.editor)
    enter(page.editor)
    click(page.button)
    expect(inspect).toHaveBeenCalledOnce()
    resolve(decision('ALLOW'))
    await settle()
    expect(page.sent).toEqual(['hello'])
  })
})

describe('other ways to send', () => {
  it('intercepts the send button and form submission', async () => {
    const page = chatPage()
    const { inspect } = setup(decision('BLOCK'))
    page.editor.value = 'secret stuff'
    click(page.button)
    page.form.dispatchEvent(asUser(new SubmitEvent('submit', { bubbles: true, cancelable: true })))
    await settle()
    expect(inspect).toHaveBeenCalledTimes(1) // the second attempt hit the running check
    expect(page.sent).toEqual([])
  })

  it('lets an empty editor through without asking the gateway', async () => {
    const page = chatPage()
    const { inspect } = setup(decision('BLOCK'))
    click(page.button)
    await settle()
    expect(inspect).not.toHaveBeenCalled()
    expect(page.sent).toEqual([''])
  })
})

describe('gateway trouble', () => {
  it('fails closed when the gateway is unavailable in block mode', async () => {
    const page = chatPage()
    const { showPanel } = setup({ kind: 'unavailable', reason: 'unreachable', failMode: 'block' }, 'send_unchecked')
    page.editor.value = 'hello'
    enter(page.editor)
    await settle()
    expect(showPanel).toHaveBeenCalledOnce()
    expect(page.sent).toEqual([]) // even a forged "send" choice is ignored in block mode
  })

  it('sends unchecked only when policy allows it and the user chooses so', async () => {
    const page = chatPage()
    setup({ kind: 'unavailable', reason: 'unreachable', failMode: 'allow' }, 'send_unchecked')
    page.editor.value = 'hello'
    enter(page.editor)
    await settle()
    expect(page.sent).toEqual(['hello'])
  })

  it('fails closed when the extension itself cannot answer', async () => {
    const page = chatPage()
    const { showPanel } = setup(async () => {
      throw new Error('Extension context invalidated')
    })
    page.editor.value = 'hello'
    enter(page.editor)
    await settle()
    expect(page.sent).toEqual([])
    expect(showPanel.mock.calls[0]?.[1]).toMatchObject({ kind: 'unavailable', failMode: 'block' })
  })
})

describe('contenteditable editors (Claude, Gemini)', () => {
  it('reads the prompt and replaces it with the redacted text', async () => {
    document.body.innerHTML = `<fieldset><div class="ProseMirror" contenteditable="true"><p>key db_password=hunter2hunter</p></div>
      <button aria-label="Send message">Send</button></fieldset>`
    const sent: string[] = []
    const editor = document.querySelector<HTMLElement>('.ProseMirror')!
    document.querySelector('button')!.addEventListener('click', () => sent.push(editor.textContent ?? ''))
    const { inspect } = setup(decision('REDACT', 'key db_password=[PASSWORD_1]'), 'replace', claude)
    enter(editor.querySelector('p')!) // the event target is a node inside the editor
    await settle()
    expect(inspect).toHaveBeenCalledWith('key db_password=hunter2hunter')
    expect(sent).toEqual([])
    expect(editor.textContent).toBe('key db_password=[PASSWORD_1]')
  })
})

describe('Phase 6 review regressions', () => {
  it('checks a send-button click even when an empty editor comes first (High)', async () => {
    // ChatGPT-like composer: a hidden fallback textarea beside the real editor.
    document.body.innerHTML = `<form id="f"><textarea style="display:none"></textarea>
      <div id="prompt-textarea" contenteditable="true">key db_password=hunter2hunter</div>
      <button type="submit" data-testid="send-button">Send</button></form>`
    const sent: string[] = []
    document.getElementById('f')!.addEventListener('submit', (e) => {
      e.preventDefault()
      sent.push('submitted')
    })
    const { inspect } = setup(decision('BLOCK'))
    click(document.querySelector('button')!)
    await settle()
    expect(inspect).toHaveBeenCalledWith('key db_password=hunter2hunter')
    expect(sent).toEqual([])
  })

  it('checks every filled editor when it is unclear which one is sent (High)', async () => {
    document.body.innerHTML = `<fieldset><div contenteditable="true"></div><div contenteditable="true">secret one</div>
      <div contenteditable="true">secret two</div><button aria-label="Send message">Send</button></fieldset>`
    const sent: string[] = []
    document.querySelector('button')!.addEventListener('click', () => sent.push('sent'))
    const { inspect } = setup(decision('BLOCK'), 'dismiss', claude)
    click(document.querySelector('button')!)
    await settle()
    expect(inspect).toHaveBeenCalledWith('secret one\n\nsecret two')
    expect(sent).toEqual([])
  })

  it('stops page-script (synthetic) sends without asking the gateway (Medium)', async () => {
    const page = chatPage()
    const { inspect } = setup(decision('ALLOW'))
    page.editor.value = 'planted by the page: db_password=hunter2hunter'
    page.editor.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true, cancelable: true }))
    page.button.click() // untrusted
    page.form.requestSubmit() // untrusted
    await settle()
    expect(inspect).not.toHaveBeenCalled() // no oracle, no audit entries in the user's name
    expect(page.sent).toEqual([])
  })

  it('lets the site follow-up events through for the approved text only, briefly', async () => {
    let clock = 1_000
    const page = chatPage()
    const inspect = vi.fn(async () => decision('ALLOW'))
    guard = installGuard({
      win: window,
      site: chatgpt,
      inspect,
      showPanel: vi.fn(async () => 'dismiss' as const),
      isTrusted: (e) => trusted.has(e),
      now: () => clock,
    })
    page.editor.value = 'hello'
    enter(page.editor)
    await settle()
    expect(page.sent).toEqual(['hello'])
    // The site re-submits the same approved text from its own code: allowed.
    page.editor.value = 'hello'
    page.form.requestSubmit()
    expect(page.sent).toEqual(['hello', 'hello'])
    // Different text from page code: stopped, not inspected.
    page.editor.value = 'something else'
    page.form.requestSubmit()
    // Same text after the approval window: stopped.
    page.editor.value = 'hello'
    clock += APPROVAL_MS + 1
    page.form.requestSubmit()
    expect(page.sent).toEqual(['hello', 'hello'])
    expect(inspect).toHaveBeenCalledOnce()
  })

  it('does not treat a script-started form submission as the user (Chrome marks it trusted)', async () => {
    // Found in the live Chromium run after the first fix: requestSubmit() fires a
    // *trusted* submit event, so isTrusted alone cannot identify the user.
    let clock = 50_000
    const page = chatPage()
    const inspect = vi.fn(async () => decision('ALLOW'))
    guard = installGuard({
      win: window,
      site: chatgpt,
      inspect,
      showPanel: vi.fn(async () => 'dismiss' as const),
      isTrusted: (e) => trusted.has(e) || e.type === 'submit', // as in Chrome
      now: () => clock,
    })
    page.editor.value = 'planted: db_password=hunter2hunter'
    page.form.requestSubmit()
    await settle()
    expect(inspect).not.toHaveBeenCalled()
    expect(page.sent).toEqual([])
    // Right after a real click (e.g. a send button the selectors do not know), it is the user.
    click(document.body)
    clock += 200
    page.form.requestSubmit()
    await settle()
    expect(inspect).toHaveBeenCalledOnce()
  })

  it('replays the button the user clicked, not the first send button (Low)', async () => {
    document.body.innerHTML = `<fieldset id="a"><div contenteditable="true">hello</div>
      <button aria-label="Send message" id="b1">Send</button></fieldset>
      <fieldset id="b"><div contenteditable="true"></div><button aria-label="Send message" id="b2">Send</button></fieldset>`
    const clicked: string[] = []
    for (const id of ['b1', 'b2']) document.getElementById(id)!.addEventListener('click', () => clicked.push(id))
    setup(decision('ALLOW'), 'dismiss', claude)
    click(document.getElementById('b1')!)
    await settle()
    expect(clicked).toEqual(['b1'])
  })
})

describe('ChatGPT markup as of 2026-10 (live test)', () => {
  it('guards the id-less ProseMirror composer and ignores CodeMirror answer blocks', async () => {
    document.body.innerHTML = `<div class="cm-content" contenteditable="true">print("old answer")</div>
      <form id="f"><textarea style="display:none"></textarea>
      <div class="ProseMirror" contenteditable="true"><p>key db_password=hunter2hunter</p></div>
      <button type="submit" data-testid="send-button">Send</button></form>`
    const sent: string[] = []
    document.getElementById('f')!.addEventListener('submit', (e) => {
      e.preventDefault()
      sent.push('submitted')
    })
    const { inspect } = setup(decision('BLOCK'))
    enter(document.querySelector('.ProseMirror p')!)
    await settle()
    expect(inspect).toHaveBeenCalledWith('key db_password=hunter2hunter')
    expect(sent).toEqual([])
    // A keypress in an answer's code block is not a prompt send.
    expect(enter(document.querySelector('.cm-content')!)).toBe(true)
  })
})
