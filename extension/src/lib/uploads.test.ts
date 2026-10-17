import { afterEach, describe, expect, it, vi } from 'vitest'

import type { Verdict } from './messages'
import { describe as describePanel, type Choice, type Subject } from './panel'
import { MAX_FILE_BYTES, installUploadGuard, isTextFile, readCheckable, type UploadGuard } from './uploads'

const SECRET = ['db', 'password=hunter2hunter'].join('_')

const decision = (action: 'ALLOW' | 'REDACT' | 'BLOCK'): Verdict => ({
  kind: 'decision',
  action,
  sanitizedText: action === 'BLOCK' ? null : 'x',
  findings: action === 'ALLOW' ? [] : [{ entityType: 'PASSWORD', severity: 'HIGH' }],
  reasons: [],
  riskScore: 50,
})

const trusted = new WeakSet<Event>()
const asUser = <E extends Event>(e: E): E => {
  trusted.add(e)
  return e
}
const settle = () => new Promise((r) => setTimeout(r, 0))

let guard: UploadGuard | null = null
afterEach(() => {
  guard?.stop()
  guard = null
  document.body.innerHTML = ''
})

function setup(verdict: Verdict | ((name: string, text: string | null) => Promise<Verdict>), choice: Choice = 'dismiss') {
  const inspectFile = vi.fn(typeof verdict === 'function' ? verdict : async () => verdict)
  const showPanel = vi.fn(async (_doc: Document, _v: Verdict, _s: Subject) => choice)
  const redeliver = vi.fn()
  guard = installUploadGuard({ win: window, inspectFile, showPanel, redeliver, isTrusted: (e) => trusted.has(e) })
  return { inspectFile, showPanel, redeliver }
}

/** A site file input; `seen` records what the site's own handler received. */
function fileInput() {
  document.body.innerHTML = '<input type="file" id="f" />'
  const input = document.getElementById('f') as HTMLInputElement
  const seen: string[] = []
  input.addEventListener('change', () => seen.push('change'))
  input.addEventListener('input', () => seen.push('input'))
  return { input, seen }
}

/** The user picking files: the browser sets input.files, then fires input + change. */
function pick(input: HTMLInputElement, files: File[]) {
  Object.defineProperty(input, 'files', { value: files, configurable: true })
  input.dispatchEvent(asUser(new Event('input', { bubbles: true })))
  input.dispatchEvent(asUser(new Event('change', { bubbles: true })))
}

describe('which files can be checked', () => {
  it('recognises text and code files by name or type', () => {
    for (const name of ['notes.txt', 'config.yaml', '.env', 'main.py', 'Dockerfile', 'id_rsa.pem', 'data.CSV']) {
      expect(isTextFile(new File(['x'], name))).toBe(true)
    }
    expect(isTextFile(new File(['x'], 'blob', { type: 'application/json' }))).toBe(true)
    for (const name of ['photo.png', 'report.pdf', 'archive.zip', 'deck.pptx']) {
      expect(isTextFile(new File(['x'], name))).toBe(false)
    }
  })

  it('reads small text files and refuses binary or oversized ones', async () => {
    expect(await readCheckable(new File([SECRET], 'a.txt'))).toBe(SECRET)
    expect(await readCheckable(new File(['abc\u0000def'], 'disguised.txt'))).toBeNull()
    expect(await readCheckable(new File(['a'.repeat(MAX_FILE_BYTES + 1)], 'big.log'))).toBeNull()
    expect(await readCheckable(new File(['%PDF-1.7'], 'r.pdf'))).toBeNull()
  })
})

describe('file picker', () => {
  it('holds a picked file, checks its text, and stops it on BLOCK', async () => {
    const { input, seen } = fileInput()
    const { inspectFile, showPanel, redeliver } = setup(decision('BLOCK'))
    pick(input, [new File([SECRET], 'creds.env')])
    expect(seen).toEqual([]) // the site never saw the pick
    expect(input.value).toBe('')
    await settle()
    expect(inspectFile).toHaveBeenCalledOnce() // one check for the input + change pair
    expect(inspectFile).toHaveBeenCalledWith('creds.env', SECRET)
    expect(showPanel.mock.calls[0]?.[2]).toEqual({ kind: 'file', name: 'creds.env' })
    expect(redeliver).not.toHaveBeenCalled()
  })

  it('hands allowed files back to the same input', async () => {
    const { input, seen } = fileInput()
    const { redeliver, showPanel } = setup(decision('ALLOW'))
    const files = [new File(['hello'], 'a.txt'), new File(['print(1)'], 'b.py')]
    pick(input, files)
    await settle()
    expect(showPanel).not.toHaveBeenCalled()
    expect(redeliver).toHaveBeenCalledWith('input', input, files)
    expect(seen).toEqual([])
  })

  it('stops the whole batch if any file is not allowed', async () => {
    const { input } = fileInput()
    const { redeliver, inspectFile } = setup(async (name) => decision(name === 'bad.txt' ? 'REDACT' : 'ALLOW'))
    pick(input, [new File(['ok'], 'good.txt'), new File([SECRET], 'bad.txt'), new File(['ok'], 'later.txt')])
    await settle()
    expect(inspectFile.mock.calls.map((c) => c[0])).toEqual(['good.txt', 'bad.txt'])
    expect(redeliver).not.toHaveBeenCalled()
  })
})

describe('files that cannot be checked', () => {
  it('are blocked by default', async () => {
    const { input } = fileInput()
    const { inspectFile, redeliver } = setup({ kind: 'uncheckable', uploadPolicy: 'block' }, 'send_unchecked')
    pick(input, [new File(['%PDF'], 'contract.pdf')])
    await settle()
    expect(inspectFile).toHaveBeenCalledWith('contract.pdf', null) // no content read or sent
    expect(redeliver).not.toHaveBeenCalled() // a forged "upload anyway" is ignored
  })

  it('can be uploaded after confirmation when policy says warn', async () => {
    const { input } = fileInput()
    const { redeliver } = setup({ kind: 'uncheckable', uploadPolicy: 'warn' }, 'send_unchecked')
    pick(input, [new File(['png'], 'diagram.png')])
    await settle()
    expect(redeliver).toHaveBeenCalledOnce()
  })
})

const withFiles = <E extends Event>(e: E, prop: 'dataTransfer' | 'clipboardData', files: File[]): E => {
  Object.defineProperty(e, prop, { value: { files } })
  return e
}

describe('drop and paste', () => {
  it('holds dropped files and replays the drop when allowed', async () => {
    document.body.innerHTML = '<div id="zone"></div>'
    const zone = document.getElementById('zone')!
    const siteDrop = vi.fn()
    zone.addEventListener('drop', siteDrop)
    const { redeliver } = setup(decision('ALLOW'))
    const files = [new File(['hi'], 'a.md')]
    const ev = asUser(withFiles(new Event('drop', { bubbles: true, cancelable: true }), 'dataTransfer', files))
    zone.dispatchEvent(ev)
    expect(ev.defaultPrevented).toBe(true)
    expect(siteDrop).not.toHaveBeenCalled()
    await settle()
    expect(redeliver).toHaveBeenCalledWith('drop', zone, files)
  })

  it('holds pasted files but leaves pasted text to the send-time check', async () => {
    document.body.innerHTML = '<div id="ed" contenteditable="true"></div>'
    const ed = document.getElementById('ed')!
    const { inspectFile } = setup(decision('BLOCK'))
    const textPaste = asUser(withFiles(new Event('paste', { bubbles: true, cancelable: true }), 'clipboardData', []))
    ed.dispatchEvent(textPaste)
    expect(textPaste.defaultPrevented).toBe(false)
    const filePaste = asUser(withFiles(new Event('paste', { bubbles: true, cancelable: true }), 'clipboardData', [new File([SECRET], 'k.txt')]))
    ed.dispatchEvent(filePaste)
    expect(filePaste.defaultPrevented).toBe(true)
    await settle()
    expect(inspectFile).toHaveBeenCalledOnce()
  })
})

describe('robustness', () => {
  it('lets its own re-delivery (untrusted events) through', () => {
    const { input, seen } = fileInput()
    const { inspectFile } = setup(decision('BLOCK'))
    Object.defineProperty(input, 'files', { value: [new File(['x'], 'a.txt')], configurable: true })
    input.dispatchEvent(new Event('change', { bubbles: true }))
    expect(seen).toEqual(['change'])
    expect(inspectFile).not.toHaveBeenCalled()
  })

  it('fails closed when the extension cannot answer', async () => {
    const { input } = fileInput()
    const { showPanel, redeliver } = setup(async () => {
      throw new Error('Extension context invalidated')
    })
    pick(input, [new File(['x'], 'a.txt')])
    await settle()
    expect(showPanel.mock.calls[0]?.[1]).toMatchObject({ kind: 'unavailable', failMode: 'block' })
    expect(redeliver).not.toHaveBeenCalled()
  })
})

describe('file panel wording', () => {
  const file = { kind: 'file', name: 'x.pdf' } as const
  it('never offers to rewrite a file, and offers override only where policy allows', () => {
    expect(describePanel(decision('REDACT'), file)!.buttons.map((b) => b.choice)).toEqual(['dismiss'])
    expect(describePanel({ kind: 'uncheckable', uploadPolicy: 'block' }, file)!.buttons.map((b) => b.choice)).toEqual(['dismiss'])
    expect(describePanel({ kind: 'uncheckable', uploadPolicy: 'warn' }, file)!.buttons.map((b) => b.choice)).toContain('send_unchecked')
    expect(describePanel({ kind: 'unavailable', reason: 'unreachable', failMode: 'block' }, file)!.buttons.map((b) => b.choice)).toEqual([
      'dismiss',
    ])
  })
})
