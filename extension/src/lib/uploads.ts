// Content-script upload check: files chosen with a file picker, dropped onto
// the page or pasted are held until the gateway has seen them.
//
// Text files (by extension or MIME type, up to MAX_FILE_BYTES, no NUL bytes)
// are read and inspected like a prompt; any decision other than ALLOW stops the
// upload. Other files cannot be checked and follow the uploadPolicy setting
// (block by default). Allowed files are handed back to the site: the original
// file input gets its files again, or the drop / paste is replayed.
//
// As for typed prompts, only real user actions are intercepted; the events the
// guard re-dispatches itself are recognised and let through.

import type { Verdict } from './messages'
import type { Choice, Subject } from './panel'

export const MAX_FILE_BYTES = 1_000_000

const TEXT_EXTENSIONS = new Set([
  'txt', 'md', 'markdown', 'csv', 'tsv', 'json', 'jsonl', 'xml', 'yaml', 'yml', 'toml', 'ini', 'cfg', 'conf',
  'env', 'properties', 'log', 'sql', 'html', 'htm', 'css', 'js', 'mjs', 'cjs', 'ts', 'tsx', 'jsx', 'py', 'rb',
  'php', 'java', 'kt', 'kts', 'scala', 'go', 'rs', 'c', 'h', 'cc', 'cpp', 'hpp', 'cs', 'swift', 'm', 'sh',
  'bash', 'zsh', 'ps1', 'psm1', 'bat', 'cmd', 'r', 'pl', 'lua', 'dart', 'vue', 'svelte', 'tf', 'hcl',
  'gradle', 'dockerfile', 'pem', 'key', 'crt', 'cer', 'pub', 'gitignore', 'npmrc', 'pypirc', 'netrc',
])
const TEXT_MIME = /^(text\/|application\/(json|xml|x-yaml|yaml|toml|x-sh|javascript|x-httpd-php|sql))/

export function isTextFile(file: File): boolean {
  const lower = file.name.toLowerCase()
  const dot = lower.lastIndexOf('.')
  const ext = dot >= 0 ? lower.slice(dot + 1) : lower // ".env", "Dockerfile"
  return TEXT_EXTENSIONS.has(ext) || TEXT_MIME.test(file.type)
}

/** The text to inspect, or null when the file cannot be checked. */
export async function readCheckable(file: File): Promise<string | null> {
  if (!isTextFile(file) || file.size > MAX_FILE_BYTES) return null
  const text = await file.text()
  return text.includes('\u0000') ? null : text // binary content behind a text name
}

export interface UploadDeps {
  win: Window
  inspectFile: (name: string, text: string | null) => Promise<Verdict>
  showPanel: (doc: Document, verdict: Verdict, subject: Subject) => Promise<Choice>
  isTrusted?: (e: Event) => boolean
  /** Hand allowed files back to the site (real implementation below; tests replace it). */
  redeliver?: (kind: 'input' | 'drop' | 'paste', target: EventTarget, files: File[]) => void
}

export interface UploadGuard {
  stop: () => void
}

/** Re-create the user's action with the same files. Uses DataTransfer, which the
 *  browser accepts as the files of an <input> and of drop / paste events. */
export function redeliverFiles(kind: 'input' | 'drop' | 'paste', target: EventTarget, files: File[]): void {
  const dt = new DataTransfer()
  for (const f of files) dt.items.add(f)
  if (kind === 'input' && target instanceof HTMLInputElement) {
    target.files = dt.files
    target.dispatchEvent(new Event('input', { bubbles: true }))
    target.dispatchEvent(new Event('change', { bubbles: true }))
  } else if (kind === 'drop') {
    target.dispatchEvent(new DragEvent('drop', { dataTransfer: dt, bubbles: true, cancelable: true }))
  } else if (kind === 'paste') {
    target.dispatchEvent(new ClipboardEvent('paste', { clipboardData: dt, bubbles: true, cancelable: true }))
  }
}

/** The real target: inside a shadow root, events reach the window retargeted to
 *  the shadow host, so the input itself is only visible in the composed path. */
function realTarget(e: Event): EventTarget | null {
  return e.composedPath()[0] ?? e.target
}

function isFileInput(t: EventTarget | null): t is HTMLInputElement {
  return t instanceof HTMLInputElement && t.type === 'file'
}

function filesOf(e: Event): File[] {
  if (e.type === 'drop') return Array.from((e as DragEvent).dataTransfer?.files ?? [])
  if (e.type === 'paste') return Array.from((e as ClipboardEvent).clipboardData?.files ?? [])
  const t = realTarget(e)
  return isFileInput(t) ? Array.from(t.files ?? []) : []
}

export function installUploadGuard({
  win,
  inspectFile,
  showPanel,
  isTrusted = (e) => e.isTrusted,
  redeliver = redeliverFiles,
}: UploadDeps): UploadGuard {
  const doc = win.document
  const pendingInputs = new WeakSet<EventTarget>() // file inputs being checked

  /** Decide on a batch of files; true = all may be uploaded. */
  async function allowed(files: File[]): Promise<boolean> {
    for (const file of files) {
      let verdict: Verdict
      try {
        verdict = await inspectFile(file.name, await readCheckable(file))
      } catch {
        verdict = { kind: 'unavailable', reason: 'unreachable', failMode: 'block' }
      }
      if (verdict.kind === 'disabled') return true
      if (verdict.kind === 'decision' && verdict.action === 'ALLOW') continue
      const choice = await showPanel(doc, verdict, { kind: 'file', name: file.name })
      const mayOverride =
        (verdict.kind === 'uncheckable' && verdict.uploadPolicy === 'warn') ||
        (verdict.kind === 'unavailable' && verdict.failMode === 'allow')
      if (!(mayOverride && choice === 'send_unchecked')) return false
    }
    return true
  }

  const onFiles = (e: Event): void => {
    if (!isTrusted(e)) return // our own re-delivery (or page code with files it already has)
    const target = realTarget(e)
    const isInput = isFileInput(target)
    if (isInput && pendingInputs.has(target)) {
      // The second event (input/change) of the same pick, or a new pick while
      // the first is being checked: held, and the input emptied so the site
      // cannot read unchecked files from it.
      e.stopImmediatePropagation()
      target.value = ''
      return
    }
    const files = filesOf(e)
    if (files.length === 0 || !target) return
    e.preventDefault()
    e.stopImmediatePropagation()
    const kind = isInput ? 'input' : (e.type as 'drop' | 'paste')
    if (isInput) {
      pendingInputs.add(target)
      target.value = '' // the site must not read the files from the input meanwhile
    }
    void allowed(files)
      .then((ok) => {
        if (ok) redeliver(kind, target, files)
      })
      .finally(() => {
        if (isInput) pendingInputs.delete(target)
      })
  }

  // Pasted *text* is checked when the prompt is sent; only pasted files are held here.
  const events = ['change', 'input', 'drop', 'paste'] as const
  for (const type of events) win.addEventListener(type, onFiles, true)
  return {
    stop: () => {
      for (const type of events) win.removeEventListener(type, onFiles, true)
    },
  }
}
