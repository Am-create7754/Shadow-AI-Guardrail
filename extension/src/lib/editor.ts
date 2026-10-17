// Reading and replacing the text of a prompt editor: a <textarea>/<input> or a
// contenteditable element (ProseMirror, Quill, ...).

export type Editor = HTMLTextAreaElement | HTMLInputElement | HTMLElement

export function isEditor(el: Element | null): el is Editor {
  if (!el) return false
  if (el instanceof HTMLTextAreaElement) return true
  if (el instanceof HTMLInputElement) return el.type === 'text' || el.type === 'search'
  if (!(el instanceof HTMLElement)) return false
  if (el.isContentEditable) return true
  // Attribute check as well (jsdom has no isContentEditable).
  const attr = el.getAttribute('contenteditable')
  return attr === '' || attr === 'true' || attr === 'plaintext-only'
}

/** The editor an event target belongs to (it may be a node inside it). */
export function editorFrom(target: EventTarget | null, selector: string): Editor | null {
  if (!(target instanceof Element)) return null
  const hit = target.closest(selector)
  if (hit && isEditor(hit)) return hit
  // A node inside a contenteditable root that itself matches the selector.
  const root = target.closest('[contenteditable="true"], [contenteditable=""]')
  return root && root.matches(selector) && isEditor(root) ? root : null
}

export function readText(el: Editor): string {
  if (el instanceof HTMLTextAreaElement || el instanceof HTMLInputElement) return el.value
  // innerText keeps the line breaks the user sees; jsdom lacks it.
  const text = typeof el.innerText === 'string' ? el.innerText : el.textContent
  return (text ?? '').replace(/ /g, ' ').replace(/\n$/, '')
}

/**
 * Replace the whole editor content in a way the page's framework notices
 * (React tracks the value setter; ProseMirror/Quill listen to input events).
 */
export function writeText(el: Editor, text: string): void {
  if (el instanceof HTMLTextAreaElement || el instanceof HTMLInputElement) {
    const proto = el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype
    Object.getOwnPropertyDescriptor(proto, 'value')?.set?.call(el, text)
    el.dispatchEvent(new Event('input', { bubbles: true }))
    return
  }
  el.focus()
  const doc = el.ownerDocument
  const selection = doc.getSelection()
  if (selection) {
    const range = doc.createRange()
    range.selectNodeContents(el)
    selection.removeAllRanges()
    selection.addRange(range)
  }
  // execCommand is deprecated but is still what rich editors handle as real
  // typing (undo history, internal model). Fall back to a plain replacement.
  let inserted = false
  try {
    inserted = typeof doc.execCommand === 'function' && doc.execCommand('insertText', false, text)
  } catch {
    inserted = false
  }
  if (!inserted || readText(el) !== text) {
    el.textContent = text
    el.dispatchEvent(new InputEvent('input', { bubbles: true, inputType: 'insertReplacementText' }))
  }
}
