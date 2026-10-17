// Content-script core: stop a prompt from being sent until the gateway has
// decided. Intercepts, in the capture phase (before the site's own handlers),
//   * Enter (without Shift) in a prompt editor,
//   * clicks on the site's send button,
//   * form submission containing a prompt editor.
// The prompt is sent to the service worker; on ALLOW the original action is
// replayed, otherwise a panel explains what happened.
//
// Rules (Phase 6 review):
//   * Every prompt editor in scope is considered, not just the first match: a
//     hidden empty editor must not make a send look empty.
//   * Only real user input (isTrusted) starts a check. A page script's synthetic
//     send is stopped without contacting the gateway, so a page cannot use the
//     user's API key as an oracle or fill the audit log in their name.
//   * An approval is bound to the exact text of every editor in scope and lasts
//     a few seconds, so the site's own follow-up events (e.g. a submit it fires
//     from a click handler) pass, while any other text is checked again.

import { readText, editorFrom, isEditor, writeText, type Editor } from './editor'
import type { Verdict } from './messages'
import type { Choice } from './panel'
import type { SiteAdapter } from './sites'

export interface GuardDeps {
  win: Window
  site: SiteAdapter
  inspect: (text: string) => Promise<Verdict>
  showPanel: (doc: Document, verdict: Verdict) => Promise<Choice>
  /** Clock, for tests. */
  now?: () => number
  /** Whether an event came from the user, for tests (jsdom cannot create trusted events). */
  isTrusted?: (e: Event) => boolean
}

export interface Guard {
  stop: () => void
}

/** How long an approval covers the site's own follow-up events. */
export const APPROVAL_MS = 3_000
/** A form submission counts as the user's only this soon after real input:
 *  browsers mark the submit event trusted even when a script submitted the form. */
export const GESTURE_MS = 1_000

interface Approval {
  texts: Map<Editor, string>
  until: number
}

export function installGuard({
  win,
  site,
  inspect,
  showPanel,
  now = () => Date.now(),
  isTrusted = (e) => e.isTrusted,
}: GuardDeps): Guard {
  const doc = win.document
  let approval: Approval | null = null
  let busy = false
  let lastGesture = -Infinity // time of the last real keydown / click / pointer press

  /** All prompt editors in scope (a form, or the whole page). */
  const editorsIn = (scope: ParentNode): Editor[] =>
    [...scope.querySelectorAll(site.editor)].filter((el): el is Editor => isEditor(el))

  /** Editors that would be sent: the focused one if it is in scope and has text,
   *  otherwise every non-empty one (ambiguity is resolved by checking them all). */
  const pending = (editors: Editor[]): Editor[] => {
    const filled = editors.filter((e) => readText(e).trim() !== '')
    const focused = filled.find((e) => e === doc.activeElement || e.contains(doc.activeElement))
    return focused ? [focused] : filled
  }

  const isApproved = (editors: Editor[]): boolean => {
    if (!approval) return false
    if (now() > approval.until) {
      approval = null
      return false
    }
    const a = approval
    return editors.every((e) => a.texts.get(e) === readText(e))
  }

  const replay = (editors: Editor[], trigger: { button: HTMLElement | null; form: HTMLFormElement | null }): void => {
    approval = { texts: new Map(editors.map((e) => [e, readText(e)])), until: now() + APPROVAL_MS }
    const button =
      trigger.button?.isConnected && !(trigger.button as HTMLButtonElement).disabled
        ? trigger.button
        : doc.querySelector<HTMLButtonElement>(site.send)
    if (button && !(button as HTMLButtonElement).disabled) button.click()
    else if (trigger.form) trigger.form.requestSubmit()
    else {
      editors[0]?.dispatchEvent(
        new KeyboardEvent('keydown', { key: 'Enter', code: 'Enter', keyCode: 13, bubbles: true, cancelable: true }),
      )
    }
  }

  async function check(editors: Editor[], trigger: { button: HTMLElement | null; form: HTMLFormElement | null }): Promise<void> {
    const texts = editors.map(readText)
    const unchanged = (): boolean => editors.every((e, i) => readText(e) === texts[i])
    busy = true
    try {
      const verdict = await inspect(texts.join('\n\n'))
      if (verdict.kind === 'disabled' || (verdict.kind === 'decision' && verdict.action === 'ALLOW')) {
        if (unchanged()) replay(editors, trigger)
        return
      }
      const choice = await showPanel(doc, verdict)
      const single = editors.length === 1 ? editors[0] : undefined
      if (choice === 'replace' && single && verdict.kind === 'decision' && verdict.sanitizedText !== null) {
        writeText(single, verdict.sanitizedText)
        single.focus()
      } else if (choice === 'send_unchecked' && verdict.kind === 'unavailable' && verdict.failMode === 'allow') {
        if (unchanged()) replay(editors, trigger)
      }
    } catch {
      // Extension reloaded or worker unavailable: fail closed, keep the text.
      await showPanel(doc, { kind: 'unavailable', reason: 'unreachable', failMode: 'block' })
    } finally {
      busy = false
    }
  }

  /** Common path: block the event, then decide asynchronously. */
  const intercept = (
    e: Event,
    scope: Editor[],
    trigger: { button: HTMLElement | null; form: HTMLFormElement | null },
  ): void => {
    const editors = pending(scope)
    if (editors.length === 0) return // nothing to send, nothing to check
    if (isApproved(editors)) return // approved send (or the site's follow-up): let it through
    e.preventDefault()
    e.stopImmediatePropagation()
    // Synthetic events (page scripts) never start a check; a check already
    // running is not started twice.
    const fromUser = e.type === 'submit' ? isTrusted(e) && now() - lastGesture <= GESTURE_MS : isTrusted(e)
    if (!fromUser || busy) return
    void check(editors, trigger)
  }

  const onGesture = (e: Event): void => {
    if (isTrusted(e)) lastGesture = now()
  }

  const onKeyDown = (e: KeyboardEvent): void => {
    onGesture(e)
    if (e.key !== 'Enter' || e.shiftKey || e.isComposing || e.altKey) return
    const editor = editorFrom(e.target, site.editor)
    if (!editor) return
    intercept(e, [editor], { button: null, form: editor.closest('form') })
  }

  const onClick = (e: MouseEvent): void => {
    onGesture(e)
    if (!(e.target instanceof Element)) return
    const button = e.target.closest<HTMLElement>(site.send)
    if (!button) return
    const form = button.closest('form')
    const inForm = form ? editorsIn(form) : []
    intercept(e, inForm.length ? inForm : editorsIn(doc), { button, form })
  }

  const onSubmit = (e: SubmitEvent): void => {
    if (!(e.target instanceof HTMLFormElement)) return
    const editors = editorsIn(e.target)
    if (!editors.length) return
    intercept(e, editors, { button: null, form: e.target })
  }

  win.addEventListener('keydown', onKeyDown, true)
  win.addEventListener('click', onClick, true)
  win.addEventListener('submit', onSubmit, true)
  win.addEventListener('pointerdown', onGesture, true)
  return {
    stop: () => {
      win.removeEventListener('pointerdown', onGesture, true)
      win.removeEventListener('keydown', onKeyDown, true)
      win.removeEventListener('click', onClick, true)
      win.removeEventListener('submit', onSubmit, true)
    },
  }
}
