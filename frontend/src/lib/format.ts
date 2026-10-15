// Pure helpers shared by components (kept out of .tsx files so React Fast
// Refresh can treat those as component-only modules).

export function cx(...classes: (string | false | null | undefined)[]): string {
  return classes.filter(Boolean).join(' ')
}

export const ACTION_LABEL: Record<string, string> = {
  ALLOW: 'Allowed',
  REDACT: 'Redacted',
  REQUIRE_APPROVAL: 'Needs approval',
  BLOCK: 'Blocked',
  APPROVED: 'Approved',
}

export function formatTime(iso: string | null | undefined): string {
  if (!iso) return '—'
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString()
}

export interface Segment {
  kind: 'text' | 'code'
  content: string
  language?: string
}

/** Split an answer into prose and fenced code blocks (``` or ~~~ fences). */
export function splitFences(text: string): Segment[] {
  const segments: Segment[] = []
  const lines = text.split('\n')
  let buffer: string[] = []
  let fence: string | null = null
  let language = ''
  const flush = (kind: 'text' | 'code') => {
    if (buffer.length || kind === 'code') segments.push({ kind, content: buffer.join('\n'), language: kind === 'code' ? language : undefined })
    buffer = []
  }
  for (const line of lines) {
    const m = /^ {0,3}(`{3,}|~{3,})\s*([\w+#.-]*)/.exec(line)
    if (fence === null && m) {
      flush('text')
      fence = m[1] ?? '```'
      language = m[2] ?? ''
    } else if (fence !== null && m && (m[1] ?? '')[0] === fence[0] && (m[1] ?? '').length >= fence.length && !m[2]) {
      flush('code')
      fence = null
    } else {
      buffer.push(line)
    }
  }
  flush(fence === null ? 'text' : 'code')
  return segments.filter((s) => s.kind === 'code' || s.content.trim() !== '')
}
