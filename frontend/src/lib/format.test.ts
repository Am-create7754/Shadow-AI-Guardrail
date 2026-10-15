import { describe, expect, it } from 'vitest'

import { cx, formatTime, splitFences } from './format'

describe('splitFences', () => {
  it('separates prose from fenced code with its language', () => {
    const segs = splitFences('Intro\n```python\nprint(1)\nprint(2)\n```\nOutro')
    expect(segs).toEqual([
      { kind: 'text', content: 'Intro', language: undefined },
      { kind: 'code', content: 'print(1)\nprint(2)', language: 'python' },
      { kind: 'text', content: 'Outro', language: undefined },
    ])
  })

  it('supports tilde fences and longer closing fences', () => {
    const segs = splitFences('~~~\na\n~~~~\n````js\nb\n````')
    expect(segs.map((s) => [s.kind, s.content])).toEqual([['code', 'a'], ['code', 'b']])
  })

  it('does not close a backtick fence with a tilde fence', () => {
    const segs = splitFences('```\nx\n~~~\ny\n```')
    expect(segs).toHaveLength(1)
    expect(segs[0]?.content).toBe('x\n~~~\ny')
  })

  it('keeps an unterminated fence as code (e.g. mid-stream)', () => {
    const segs = splitFences('text\n```sh\nrm -rf /tmp/x')
    expect(segs.at(-1)).toMatchObject({ kind: 'code', content: 'rm -rf /tmp/x', language: 'sh' })
  })

  it('drops whitespace-only prose', () => {
    expect(splitFences('\n\n')).toEqual([])
  })
})

describe('helpers', () => {
  it('cx joins truthy class names', () => {
    expect(cx('a', false, null, undefined, 'b')).toBe('a b')
  })

  it('formatTime tolerates missing and invalid values', () => {
    expect(formatTime(null)).toBe('—')
    expect(formatTime('not-a-date')).toBe('not-a-date')
    expect(formatTime('2026-10-15T10:00:00Z')).not.toBe('2026-10-15T10:00:00Z')
  })
})
