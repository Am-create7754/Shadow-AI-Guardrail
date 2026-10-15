import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import { AnswerView, HighlightedText } from './guardrail'

describe('HighlightedText', () => {
  it('highlights typed placeholders', () => {
    const { container } = render(<HighlightedText text="key [API_KEY_1] and [EMAIL_ADDRESS_2] here" />)
    const tokens = [...container.querySelectorAll('.placeholder-token')].map((n) => n.textContent)
    expect(tokens).toEqual(['[API_KEY_1]', '[EMAIL_ADDRESS_2]'])
  })

  it('renders hostile markup as inert text', () => {
    const payload = '<img src=x onerror="alert(1)"><script>alert(2)</script>'
    const { container } = render(<HighlightedText text={payload} />)
    expect(container.querySelector('img')).toBeNull()
    expect(container.querySelector('script')).toBeNull()
    expect(container.textContent).toBe(payload)
  })
})

describe('AnswerView', () => {
  const answer = 'Here:\n```python\nimport os\npassword = "x"\n```\nand\n```js\neval(input)\n```'

  it('flags the reported line in the reported code block only', () => {
    const { container } = render(
      <AnswerView text={answer} codeFindings={[{ block: 1, line: 1, rule_id: 'js-eval', cwe: 'CWE-95', severity: 'high', title: 'eval', language: 'js' }] as never} />,
    )
    const pres = container.querySelectorAll('pre')
    expect(pres).toHaveLength(2)
    const flaggedIn = (pre: Element) => [...pre.children].filter((row) => row.className.includes('color-block')).map((row) => row.textContent)
    expect(flaggedIn(pres[0]!)).toEqual([])
    expect(flaggedIn(pres[1]!)).toEqual(['1eval(input)'])
    expect(screen.getByText('1 flagged line')).toBeInTheDocument()
  })

  it('never interprets markdown links or HTML in prose', () => {
    const { container } = render(<AnswerView text={'[click](javascript:alert(1)) <b>bold</b>'} />)
    expect(container.querySelector('a')).toBeNull()
    expect(container.querySelector('b')).toBeNull()
  })
})
