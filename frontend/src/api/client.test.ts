import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { ApiError, api, setToken, setUnauthorizedHandler } from './client'

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

/** A streaming response whose body arrives in the given raw chunks. */
function sse(chunks: string[]): Response {
  const enc = new TextEncoder()
  const body = new ReadableStream<Uint8Array>({
    start(controller) {
      for (const c of chunks) controller.enqueue(enc.encode(c))
      controller.close()
    },
  })
  return new Response(body, { status: 200, headers: { 'Content-Type': 'text/event-stream' } })
}

const delta = (text: string) => `data: ${JSON.stringify({ choices: [{ delta: { content: text } }] })}\n\n`

let fetchMock: ReturnType<typeof vi.fn>

beforeEach(() => {
  fetchMock = vi.fn()
  vi.stubGlobal('fetch', fetchMock)
  setToken(null)
  setUnauthorizedHandler(null)
})

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('request()', () => {
  it('sends the bearer token from memory and never cookies', async () => {
    fetchMock.mockResolvedValue(json(200, { id: 'u1' }))
    setToken('tok-123')
    await api.me()
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit]
    expect(url).toBe('/v1/me')
    expect(init.credentials).toBe('omit')
    expect(init.cache).toBe('no-store')
    expect((init.headers as Record<string, string>).Authorization).toBe('Bearer tok-123')
  })

  it('omits the Authorization header when signed out', async () => {
    fetchMock.mockResolvedValue(json(200, { data: [] }))
    await api.models()
    const init = fetchMock.mock.calls[0]?.[1] as RequestInit
    expect((init.headers as Record<string, string>).Authorization).toBeUndefined()
  })

  it('never writes the token to web storage', async () => {
    fetchMock.mockResolvedValue(json(200, { access_token: 'secret-token', expires_in: 900 }))
    const res = await api.login('alice', 'correct horse battery')
    setToken(res.access_token)
    expect(JSON.stringify({ ...localStorage })).not.toContain('secret-token')
    expect(JSON.stringify({ ...sessionStorage })).not.toContain('secret-token')
  })

  it('normalises gateway errors into ApiError', async () => {
    fetchMock.mockResolvedValue(json(403, { error: { type: 'forbidden', message: 'admin role required', request_id: 'req-9' } }))
    const err = await api.users().catch((e: unknown) => e)
    expect(err).toBeInstanceOf(ApiError)
    expect(err).toMatchObject({ status: 403, type: 'forbidden', message: 'admin role required', requestId: 'req-9' })
  })

  it('handles non-JSON error bodies', async () => {
    fetchMock.mockResolvedValue(new Response('<html>bad gateway</html>', { status: 502 }))
    await expect(api.me()).rejects.toMatchObject({ status: 502, type: 'http_error' })
  })

  it('signals 401 to the session handler, except on the login call itself', async () => {
    const handler = vi.fn()
    setUnauthorizedHandler(handler)
    fetchMock.mockResolvedValue(json(401, { error: { type: 'unauthorized', message: 'bad credentials' } }))
    await expect(api.login('a', 'b')).rejects.toBeInstanceOf(ApiError)
    expect(handler).not.toHaveBeenCalled()
    fetchMock.mockResolvedValue(json(401, { error: { type: 'unauthorized', message: 'expired' } }))
    await expect(api.me()).rejects.toBeInstanceOf(ApiError)
    expect(handler).toHaveBeenCalledOnce()
  })

  it('url-encodes path parameters', async () => {
    fetchMock.mockResolvedValue(new Response(null, { status: 204 }))
    await api.revokeKey('../admin/users')
    expect(fetchMock.mock.calls[0]?.[0]).toBe('/v1/me/api-keys/..%2Fadmin%2Fusers')
  })

  it('drops empty audit filters from the query string', async () => {
    fetchMock.mockResolvedValue(json(200, []))
    await api.auditEvents({ limit: 50, before_seq: undefined, event_type: '', actor: 'u 1' })
    expect(fetchMock.mock.calls[0]?.[0]).toBe('/v1/admin/audit/events?limit=50&actor=u+1')
  })
})

describe('chatStream()', () => {
  const req = { model: 'mock-echo', messages: [{ role: 'user' as const, content: 'hi' }] }

  it('reassembles events split across network chunks', async () => {
    const stream = delta('Hello') + delta(', world') + `data: ${JSON.stringify({ choices: [], guardrail: { action: 'REDACT' } })}\n\n` + 'data: [DONE]\n\n'
    // Cut the byte stream at awkward places, including inside JSON and between the two newlines.
    const cuts = [3, 17, 40, 41, 60, stream.length]
    const chunks: string[] = []
    let prev = 0
    for (const c of cuts) {
      chunks.push(stream.slice(prev, c))
      prev = c
    }
    fetchMock.mockResolvedValue(sse(chunks))
    const deltas: string[] = []
    const onGuardrail = vi.fn()
    await api.chatStream(req, { onDelta: (t) => deltas.push(t), onGuardrail })
    expect(deltas.join('')).toBe('Hello, world')
    expect(onGuardrail).toHaveBeenCalledWith({ action: 'REDACT' })
    const init = fetchMock.mock.calls[0]?.[1] as RequestInit
    expect(JSON.parse(init.body as string)).toMatchObject({ stream: true, model: 'mock-echo' })
  })

  it('stops at [DONE] and ignores anything after it', async () => {
    fetchMock.mockResolvedValue(sse([delta('a'), 'data: [DONE]\n\n', delta('ignored')]))
    const deltas: string[] = []
    await api.chatStream(req, { onDelta: (t) => deltas.push(t) })
    expect(deltas).toEqual(['a'])
  })

  it('turns an in-stream error event into an ApiError', async () => {
    const error = { error: { type: 'output_blocked', message: 'answer withheld', request_id: 'r1' } }
    fetchMock.mockResolvedValue(sse([delta('partial'), `data: ${JSON.stringify(error)}\n\n`]))
    const err = await api.chatStream(req, { onDelta: () => {} }).catch((e: unknown) => e)
    expect(err).toBeInstanceOf(ApiError)
    expect(err).toMatchObject({ status: 200, type: 'output_blocked', requestId: 'r1' })
  })

  it('releases the connection on [DONE], error events and malformed data', async () => {
    // Regression (Phase 5 review): an abandoned reader kept the upstream call running.
    const cases: [string[], boolean][] = [
      [[delta('a'), 'data: [DONE]\n\n', delta('never read')], false],
      [[`data: ${JSON.stringify({ error: { type: 'x', message: 'y' } })}\n\n`, delta('never read')], true],
      [['data: {not json\n\n', delta('never read')], true],
    ]
    for (const [chunks, throws] of cases) {
      let cancelled = false
      const enc = new TextEncoder()
      let i = 0
      const body = new ReadableStream<Uint8Array>({
        pull(controller) {
          const c = chunks[i++]
          if (c === undefined) controller.close()
          else controller.enqueue(enc.encode(c))
        },
        cancel() {
          cancelled = true
        },
      })
      fetchMock.mockResolvedValue(new Response(body, { status: 200 }))
      const run = api.chatStream(req, { onDelta: () => {} })
      if (throws) await expect(run).rejects.toBeTruthy()
      else await run
      await vi.waitFor(() => expect(cancelled).toBe(true))
    }
  })

  it('surfaces a blocked request before any stream starts', async () => {
    fetchMock.mockResolvedValue(json(403, { error: { type: 'policy_blocked', message: 'blocked by policy' } }))
    const onDelta = vi.fn()
    await expect(api.chatStream(req, { onDelta })).rejects.toMatchObject({ status: 403, type: 'policy_blocked' })
    expect(onDelta).not.toHaveBeenCalled()
  })
})
