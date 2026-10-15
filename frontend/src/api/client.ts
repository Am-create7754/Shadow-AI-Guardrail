// Thin, typed client for the gateway API.
//
// * The session token lives only in memory (see auth/AuthContext): never in
//   localStorage/sessionStorage, where an injected script could read it later.
// * Every error is normalised to ApiError using the gateway's
//   {"error": {type, message, request_id, details}} shape.

import type {
  ApiKeyInfo,
  Approval,
  AuditEvent,
  ChatCompletion,
  CreatedApiKey,
  GuardrailInfo,
  InspectResult,
  Metrics,
  ModelList,
  Policy,
  Role,
  User,
  VerifyReport,
} from './types'

export class ApiError extends Error {
  readonly status: number
  readonly type: string
  readonly requestId: string | undefined
  readonly details: unknown

  constructor(status: number, type: string, message: string, requestId?: string, details?: unknown) {
    super(message)
    this.status = status
    this.type = type
    this.requestId = requestId
    this.details = details
  }
}

let token: string | null = null
let onUnauthorized: (() => void) | null = null

export function setToken(value: string | null): void {
  token = value
}

export function setUnauthorizedHandler(handler: (() => void) | null): void {
  onUnauthorized = handler
}

function headers(json: boolean): HeadersInit {
  const h: Record<string, string> = {}
  if (json) h['Content-Type'] = 'application/json'
  if (token) h.Authorization = `Bearer ${token}`
  return h
}

async function toApiError(res: Response): Promise<ApiError> {
  let body: unknown = null
  try {
    body = await res.json()
  } catch {
    // non-JSON error body (e.g. a proxy page): fall through to a generic message
  }
  const err = (body as { error?: { type?: string; message?: string; request_id?: string; details?: unknown } } | null)?.error
  return new ApiError(
    res.status,
    err?.type ?? 'http_error',
    err?.message ?? `request failed (HTTP ${res.status})`,
    err?.request_id,
    err?.details,
  )
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch(path, {
    method,
    headers: headers(body !== undefined),
    body: body === undefined ? undefined : JSON.stringify(body),
    credentials: 'omit',
    cache: 'no-store',
  })
  if (!res.ok) {
    const err = await toApiError(res)
    if (res.status === 401 && onUnauthorized && path !== '/v1/auth/login') onUnauthorized()
    throw err
  }
  if (res.status === 204) return undefined as T
  return (await res.json()) as T
}

export interface ChatRequest {
  model: string
  messages: { role: 'system' | 'user' | 'assistant'; content: string }[]
  temperature?: number
  max_tokens?: number
}

export interface StreamHandlers {
  onDelta: (text: string) => void
  onGuardrail?: (info: GuardrailInfo) => void
}

export const api = {
  login: (username: string, password: string) =>
    request<{ access_token: string; expires_in: number }>('POST', '/v1/auth/login', { username, password }),
  logout: () => request<void>('POST', '/v1/auth/logout'),
  me: () => request<User>('GET', '/v1/me'),
  models: () => request<ModelList>('GET', '/v1/models'),
  inspect: (text: string) => request<InspectResult>('POST', '/v1/inspect', { text }),
  chat: (req: ChatRequest) => request<ChatCompletion>('POST', '/v1/chat/completions', { ...req, stream: false }),

  myApprovals: () => request<Approval[]>('GET', '/v1/approvals'),
  executeApproval: (id: string) => request<ChatCompletion>('POST', `/v1/approvals/${encodeURIComponent(id)}/execute`),
  myKeys: () => request<ApiKeyInfo[]>('GET', '/v1/me/api-keys'),
  createKey: (name: string) => request<CreatedApiKey>('POST', '/v1/me/api-keys', { name }),
  revokeKey: (id: string) => request<void>('DELETE', `/v1/me/api-keys/${encodeURIComponent(id)}`),

  adminApprovals: (status?: string) =>
    request<Approval[]>('GET', `/v1/admin/approvals${status ? `?status=${encodeURIComponent(status)}` : ''}`),
  adminApproval: (id: string) => request<Approval>('GET', `/v1/admin/approvals/${encodeURIComponent(id)}`),
  decide: (id: string, approve: boolean, note?: string) =>
    request<Approval>('POST', `/v1/admin/approvals/${encodeURIComponent(id)}/${approve ? 'approve' : 'deny'}`, {
      note: note || null,
    }),
  auditEvents: (params: { limit?: number; before_seq?: number; event_type?: string; actor?: string }) => {
    const q = new URLSearchParams()
    for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== '') q.set(k, String(v))
    return request<AuditEvent[]>('GET', `/v1/admin/audit/events?${q.toString()}`)
  },
  verifyAudit: () => request<VerifyReport>('GET', '/v1/admin/audit/verify'),
  metrics: (hours: number) => request<Metrics>('GET', `/v1/admin/metrics?hours=${hours}`),
  policy: () => request<Policy>('GET', '/v1/admin/policy'),
  users: () => request<User[]>('GET', '/v1/admin/users'),
  createUser: (username: string, password: string, role: Role) =>
    request<User>('POST', '/v1/admin/users', { username, password, role }),
  setUserActive: (id: string, isActive: boolean) =>
    request<User>('PATCH', `/v1/admin/users/${encodeURIComponent(id)}`, { is_active: isActive }),

  /** Streamed chat (OpenAI SSE format). Resolves when the stream ends. */
  async chatStream(req: ChatRequest, handlers: StreamHandlers, signal?: AbortSignal): Promise<void> {
    const res = await fetch('/v1/chat/completions', {
      method: 'POST',
      headers: headers(true),
      body: JSON.stringify({ ...req, stream: true }),
      credentials: 'omit',
      cache: 'no-store',
      signal,
    })
    if (!res.ok) {
      const err = await toApiError(res)
      if (res.status === 401 && onUnauthorized) onUnauthorized()
      throw err
    }
    if (!res.body) throw new ApiError(0, 'stream_unsupported', 'streaming is not supported by this browser')
    const reader = res.body.pipeThrough(new TextDecoderStream()).getReader()
    // Always release the connection - on [DONE], on an error event, on bad JSON -
    // so the gateway stops the upstream call instead of generating unseen tokens.
    try {
      let buffer = ''
      for (;;) {
        const { value, done } = await reader.read()
        if (done) break
        buffer += value
        let idx: number
        while ((idx = buffer.indexOf('\n\n')) !== -1) {
          const event = buffer.slice(0, idx)
          buffer = buffer.slice(idx + 2)
          for (const line of event.split('\n')) {
            if (!line.startsWith('data:')) continue
            const data = line.slice(5).trim()
            if (data === '[DONE]') return
            const obj = JSON.parse(data) as {
              error?: { type: string; message: string; request_id?: string }
              choices?: { delta?: { content?: string } }[]
              guardrail?: GuardrailInfo
            }
            if (obj.error) {
              throw new ApiError(200, obj.error.type, obj.error.message, obj.error.request_id, obj.error)
            }
            const text = obj.choices?.[0]?.delta?.content
            if (text) handlers.onDelta(text)
            if (obj.guardrail) handlers.onGuardrail?.(obj.guardrail)
          }
        }
      }
    } finally {
      await reader.cancel().catch(() => {})
    }
  },
}
