// Calls to the guardrail gateway. Runs in the service worker only: the API key
// is attached here and nowhere else. Requests go only to the configured gateway
// origin, never follow redirects, send no cookies and time out.

import type { Settings } from './config'
import type { Action, PublicFinding, UnavailableReason, Verdict } from './messages'

export const MAX_TEXT = 100_000
const TIMEOUT_MS = 10_000
const ACTIONS: readonly Action[] = ['ALLOW', 'REDACT', 'REQUIRE_APPROVAL', 'BLOCK']

type Fetch = typeof fetch

async function call(fetchImpl: Fetch, settings: Settings, key: string, path: string, body?: unknown): Promise<Response> {
  return fetchImpl(new URL(path, settings.gatewayUrl).toString(), {
    method: body === undefined ? 'GET' : 'POST',
    headers: {
      Authorization: `Bearer ${key}`,
      ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
    credentials: 'omit',
    cache: 'no-store',
    redirect: 'error',
    referrerPolicy: 'no-referrer',
    signal: AbortSignal.timeout(TIMEOUT_MS),
  })
}

function failure(status: number): UnavailableReason {
  if (status === 401 || status === 403) return 'unauthorized'
  if (status === 429) return 'rate_limited'
  if (status === 413 || status === 422) return 'too_long'
  return status >= 500 ? 'unreachable' : 'bad_response'
}

function parseFindings(raw: unknown): PublicFinding[] {
  if (!Array.isArray(raw)) return []
  return raw.slice(0, 50).flatMap((f: unknown) => {
    if (typeof f !== 'object' || f === null) return []
    const { entity_type: entityType, severity, action } = f as Record<string, unknown>
    if (typeof entityType !== 'string' || typeof severity !== 'string') return []
    if (action === 'ALLOW') return [] // below policy thresholds: not acted on
    return [{ entityType: entityType.slice(0, 64), severity: severity.slice(0, 16) }]
  })
}

/** Ask the gateway for a decision on a prompt typed into `siteId`. */
export async function inspectPrompt(
  fetchImpl: Fetch,
  settings: Settings,
  key: string | null,
  text: string,
  siteId: string,
): Promise<Verdict> {
  const unavailable = (reason: UnavailableReason): Verdict => ({
    kind: 'unavailable',
    reason,
    // A prompt too large to inspect is never let through, whatever the mode.
    failMode: reason === 'too_long' ? 'block' : settings.failMode,
  })
  if (!key || !settings.gatewayUrl) return unavailable('not_configured')
  if (text.length > MAX_TEXT) return unavailable('too_long')

  let res: Response
  try {
    res = await call(fetchImpl, settings, key, '/v1/inspect', { text, source: `extension:${siteId}` })
  } catch {
    return unavailable('unreachable')
  }
  if (!res.ok) return unavailable(failure(res.status))

  let body: Record<string, unknown>
  try {
    body = (await res.json()) as Record<string, unknown>
  } catch {
    return unavailable('bad_response')
  }
  const action = body.action as Action
  if (!ACTIONS.includes(action)) return unavailable('bad_response')
  const sanitized = typeof body.sanitized_text === 'string' ? body.sanitized_text : null
  if (action === 'REDACT' && sanitized === null) return unavailable('bad_response')
  return {
    kind: 'decision',
    action,
    sanitizedText: action === 'BLOCK' ? null : sanitized,
    findings: parseFindings(body.findings),
    reasons: Array.isArray(body.reasons) ? body.reasons.filter((r): r is string => typeof r === 'string').slice(0, 5) : [],
    riskScore: typeof body.risk_score === 'number' ? body.risk_score : 0,
  }
}

/** Authenticated probe used by the popup and options page. */
export async function whoAmI(
  fetchImpl: Fetch,
  settings: Settings,
  key: string,
): Promise<{ ok: true; username: string; role: string } | { ok: false; reason: UnavailableReason }> {
  if (!settings.gatewayUrl) return { ok: false, reason: 'not_configured' }
  try {
    const res = await call(fetchImpl, settings, key, '/v1/me')
    if (!res.ok) return { ok: false, reason: failure(res.status) }
    const me = (await res.json()) as Record<string, unknown>
    if (typeof me.username !== 'string' || typeof me.role !== 'string') return { ok: false, reason: 'bad_response' }
    return { ok: true, username: me.username, role: me.role }
  } catch {
    return { ok: false, reason: 'unreachable' }
  }
}
