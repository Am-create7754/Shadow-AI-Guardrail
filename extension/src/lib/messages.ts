// Messages between the content script / extension pages and the service worker.
// The content script never sees the API key or the gateway address: it sends
// the prompt text and receives a verdict.

import type { FailMode, UploadPolicy } from './config'

export type Action = 'ALLOW' | 'REDACT' | 'REQUIRE_APPROVAL' | 'BLOCK'

/** What the page is told about a finding: type and severity, never the value. */
export interface PublicFinding {
  entityType: string
  severity: string
}

export type Verdict =
  | {
      kind: 'decision'
      action: Action
      /** Prompt with placeholders; null when blocked. */
      sanitizedText: string | null
      findings: PublicFinding[]
      reasons: string[]
      riskScore: number
    }
  | { kind: 'unavailable'; reason: UnavailableReason; failMode: FailMode }
  | { kind: 'disabled' }
  /** A file the gateway cannot read (not text). */
  | { kind: 'uncheckable'; uploadPolicy: UploadPolicy }

export type UnavailableReason =
  | 'not_configured'
  | 'unauthorized'
  | 'unreachable'
  | 'rate_limited'
  | 'too_long'
  | 'bad_response'

export const REASON_TEXT: Record<UnavailableReason, string> = {
  not_configured: 'The extension has no API key yet. Open its options to connect it to the gateway.',
  unauthorized: 'The gateway rejected the API key (revoked or invalid). Update it in the options.',
  unreachable: 'The guardrail gateway could not be reached.',
  rate_limited: 'The gateway is rate limiting requests; try again shortly.',
  too_long: 'The prompt is longer than the gateway can inspect (100,000 characters).',
  bad_response: 'The gateway returned an unexpected response.',
}

export interface InspectMessage {
  type: 'inspect'
  text: string
}

/** A file about to be uploaded: its text, or null when it is not a text file. */
export interface InspectFileMessage {
  type: 'inspectFile'
  name: string
  text: string | null
}

export interface StatusMessage {
  type: 'status'
}

export type Message = InspectMessage | InspectFileMessage | StatusMessage

export interface Status {
  enabled: boolean
  configured: boolean
  gatewayUrl: string
  failMode: FailMode
  /** Result of an authenticated probe: signed-in user, or why not. */
  connection: { ok: true; username: string; role: string } | { ok: false; reason: UnavailableReason }
  keyPrefix: string | null
}
