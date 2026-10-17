// Response shapes of the gateway API (see docs/API.md).

export type Role = 'developer' | 'admin'
export type Action = 'ALLOW' | 'REDACT' | 'REQUIRE_APPROVAL' | 'BLOCK'
export type OutputActionName = 'ALLOW' | 'REDACT' | 'BLOCK'
export type Severity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'

export interface User {
  id: string
  username: string
  role: Role
  is_active: boolean
  created_by?: string | null
}

export interface Finding {
  rule_id: string
  entity_type: string
  category: string
  severity: Severity
  confidence: number
  detector: string
  start: number
  end: number
  length: number
  redactable: boolean
  explanation: string
  corroborated_by: string[]
  action: Action
  reason: string
}

export interface Replacement {
  placeholder: string
  entity_type: string
  rule_id: string
  start: number
  end: number
  fingerprint: string
}

export interface InspectResult {
  action: Action
  risk_score: number
  risk_level: 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  reasons: string[]
  findings: Finding[]
  sanitized_text: string | null
  replacements: Replacement[]
  normalized: boolean
  scan_ms: number
  request_id: string
}

export interface CodeFinding {
  rule_id: string
  cwe: string
  severity: Severity
  language: string
  block: number
  line: number
  message: string
}

export interface OutputSummary {
  action: OutputActionName
  entities: Record<string, number>
  placeholders: string[]
  code_findings: CodeFinding[]
  reason: string | null
}

export interface GuardrailInfo {
  request_id: string
  action: Action | 'APPROVED'
  risk_score?: number
  placeholders: string[]
  reasons?: string[]
  output_inspected?: boolean
  output?: OutputSummary
  approval_id?: string
  audit_incomplete?: boolean
  findings?: Omit<Finding, 'start' | 'end' | 'length'>[]
  sanitized_messages?: string[]
  entities?: Record<string, number>
  expires_at?: string
}

export interface ChatCompletion {
  id: string
  model: string
  choices: { index: number; message: { role: string; content: string }; finish_reason: string }[]
  usage: { prompt_tokens: number; completion_tokens: number; total_tokens: number }
  guardrail: GuardrailInfo
}

export interface ModelList {
  data: { id: string; owned_by: string }[]
}

export type ApprovalStatus = 'pending' | 'approved' | 'denied' | 'executed' | 'expired'

export interface Approval {
  id: string
  requester_id: string
  status: ApprovalStatus
  created_at: string
  expires_at: string
  decided_at: string | null
  decided_by: string | null
  decision_note: string | null
  executed_at: string | null
  request_id: string
  model: string
  risk_score: number
  summary: {
    action: Action
    entities: Record<string, number>
    rules: string[]
    placeholders: string[]
    messages: number
    reasons: string[]
    model?: string
  }
  messages?: { role: string; content: string }[] | null
}

export interface ApiKeyInfo {
  id: string
  name: string
  prefix: string
  created_at: string
  last_used_at: string | null
  revoked_at: string | null
}

export interface CreatedApiKey {
  id: string
  name: string
  prefix: string
  key: string
}

export interface AuditEvent {
  seq: number
  event_id: string
  occurred_at: string
  recorded_at: string
  event_type: string
  actor: string
  request_id: string | null
  data: Record<string, unknown>
  prev_hash: string
  hash: string
  key_id: string
}

export interface VerifyIssue {
  seq: number | null
  kind: string
  detail: string
}

export interface VerifyReport {
  ok: boolean
  events_checked: number
  last_seq: number
  head_seq: number | null
  checkpoints_checked: number
  anchor_checked: boolean
  first_bad_seq: number | null
  issues: VerifyIssue[]
  issues_truncated: boolean
}

export interface Metrics {
  window_hours: number
  events: number
  requests: number
  protected_requests: number
  protection_rate: number
  active_users: number
  actions: Record<Action, number>
  timeline: ({ bucket: string } & Record<Action, number>)[]
  top_entities: [string, number][]
  top_rules: [string, number][]
  output_entities: [string, number][]
  code_findings: [string, number][]
  risk_bands: Record<'none' | 'low' | 'medium' | 'high' | 'critical', number>
  models: [string, number][]
  provider_errors: number
  output_blocked: number
  failed_logins: number
  inspections: number
  /** Where inspect-only checks came from: "api" or "extension:<site>". */
  inspection_sources: [string, number][]
  /** More events than the server aggregates: only the newest ones were used. */
  truncated: boolean
}

export type Policy = Record<string, unknown> & {
  name: string
  description: string
  default_action: Action
  min_confidence: number
  category_actions: Record<string, Action>
  entity_actions: Record<string, Action>
  output: {
    category_actions: Record<string, OutputActionName>
    entity_actions: Record<string, OutputActionName>
    code: { mode: string; block_at: string | number }
  }
}
