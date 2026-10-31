// Minimal fetch client for the KubeShield API.
// - Session is an HttpOnly cookie set by the backend; nothing is stored client-side.
// - Every state-changing request carries X-Requested-With: kubeshield (CSRF defence).
// - A 401 on any authenticated call hands control to the registered unauthorized handler.

import type {
  ActionSpec,
  AuditEntry,
  ClusterResponse,
  Detection,
  ImageScan,
  ImageScanDetail,
  ImagesResponse,
  Incident,
  IncidentDetail,
  IncidentStatus,
  Me,
  MitreCoverage,
  NetworkFlowsResponse,
  NetworkSummary,
  Overview,
  Paged,
  Playbook,
  PlaybookInput,
  PoliciesResponse,
  PolicyViolation,
  PostureFindingsResponse,
  PreflightResult,
  ResponseAction,
  RuntimeSettings,
  Sbom,
  Scenario,
  SecurityEvent,
  SettingsResponse,
  SimulationRun,
  SystemStatus,
  Vulnerability,
} from './types'

const BASE = '/api/v1'

export class ApiError extends Error {
  readonly status: number
  readonly detail: string

  constructor(status: number, detail: string) {
    super(detail)
    this.name = 'ApiError'
    this.status = status
    this.detail = detail
  }
}

type QueryValue = string | number | boolean | null | undefined | (string | number)[]
export type Query = Record<string, QueryValue>

let unauthorizedHandler: (() => void) | null = null

/** Registered by the auth provider; called whenever an authenticated request returns 401. */
export function onUnauthorized(handler: (() => void) | null): void {
  unauthorizedHandler = handler
}

function buildUrl(path: string, query?: Query): string {
  const params = new URLSearchParams()
  if (query) {
    for (const [key, value] of Object.entries(query)) {
      if (value === undefined || value === null || value === '') continue
      if (Array.isArray(value)) {
        for (const v of value) params.append(key, String(v))
      } else {
        params.append(key, String(value))
      }
    }
  }
  const qs = params.toString()
  return `${BASE}${path}${qs ? `?${qs}` : ''}`
}

function detailFrom(body: unknown, fallback: string): string {
  if (body && typeof body === 'object' && 'detail' in body) {
    const d = (body as { detail: unknown }).detail
    if (typeof d === 'string') return d
    if (Array.isArray(d)) {
      // FastAPI validation errors: [{loc, msg, type}]
      return d
        .map((e) => {
          if (e && typeof e === 'object' && 'msg' in e) {
            const loc = 'loc' in e && Array.isArray(e.loc) ? `${e.loc.slice(1).join('.')}: ` : ''
            return `${loc}${String(e.msg)}`
          }
          return String(e)
        })
        .join('; ')
    }
  }
  return fallback
}

async function request<T>(
  method: 'GET' | 'POST' | 'PUT' | 'DELETE',
  path: string,
  opts: { query?: Query; body?: unknown; signal?: AbortSignal; skipAuthRedirect?: boolean } = {},
): Promise<T> {
  const headers: Record<string, string> = { Accept: 'application/json' }
  if (method !== 'GET') headers['X-Requested-With'] = 'kubeshield'
  if (opts.body !== undefined) headers['Content-Type'] = 'application/json'

  let res: Response
  try {
    res = await fetch(buildUrl(path, opts.query), {
      method,
      headers,
      credentials: 'same-origin',
      body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
      signal: opts.signal,
    })
  } catch (err) {
    if (err instanceof DOMException && err.name === 'AbortError') throw err
    throw new ApiError(0, 'Unable to reach the KubeShield API')
  }

  if (res.status === 204) return undefined as T

  let body: unknown = null
  const text = await res.text()
  if (text) {
    try {
      body = JSON.parse(text)
    } catch {
      body = text
    }
  }

  if (!res.ok) {
    if (res.status === 401 && !opts.skipAuthRedirect && unauthorizedHandler) unauthorizedHandler()
    throw new ApiError(res.status, detailFrom(body, `${res.status} ${res.statusText || 'request failed'}`))
  }
  return body as T
}

const get = <T>(path: string, query?: Query, signal?: AbortSignal) => request<T>('GET', path, { query, signal })
const post = <T>(path: string, body?: unknown) => request<T>('POST', path, { body: body ?? {} })
const put = <T>(path: string, body: unknown) => request<T>('PUT', path, { body })
const del = <T>(path: string) => request<T>('DELETE', path)

export interface EventQuery extends Query {
  severity?: string[]
  source?: string
  namespace?: string
  rule_id?: string
  q?: string
  since_hours?: number
  limit?: number
  offset?: number
}

export const api = {
  // auth
  login: (username: string, password: string) =>
    request<Me>('POST', '/auth/login', { body: { username, password }, skipAuthRedirect: true }),
  logout: () => request<{ status: string }>('POST', '/auth/logout', { body: {}, skipAuthRedirect: true }),
  me: () => request<Me>('GET', '/auth/me', { skipAuthRedirect: true }),

  // overview / system
  overview: (signal?: AbortSignal) => get<Overview>('/overview', undefined, signal),
  systemStatus: (signal?: AbortSignal) => get<SystemStatus>('/system/status', undefined, signal),
  detections: (signal?: AbortSignal) => get<Detection[]>('/detections', undefined, signal),

  // events
  events: (query: EventQuery, signal?: AbortSignal) => get<Paged<SecurityEvent>>('/events', query, signal),
  event: (id: string, signal?: AbortSignal) =>
    get<SecurityEvent>(`/events/${encodeURIComponent(id)}`, undefined, signal),

  // incidents
  incidents: (query: Query, signal?: AbortSignal) => get<Paged<Incident>>('/incidents', query, signal),
  incident: (id: number | string, signal?: AbortSignal) =>
    get<IncidentDetail>(`/incidents/${encodeURIComponent(String(id))}`, undefined, signal),
  setIncidentStatus: (id: number, status: IncidentStatus, note?: string) =>
    post<Incident>(`/incidents/${id}/status`, { status, note: note || null }),

  // responses
  actionCatalog: (signal?: AbortSignal) => get<ActionSpec[]>('/responses/actions', undefined, signal),
  responses: (query: Query, signal?: AbortSignal) => get<Paged<ResponseAction>>('/responses', query, signal),
  response: (id: string) => get<ResponseAction>(`/responses/${encodeURIComponent(id)}`),
  createResponse: (body: { action_type: string; namespace: string; name: string; incident_id?: number | null; reason?: string }) =>
    post<ResponseAction>('/responses', body),
  decideResponse: (id: string, approve: boolean, note?: string) =>
    post<ResponseAction>(`/responses/${encodeURIComponent(id)}/decision`, { approve, note: note || null }),

  // playbooks
  playbooks: (signal?: AbortSignal) => get<Playbook[]>('/playbooks', undefined, signal),
  createPlaybook: (body: PlaybookInput) => post<Playbook>('/playbooks', body),
  updatePlaybook: (id: number, body: PlaybookInput) => put<Playbook>(`/playbooks/${id}`, body),
  deletePlaybook: (id: number) => del<void>(`/playbooks/${id}`),

  // audit
  audit: (query: Query, signal?: AbortSignal) => get<AuditEntry[]>('/audit', query, signal),

  // cluster / posture
  cluster: (signal?: AbortSignal) => get<ClusterResponse>('/cluster', undefined, signal),
  refreshCluster: () => post<{ snapshot_at: string | null }>('/cluster/refresh'),
  postureFindings: (query: Query, signal?: AbortSignal) =>
    get<PostureFindingsResponse>('/posture/findings', query, signal),

  // images
  images: (signal?: AbortSignal) => get<ImagesResponse>('/images', undefined, signal),
  imageScan: (id: string, signal?: AbortSignal) =>
    get<ImageScanDetail>(`/images/scans/${encodeURIComponent(id)}`, undefined, signal),
  scanVulnerabilities: (id: string, query: Query, signal?: AbortSignal) =>
    get<Paged<Vulnerability>>(`/images/scans/${encodeURIComponent(id)}/vulnerabilities`, query, signal),
  scanSbom: (id: string, signal?: AbortSignal) =>
    get<Sbom>(`/images/scans/${encodeURIComponent(id)}/sbom`, undefined, signal),
  requestScan: (image: string) => post<ImageScan>('/images/scans', { image }),
  preflight: (manifest: string, scanImages: boolean) =>
    post<PreflightResult>('/preflight', { manifest, scan_images: scanImages }),

  // policies
  policies: (signal?: AbortSignal) => get<PoliciesResponse>('/policies', undefined, signal),
  violations: (query: Query, signal?: AbortSignal) =>
    get<Paged<PolicyViolation>>('/policies/violations', query, signal),

  // network
  flows: (query: Query, signal?: AbortSignal) => get<NetworkFlowsResponse>('/network/flows', query, signal),
  networkSummary: (signal?: AbortSignal) => get<NetworkSummary>('/network/summary', undefined, signal),

  // simulations
  scenarios: (signal?: AbortSignal) => get<Scenario[]>('/simulations/scenarios', undefined, signal),
  runs: (signal?: AbortSignal) => get<SimulationRun[]>('/simulations/runs', { limit: 50 }, signal),
  run: (id: string, signal?: AbortSignal) =>
    get<SimulationRun>(`/simulations/runs/${encodeURIComponent(id)}`, undefined, signal),
  startRun: (scenarioId: string) => post<SimulationRun>('/simulations/runs', { scenario_id: scenarioId }),

  // MITRE
  mitre: (signal?: AbortSignal) => get<MitreCoverage>('/mitre/coverage', undefined, signal),

  // settings
  settings: (signal?: AbortSignal) => get<SettingsResponse>('/settings', undefined, signal),
  putSetting: (key: string, value: boolean | string) => put<RuntimeSettings>('/settings', { key, value }),
}

export function errorMessage(err: unknown): string {
  if (err instanceof ApiError) return err.status ? `${err.detail} (HTTP ${err.status})` : err.detail
  if (err instanceof Error) return err.message
  return String(err)
}
