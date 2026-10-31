// TypeScript mirrors of the KubeShield API (backend/kubeshield/api/*.py).
// Timestamps are ISO-8601 strings or null.

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'
export const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info']

export type Role = 'viewer' | 'responder' | 'admin'
export const ROLE_RANK: Record<Role, number> = { viewer: 0, responder: 1, admin: 2 }

export type Json = string | number | boolean | null | Json[] | { [key: string]: Json }
export type JsonObject = { [key: string]: Json }

export interface Me {
  username: string
  role: Role
}

export interface Paged<T> {
  total: number
  items: T[]
}

// ----------------------------------------------------------------- events
export interface ProcessInfo {
  name?: string
  cmdline?: string
  pid?: number | string
  exepath?: string
  parent?: string
  parent_cmdline?: string
  user?: string
  uid?: number | string
  tty?: number | string
  [key: string]: Json | undefined
}

export interface SecurityEvent {
  id: string
  source: string
  rule: string
  rule_id: string | null
  detection: string | null
  severity: Severity
  source_priority: string | null
  timestamp: string | null
  ingested_at: string | null
  namespace: string | null
  pod: string | null
  container: string | null
  container_id: string | null
  image: string | null
  node: string | null
  process: ProcessInfo | null
  message: string | null
  evidence: JsonObject | null
  tags: string[] | null
  techniques: string[] | null
  recommended_response: string | null
  incident_id: number | null
  raw?: Json
}

// ----------------------------------------------------------------- incidents
export type IncidentStatus = 'open' | 'investigating' | 'contained' | 'resolved' | 'false_positive'
export const INCIDENT_STATUSES: IncidentStatus[] = ['open', 'investigating', 'contained', 'resolved', 'false_positive']

export interface Incident {
  id: number
  title: string
  status: IncidentStatus
  severity: Severity
  namespace: string | null
  pod: string | null
  workload: string | null
  summary: string | null
  rules: string[] | null
  techniques: string[] | null
  event_count: number
  first_seen: string | null
  last_seen: string | null
  created_at: string | null
  updated_at: string | null
  resolved_at: string | null
}

export interface IncidentDetail extends Incident {
  events: SecurityEvent[]
  actions: ResponseAction[]
  audit_trail: AuditEntry[]
}

// ----------------------------------------------------------------- responses
export type ActionStatus =
  | 'pending_approval'
  | 'approved'
  | 'executing'
  | 'succeeded'
  | 'failed'
  | 'rejected'
  | 'refused'
  | 'alerted'
export const ACTION_STATUSES: ActionStatus[] = [
  'pending_approval', 'approved', 'executing', 'succeeded', 'failed', 'rejected', 'refused', 'alerted',
]

export interface VerificationCheck {
  check: string
  passed: boolean
  observed?: Json
}

export interface Verification {
  verified: boolean
  checks: VerificationCheck[]
}

export interface ResponseAction {
  id: string
  incident_id: number | null
  trigger_event_id: string | null
  playbook_id: number | null
  action_type: string
  mode: 'manual' | 'approval' | 'auto' | 'alert_only' | string
  status: ActionStatus | string
  target: { namespace: string | null; kind: string | null; name: string | null }
  reason: string | null
  requested_by: string | null
  decided_by: string | null
  requested_at: string | null
  decided_at: string | null
  executed_at: string | null
  completed_at: string | null
  result: JsonObject | null
  verification: Verification | null
  error: string | null
}

export interface ActionSpec {
  type: string
  title: string
  description: string
  target_kind: 'Pod' | 'Deployment' | 'Namespace' | string
  destructive: boolean
}

export type PlaybookMode = 'alert_only' | 'approval' | 'auto'

export interface Playbook {
  id: number
  name: string
  description: string
  enabled: boolean
  match_rule_ids: string[]
  min_severity: Severity
  action_type: string
  mode: PlaybookMode
  updated_at: string | null
}

export interface PlaybookInput {
  name: string
  description: string
  enabled: boolean
  match_rule_ids: string[]
  min_severity: Severity
  action_type: string
  mode: PlaybookMode
}

export interface AuditEntry {
  id: number | string
  timestamp: string | null
  actor: string
  action: string
  target: string | null
  incident_id: number | null
  details: Json
  source_ip: string | null
}

// ----------------------------------------------------------------- cluster
export type IntegrationState = 'healthy' | 'degraded' | 'not_installed' | 'unknown'

export interface Integration {
  key: string
  title: string
  namespace: string
  kind: string
  name: string
  installed: boolean | null
  state: IntegrationState
  desired?: number
  ready?: number
  images?: string[]
  error?: string
}

export interface ClusterCounts {
  nodes?: number
  namespaces?: number
  pods?: number
  deployments?: number
  daemonsets?: number
  statefulsets?: number
  service_accounts?: number
  network_policies?: number
  cilium_network_policies?: number
  privileged_pods?: number
  lab_namespaces?: number
}

export interface ClusterNode {
  name: string
  ready: boolean
  kubelet: string | null
  os: string | null
  kernel: string | null
  runtime: string | null
  arch: string | null
  cpu: string | null
  memory: string | null
  roles: string[]
}

export interface ClusterNamespace {
  name: string
  lab: boolean
  policy_mode: string | null
  platform: boolean
  pods: number
  network_policies: number
  cilium_policies: number
  phase: string | null
}

export interface ClusterPod {
  namespace: string
  name: string
  phase: string | null
  node: string | null
  ip: string | null
  service_account: string | null
  images: string[]
  restarts: number
  ready: boolean
  owner: string | null
  quarantined: string | null
  privileged: boolean
  host_network: boolean
  host_pid: boolean
  created: string | null
  platform: boolean
}

export type ClusterResponse =
  | { available: false; error: string | null }
  | {
      available: true
      snapshot_at: string | null
      last_error: string | null
      kubernetes_version: string | null
      platform: string | null
      nodes: ClusterNode[]
      namespaces: ClusterNamespace[]
      pods: ClusterPod[]
      counts: ClusterCounts
      integrations: Integration[]
    }

export interface PostureFinding {
  id: string
  check_id: string
  title: string
  category: string
  severity: Severity
  resource_kind: string | null
  namespace: string | null
  resource_name: string | null
  container: string | null
  explanation: string | null
  remediation: string | null
  evidence: JsonObject | null
  status: 'open' | 'resolved' | string
  first_seen: string | null
  last_seen: string | null
  resolved_at: string | null
}

export interface PostureFindingsResponse extends Paged<PostureFinding> {
  by_category: Record<string, number>
}

// ----------------------------------------------------------------- overview / system
export interface ActivityBucket {
  hour: string
  critical: number
  high: number
  medium: number
  low: number
  info: number
}

export interface Overview {
  generated_at: string
  cluster: {
    available: boolean
    snapshot_at: string | null
    kubernetes_version: string | null
    counts: ClusterCounts
    nodes_ready: number
    integrations: Integration[]
  }
  incidents: { open_by_severity: Partial<Record<Severity, number>>; open_total: number }
  events_24h: {
    by_severity: Partial<Record<Severity, number>>
    total: number
    by_source: Record<string, number>
  }
  activity: ActivityBucket[]
  top_rules: { rule: string; count: number }[]
  posture: { open_by_severity: Partial<Record<Severity, number>> }
  policy: { open_violations: number; blocked_admissions: number }
  images: { scanned: number; vulnerable: number; critical: number }
  responses: Record<string, number>
  recent_events: SecurityEvent[]
}

export interface HubbleStatus {
  connected: boolean
  address: string | null
  last_error: string | null
  last_flow_at: string | null
  flows_seen: number
  flows_stored: number
}

export interface WorkerState {
  running: boolean
  last_run: string | null
  last_error: string | null
  last_result: Json
}

export interface SystemStatus {
  version: string
  kubernetes: { reachable: boolean; error: string | null; mode: string }
  integrations: Integration[]
  falco: { last_event_ingested_at: string | null }
  hubble: HubbleStatus
  trivy: { available: boolean; version: string | null }
  workers: Record<string, WorkerState>
}

export interface DetectionValidation {
  run_id: string
  scenario: string
  at: string | null
}

export interface Detection {
  id: string
  name: string
  source: string
  source_rule: string
  severity: Severity
  description: string
  techniques: string[]
  recommended_response: string
  scenario: string | null
  validated: DetectionValidation | null
  event_count: number
}

// ----------------------------------------------------------------- images
export type ScanStatus = 'queued' | 'running' | 'succeeded' | 'failed'

export interface ImageScan {
  id: string
  image: string
  digest: string | null
  status: ScanStatus | string
  trigger: string | null
  requested_by: string | null
  started_at: string | null
  finished_at: string | null
  error: string | null
  os_family: string | null
  counts: Partial<Record<Severity, number>> | null
  secret_count: number | null
  misconfig_count: number | null
  sbom_components: number | null
  scanner_version: string | null
  workloads: string[] | null
}

export interface ImageFinding {
  kind: 'secret' | 'misconfig' | string
  rule_id: string
  severity: Severity
  title: string
  target: string | null
  details: JsonObject | null
}

export interface ImageScanDetail extends ImageScan {
  findings: ImageFinding[]
}

export interface ImagesResponse {
  scanner: { available: boolean; version: string | null }
  images: ImageScan[]
  recent_scans: ImageScan[]
}

export interface Vulnerability {
  vuln_id: string
  pkg_name: string
  pkg_type: string | null
  installed_version: string | null
  fixed_version: string | null
  severity: Severity
  cvss_score: number | null
  title: string | null
  primary_url: string | null
  target: string | null
  remediation: string
}

export interface SbomComponent {
  name: string | null
  version: string | null
  type: string | null
  purl: string | null
}

export interface Sbom {
  format: string
  component_count: number
  components: SbomComponent[]
  truncated: boolean
}

export interface PreflightResource {
  kind: string | null
  name: string
  admission: 'allowed' | 'denied' | 'error' | 'skipped'
  message: string | null
}

export interface PreflightConfigFinding {
  id: string | null
  title: string | null
  severity: Severity
  message: string | null
  resolution: string | null
}

export interface PreflightImage {
  image: string
  status: 'invalid' | 'scanned' | 'queued' | 'running' | 'not_scanned' | string
  scan_id?: string
  counts?: Partial<Record<Severity, number>>
  scanned_at?: string | null
}

export interface PreflightResult {
  verdict: 'pass' | 'warn' | 'fail'
  namespace: string
  resources: PreflightResource[]
  config_findings: { findings: PreflightConfigFinding[]; error?: string }
  images: PreflightImage[]
}

// ----------------------------------------------------------------- policies
export interface KyvernoPolicy {
  name: string
  control: string | null
  title: string
  severity: Severity
  remediation: string
  mode: 'enforce' | 'audit'
  validation_actions: string[]
  namespace_selector: Json
  background: boolean
  ready: boolean | null
  message: string | null
  managed_by_kubeshield: boolean
  rules: (string | null)[]
  open_violations: number
  admission_denials: number
}

export interface PoliciesResponse {
  available: boolean
  error: string | null
  policies: KyvernoPolicy[]
}

export interface PolicyViolation {
  id: string
  source: 'report' | 'admission' | string
  policy: string
  control: string | null
  mode: string | null
  severity: Severity
  result: string
  namespace: string | null
  resource_kind: string | null
  resource_name: string | null
  message: string | null
  remediation: string | null
  status: 'open' | 'resolved' | 'blocked' | string
  first_seen: string | null
  last_seen: string | null
}

// ----------------------------------------------------------------- network
export interface NetworkFlow {
  id: number | string
  timestamp: string | null
  verdict: string
  drop_reason: string | null
  direction: string | null
  protocol: string | null
  src_namespace: string | null
  src_pod: string | null
  src_ip: string | null
  dst_namespace: string | null
  dst_pod: string | null
  dst_ip: string | null
  dst_port: number | null
  dst_service: string | null
  node: string | null
}

export interface NetworkFlowsResponse {
  source: string
  hubble: HubbleStatus
  items: NetworkFlow[]
}

export interface K8sNetworkPolicy {
  namespace: string
  name: string
  pod_selector: Record<string, string>
  policy_types: string[]
  ingress_rules: number
  egress_rules: number
}

export interface CiliumPolicy {
  namespace: string
  name: string
  deny: boolean
  description: string | null
  managed_by_kubeshield: boolean
}

export interface NetworkSummary {
  window_hours: number
  observation_source: string
  hubble: HubbleStatus
  edges: { src: string; dst: string; verdict: string; count: number }[]
  verdicts: Record<string, number>
  namespaces: { name: string; lab: boolean; network_policies: number; cilium_policies: number; platform: boolean }[]
  network_policies: K8sNetworkPolicy[]
  cilium_policies: CiliumPolicy[]
  error: string | null
}

// ----------------------------------------------------------------- simulations
export type RunOutcome = 'detected' | 'blocked' | 'partial' | 'missed' | 'error'

export interface SimulationStep {
  at: string
  title: string
  command?: string[]
  exit_code?: number | null
  stdout?: string
  stderr?: string
  [key: string]: Json | undefined
}

export interface SimulationCheck {
  title: string
  passed: boolean
  [key: string]: Json | undefined
}

export interface SimulationEvidence {
  event_ids?: string[]
  incident_ids?: number[]
  response_actions?: { id: string; action: string; status: string; mode: string }[]
  scan_id?: string
  findings?: string[]
  policies?: string[]
  [key: string]: Json | undefined
}

export interface SimulationRun {
  id: string
  scenario_id: string
  status: 'running' | 'completed' | 'error'
  outcome: RunOutcome | null
  requested_by: string | null
  started_at: string | null
  finished_at: string | null
  steps: SimulationStep[] | null
  checks: SimulationCheck[] | null
  evidence: SimulationEvidence | null
  error: string | null
  incident_id: number | null
}

export interface Scenario {
  id: string
  title: string
  description: string
  objective: string
  target: string
  procedure: string[]
  expected_telemetry: string
  expected_detections: string[]
  expected_response: string
  techniques: string[]
  kind: 'runtime' | 'admission' | 'posture' | 'image' | string
  last_run: SimulationRun | null
}

// ----------------------------------------------------------------- MITRE
export type CoverageStatus = 'validated' | 'implemented' | 'not_covered'

export interface TechniqueCoverage {
  id: string
  name: string
  tactics: string[]
  matrix: 'containers' | 'linux' | string
  status: CoverageStatus
  detections: { id: string; name: string; source: string; validated: boolean }[]
  validations: { detection: string; run_id: string; scenario: string; at: string | null }[]
  observed_events: number
}

export interface MitreCoverage {
  reference_set: string
  total_techniques: number
  validated: number
  implemented: number
  validated_pct: number
  implemented_pct: number
  tactics: string[]
  techniques: TechniqueCoverage[]
  observed_other_techniques: { id: string; observed_events: number }[]
}

// ----------------------------------------------------------------- settings
export interface RuntimeSettings {
  'response.auto_enabled': boolean
  'response.auto_destructive_enabled': boolean
  'incidents.min_severity': Severity
  'simulation.enabled': boolean
  'scanner.scan_workload_images': boolean
  [key: string]: boolean | string
}

export interface SettingsResponse {
  runtime: RuntimeSettings
  static: {
    lab_label: string
    kube_mode: string
    preflight_namespace: string
    hubble_relay_address: string | null
    incident_window_minutes: number
    session_ttl_minutes: number
  }
}
