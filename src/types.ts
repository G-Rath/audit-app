export type Severity = 'info' | 'low' | 'moderate' | 'high' | 'critical';

export type SeverityCounts = Record<Severity, number>;

export type Advisories = Record<string, Advisory>;

export interface Statistics {
  dependencies?: number;
  devDependencies?: number;
  optionalDependencies?: number;
  totalDependencies?: number;
}

export interface AuditOutput {
  actions: Action[];
  advisories: Advisories;
  muted: unknown[];
  metadata: AuditMetadata;
  // npm only
  runId?: string;
}

interface Action {
  action: 'update' | 'install' | 'review';
  resolves: Resolution[];
  module: string;
  target: string;
  depth?: number;
  isMajor?: boolean;
}

export interface Resolution {
  id: number;
  path: string;
  dev: boolean;
  optional: boolean;
  bundled: boolean;
}

export interface Advisory {
  findings: AdvisoryFinding[];
  id: number;
  created: string;
  updated: string;
  deleted: null;
  title: string;
  found_by: AdvisoryActor;
  reported_by: AdvisoryActor;
  module_name: string;
  cves: unknown[];
  vulnerable_versions: string;
  patched_versions: string;
  overview: string;
  recommendation: string;
  references: string;
  access: string;
  severity: Severity;
  cwe: string;
  metadata: AdvisoryMetadata;
  url: string;
}

interface AdvisoryFinding {
  version: string;
  paths: string[];
}

interface AdvisoryActor {
  name: string;
  link?: string;
  email?: string;
}

interface AdvisoryMetadata {
  module_type: string;
  exploitability: number;
  affected_components: string;
}

export interface AuditMetadata extends Required<Statistics> {
  vulnerabilities: SeverityCounts;
}
