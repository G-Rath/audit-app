export type Severity = 'info' | 'low' | 'moderate' | 'high' | 'critical';

export type SeverityCounts = Record<Severity, number>;

export type Advisories = Record<number, Advisory>;

export interface AuditResults {
  actions: Action[];
  advisories: Advisories;
  muted: unknown[];
  metadata: AuditMetadata;
}

export interface Action {
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

export interface AdvisoryFinding {
  version: string;
  paths: string[];
}

export interface AdvisoryActor {
  name: string;
  link?: string;
  email?: string;
}

export interface AdvisoryMetadata {
  module_type: string;
  exploitability: number;
  affected_components: string;
}

export interface AuditMetadata {
  vulnerabilities: SeverityCounts;
  dependencies: number;
  devDependencies: number;
  optionalDependencies: number;
  totalDependencies: number;
}

// export interface Advisory {
//   findings: Finding[];
//   id: number;
//   created: string;
//   updated: string;
//   deleted: string | null;
//   title: string;
//   found_by: AdvisoryActor;
//   reported_by: AdvisoryActor;
//   module_name: string;
//   cves: unknown[];
//   vulnerable_versions: string;
//   patched_versions: string;
//   overview: string;
//   recommendation: string;
//   references: string;
//   access: string;
//   severity: Severity;
//   cwe: string;
//   metadata: AdvisoryMetadata;
//   url: string;
// }
