export type Severity = 'info' | 'low' | 'moderate' | 'high' | 'critical';

export type SeverityCounts = Record<Severity, number>;
export type SeverityCountsWithTotal = Record<Severity | 'total', number>;

export type Advisories = Record<string, Npm6Advisory>;

interface DependencyStatistics {
  dependencies?: number;
  devDependencies?: number;
  optionalDependencies?: number;
  totalDependencies?: number;
}

interface DependencyCounts {
  prod: number;
  dev: number;
  optional: number;
  peer: number;
  peerOptional: number;
  total: number;
}

export interface Statistics {
  dependencies: DependencyStatistics;
  severities: SeverityCountsWithTotal;
  vulnerable: SeverityCountsWithTotal;
  ignored: SeverityCountsWithTotal;
}

export type AuditOutput = NpmAuditOutput | PnpmAuditOutput | YarnAuditOutput;

export type NpmAuditOutput = Npm6AuditOutput | Npm7AuditOutput;
export type PnpmAuditOutput = Npm6AuditOutput;
export type YarnAuditOutput = Npm6AuditOutput;

export interface Npm6AuditOutput {
  actions: Action[];
  advisories: Advisories;
  muted: unknown[];
  metadata: AuditMetadata;
  // npm only
  runId?: string;
}

export interface Finding {
  id: number;
  name: string;
  paths: string[];
  versions: string[];
  range: string;
  severity: Severity;
  title: string;
  url: string;
}

export interface Npm7Vulnerability {
  name: string;
  via: Array<Npm7Advisory | string>;
  effects: string[];
  range: string;
  nodes: string[];
  fixAvailable: Fix | boolean;
  severity: Severity;
}

export interface Npm7AuditOutput {
  auditReportVersion: 2;
  vulnerabilities: Record<string, Npm7Vulnerability>;
  metadata: Npm7AuditMetadata;
}

export interface Npm7Advisory {
  source: number;
  name: string;
  dependency: string;
  title: string;
  url: string;
  severity: Severity;
  range: string;
}

interface Fix {
  name: string;
  version: string;
  isSemVerMajor: boolean;
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

export interface Npm6Advisory {
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

export interface AuditMetadata extends Required<DependencyStatistics> {
  vulnerabilities: SeverityCounts;
}

export interface Npm7AuditMetadata {
  vulnerabilities: SeverityCountsWithTotal;
  dependencies: DependencyCounts;
}

export interface PackageJson {
  name?: string;
  version?: string;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  workspaces?: string[];
}

export interface NpmLockDependency {
  version: string;
  requires?: Record<string, string>;
  dependencies?: Record<string, NpmLockDependency>;
}

export interface NpmPackageLock {
  version: string;
  dependencies: Record<string, NpmLockDependency>;
}
