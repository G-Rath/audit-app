import { spawn } from 'child_process';
import ReadlineTransform from 'readline-transform';
import { processNpm7AuditOutput } from './processNpm7AuditOutput';
import {
  AuditMetadata,
  AuditOutput,
  Finding,
  Npm6Advisory,
  Resolution,
  Statistics
} from './types';
import ReadableStream = NodeJS.ReadableStream;

type DependencyStatistics = Statistics['dependencies'];

export const SupportedPackageManagers = ['npm', 'pnpm', 'yarn'] as const;

export type SupportedPackageManager = typeof SupportedPackageManagers[number];

// https://github.com/yarnpkg/yarn/blob/17992a7da3e2371af3a264b585f8f9fbf6c511f9/src/cli/commands/audit.js

interface AuditAdvisoryLine {
  type: 'auditAdvisory';
  data: AuditAdvisoryData;
}

interface AuditAdvisoryData {
  resolution: Resolution;
  advisory: Npm6Advisory;
}

interface AuditSummaryLine {
  type: 'auditSummary';
  data: AuditMetadata;
}

type ParsedJsonLine = AuditAdvisoryLine | AuditSummaryLine;

interface NpmError {
  error: {
    code: string;
    summary: string;
    detail: string;
  };
}

type ParsedNpmOutput = AuditOutput | NpmError;

const extractDependencyStatistics = (
  metadata: AuditMetadata
): DependencyStatistics => {
  const statistics: Partial<AuditMetadata> = { ...metadata };

  delete statistics.vulnerabilities;

  return statistics;
};

export interface AuditResults {
  findings: Record<string, Finding>;
  dependencyStatistics: DependencyStatistics;
}

type AuditResultsCollector = (
  stdout: ReadableStream,
  dir: string
) => Promise<AuditResults>;

const npm6AdvisoryToFinding = (advisory: Npm6Advisory): Finding => ({
  id: advisory.id,
  name: advisory.module_name,
  paths: advisory.findings.reduce<string[]>(
    (acc, finding) => acc.concat(finding.paths),
    []
  ),
  versions: advisory.findings.map(finding => finding.version),
  range: advisory.vulnerable_versions,
  severity: advisory.severity,
  title: advisory.title,
  url: advisory.url
});

const collectYarnAuditResults: AuditResultsCollector = async stdout => {
  const results: AuditResults = { findings: {}, dependencyStatistics: {} };

  for await (const line of stdout) {
    const parsedLine = JSON.parse(line.toString()) as ParsedJsonLine;

    if (parsedLine.type === 'auditSummary') {
      results.dependencyStatistics = extractDependencyStatistics(
        parsedLine.data
      );
    }

    if (parsedLine.type === 'auditAdvisory') {
      results.findings[parsedLine.data.advisory.id.toString()] =
        npm6AdvisoryToFinding(parsedLine.data.advisory);
    }
  }

  return results;
};

export const toMapOfFindings = (
  findings: Finding[]
): Record<string, Finding> => {
  const theFindings: Record<string, Finding> = {};

  findings.forEach(finding => (theFindings[finding.id.toString()] = finding));

  return theFindings;
};

const collectNpmAuditResults: AuditResultsCollector = async (stdout, dir) => {
  let json = '';

  for await (const line of stdout) {
    json += line;
  }

  if (json.trim().startsWith('ERROR')) {
    console.log(json);

    throw new Error(json);
  }

  const auditOutput = JSON.parse(json) as ParsedNpmOutput;

  if ('error' in auditOutput) {
    const errorMessage = `${auditOutput.error.code}: ${auditOutput.error.summary}`;

    console.log(errorMessage);

    throw new Error(errorMessage);
  }

  if ('auditReportVersion' in auditOutput) {
    return processNpm7AuditOutput(auditOutput, dir);
  }

  return {
    findings: toMapOfFindings(
      Object.values(auditOutput.advisories).map(npm6AdvisoryToFinding)
    ),
    dependencyStatistics: extractDependencyStatistics(auditOutput.metadata)
  };
};

export const audit = async (
  dir: string,
  packageManager: SupportedPackageManager
): Promise<AuditResults> => {
  const resultsCollector: AuditResultsCollector =
    packageManager === 'yarn'
      ? collectYarnAuditResults
      : collectNpmAuditResults;

  const { stdout } = spawn(
    packageManager,
    [
      'audit',
      '--json',
      `--${packageManager === 'yarn' ? 'cwd' : 'prefix'}`,
      '.'
    ],
    { cwd: dir }
  );

  return resultsCollector(
    stdout.pipe(new ReadlineTransform({ skipEmpty: true })),
    dir
  );
};
