import { spawn } from 'child_process';
import ReadlineTransform from 'readline-transform';
import {
  AuditMetadata,
  AuditOutput,
  Finding,
  Npm6Advisory,
  Npm7Advisory,
  Npm7AuditMetadata,
  Npm7Vulnerability,
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

const extractDependencyStatisticsFromNpm7 = (
  metadata: Npm7AuditMetadata
): DependencyStatistics => ({
  dependencies: metadata.dependencies.prod,
  devDependencies: metadata.dependencies.dev,
  optionalDependencies: metadata.dependencies.optional,
  totalDependencies: metadata.dependencies.total
});

export interface AuditResults {
  findings: Record<string, Finding>;
  dependencyStatistics: DependencyStatistics;
}

type AuditResultsCollector = (stdout: ReadableStream) => Promise<AuditResults>;

const npm7AdvisoryToFinding = (advisory: Npm7Advisory): Finding => ({
  id: advisory.source,
  name: advisory.name,
  paths: [advisory.dependency],
  range: advisory.range,
  severity: advisory.severity,
  title: advisory.title,
  url: advisory.url
});

const npm6AdvisoryToFinding = (advisory: Npm6Advisory): Finding => ({
  id: advisory.id,
  name: advisory.module_name,
  paths: advisory.findings.reduce<string[]>(
    (acc, finding) => acc.concat(finding.paths),
    []
  ),
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

const toMapOfFindings = (findings: Finding[]): Record<string, Finding> => {
  const theFindings: Record<string, Finding> = {};

  findings.forEach(finding => (theFindings[finding.id.toString()] = finding));

  return theFindings;
};

/**
 * Finds all the advisories that are included with the given record of
 * `vulnerabilities` provided by the audit output of `npm` v7.
 *
 * @param {Record<string, Npm7Vulnerability>} vulnerabilities
 *
 * @return {Array<Npm7Advisory>}
 */
const findAdvisories = (
  vulnerabilities: Record<string, Npm7Vulnerability>
): Npm7Advisory[] => {
  return Object.values(vulnerabilities)
    .reduce<Array<Npm7Advisory | string>>((all, { via }) => all.concat(via), [])
    .filter((via): via is Npm7Advisory => typeof via === 'object');
};

const collectNpmAuditResults: AuditResultsCollector = async stdout => {
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
    return {
      findings: toMapOfFindings(
        findAdvisories(auditOutput.vulnerabilities).map(via =>
          npm7AdvisoryToFinding(via)
        )
      ),
      dependencyStatistics: extractDependencyStatisticsFromNpm7(
        auditOutput.metadata
      )
    };
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
    stdout.pipe(new ReadlineTransform({ skipEmpty: true }))
  );
};
