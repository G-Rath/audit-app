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

const tryOrCall = <TParams extends unknown[]>(
  fn: (...args: TParams) => void,
  er: (error: Error) => void
) => (...args: TParams): void => {
  try {
    fn(...args);
  } catch (error) {
    er(error);
  }
};

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

  return new Promise<AuditResults>((resolve, reject) => {
    stdout.on('error', reject);

    stdout.on(
      'data',
      tryOrCall<[string]>(line => {
        const parsedLine = JSON.parse(line) as ParsedJsonLine;

        if (parsedLine.type === 'auditSummary') {
          results.dependencyStatistics = extractDependencyStatistics(
            parsedLine.data
          );
        }

        if (parsedLine.type === 'auditAdvisory') {
          results.findings[
            parsedLine.data.advisory.id.toString()
          ] = npm6AdvisoryToFinding(parsedLine.data.advisory);
        }
      }, reject)
    );

    stdout.on('end', () => resolve(results));
  });
};

const toMapOfFindings = (findings: Finding[]): Record<string, Finding> => {
  const theFindings: Record<string, Finding> = {};

  findings.forEach(finding => (theFindings[finding.id.toString()] = finding));

  return theFindings;
};

type Npm7VulnerabilityWithAdvisory = Omit<Npm7Vulnerability, 'via'> & {
  via: [Npm7Advisory];
};

const collectNpmAuditResults: AuditResultsCollector = async stdout => {
  let json = '';

  return new Promise<AuditResults>((resolve, reject) => {
    stdout.on('error', reject);

    stdout.on(
      'data',
      tryOrCall<[string]>(line => (json += line), reject)
    );

    stdout.on(
      'end',
      tryOrCall(() => {
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
          resolve({
            findings: toMapOfFindings(
              Object.values(auditOutput.vulnerabilities)
                .filter(
                  (vul): vul is Npm7VulnerabilityWithAdvisory =>
                    vul.via.length === 1 && typeof vul.via[0] === 'object'
                )
                .map(vul => npm7AdvisoryToFinding(vul.via[0]))
            ),
            dependencyStatistics: extractDependencyStatisticsFromNpm7(
              auditOutput.metadata
            )
          });

          return;
        }

        resolve({
          findings: toMapOfFindings(
            Object.values(auditOutput.advisories).map(npm6AdvisoryToFinding)
          ),
          dependencyStatistics: extractDependencyStatistics(
            auditOutput.metadata
          )
        });
      }, reject)
    );
  });
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
