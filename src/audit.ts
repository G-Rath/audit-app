import { spawn } from 'child_process';
import ReadlineTransform from 'readline-transform';
import {
  Advisories,
  Advisory,
  AuditMetadata,
  AuditOutput,
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
  advisory: Advisory;
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
  const statistics = { ...metadata };

  delete statistics.vulnerabilities;

  return statistics;
};

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
  advisories: Advisories;
  dependencyStatistics: DependencyStatistics;
}

type AuditResultsCollector = (stdout: ReadableStream) => Promise<AuditResults>;

const collectYarnAuditResults: AuditResultsCollector = async stdout => {
  const results: AuditResults = { advisories: {}, dependencyStatistics: {} };

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
          results.advisories[parsedLine.data.advisory.id] =
            parsedLine.data.advisory;
        }
      }, reject)
    );

    stdout.on('close', () => resolve(results));
  });
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
      'close',
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

        resolve({
          advisories: auditOutput.advisories,
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
