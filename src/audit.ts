import { spawnSync } from 'child_process';
import { Advisory, AuditMetadata, AuditResults, Resolution } from './types';

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

/**
 *
 * @param {ParsedJsonLine[]} lines
 *
 * @return {asserts lines is AuditAdvisoryLine[]}
 */
function assertContainsOnlyAuditAdvisoryLines(
  lines: ParsedJsonLine[]
): asserts lines is AuditAdvisoryLine[] {
  const otherLines = lines.filter(line => line.type !== 'auditAdvisory');

  if (otherLines.length) {
    throw new Error(
      `Expected lines to all be "auditAdvisory" type, but found type "${otherLines
        .map(line => line.type)
        .join('", & "')}" too`
    );
  }
}

export const parseYarnAuditLines = (
  str: string
): [AuditSummaryLine, ...AuditAdvisoryLine[]] => {
  const parsedLines = str
    .trim()
    .split('\n')
    .map(line => JSON.parse(line) as ParsedJsonLine);
  const summary = parsedLines.pop();

  if (summary?.type !== 'auditSummary') {
    throw new Error('Could not find "auditSummary" in `yarn audit` output');
  }

  assertContainsOnlyAuditAdvisoryLines(parsedLines);

  return [summary, ...parsedLines];
};

const parseYarnAuditOutput = (output: string): AuditResults => {
  const [{ data: metadata }, ...advisingLines] = parseYarnAuditLines(output);
  const advisories: AuditResults['advisories'] = {};

  advisingLines.forEach(
    advisory => (advisories[advisory.data.advisory.id] = advisory.data.advisory)
  );

  return {
    actions: [],
    advisories,
    muted: [],
    metadata
  };
};

export const audit = async (
  dir: string,
  packageManager: SupportedPackageManager
): Promise<AuditResults> => {
  const { stdout } = spawnSync(
    packageManager,
    [
      'audit',
      '--json',
      `--${packageManager === 'yarn' ? 'cwd' : 'prefix'}`,
      '.'
    ],
    { encoding: 'utf-8', cwd: dir }
  );

  if (packageManager === 'yarn') {
    return parseYarnAuditOutput(stdout);
  }

  return Promise.resolve(JSON.parse(stdout) as AuditResults);
};
