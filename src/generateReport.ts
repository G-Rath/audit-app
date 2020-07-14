import { AuditResults } from './audit';
import { Advisories, Statistics } from './types';

// eslint-disable-next-line @typescript-eslint/no-empty-interface
export interface Options {
  //
}

// eslint-disable-next-line @typescript-eslint/no-empty-interface
export interface AuditReport {
  statistics: Statistics;
  advisories: Advisories;
  // "advisory|path" that are in the results, and are vulnerable
  vulnerable: string[];
  // "advisory|path" that are in the results, but ignored
  ignored: string[];
  // "advisory|path" that are marked as ignored, but not in the results
  missing: string[];
}

export const generateReport = (
  options: Options,
  results: AuditResults
): AuditReport => {
  const report: AuditReport = {
    statistics: results.statistics,
    advisories: results.advisories,
    vulnerable: Object.entries(results.advisories).flatMap(([, advisory]) =>
      advisory.findings.flatMap(finding => finding.paths)
    ),
    ignored: [],
    missing: []
  };

  return report;
};
