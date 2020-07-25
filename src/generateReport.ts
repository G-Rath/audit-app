import { AuditResults } from './audit';
import { Advisories, Statistics } from './types';

export interface AuditReport {
  statistics: Statistics;
  advisories: Advisories;
  // "advisory|path" that are in the results, and are vulnerable
  vulnerable: readonly string[];
  // "advisory|path" that are in the results, but ignored
  ignored: readonly string[];
  // "advisory|path" that are marked as ignored, but not in the results
  missing: readonly string[];
}

export const generateReport = (
  ignores: readonly string[],
  results: AuditResults
): AuditReport => {
  const [
    vulnerable, //
    ignored,
    missing
  ] = Object.entries(results.advisories)
    .flatMap(([, advisory]) =>
      advisory.findings.flatMap(finding =>
        finding.paths.map(path => `${advisory.id}|${path}`)
      )
    )
    .reduce<[string[], string[], string[]]>(
      (sorts, path) => {
        const ignoreIndex = sorts[2].indexOf(path);

        if (ignoreIndex === -1) {
          sorts[0].push(path);

          return sorts;
        }

        sorts[1].push(path);
        sorts[2].splice(ignoreIndex, 1);

        return sorts;
      },
      [[], [], [...ignores]]
    );

  return { ...results, vulnerable, ignored, missing };
};
