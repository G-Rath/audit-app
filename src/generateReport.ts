import { AuditResults } from './audit';
import { Finding, SeverityCountsWithTotal, Statistics } from './types';

export interface AuditReport {
  statistics: Statistics;
  findings: Record<string, Finding>;
  // "advisory|path" that are in the results, and are vulnerable
  vulnerable: readonly string[];
  // "advisory|path" that are in the results, but ignored
  ignored: readonly string[];
  // "advisory|path" that are marked as ignored, but not in the results
  missing: readonly string[];
}

const severityCountsWithTotal: SeverityCountsWithTotal = {
  total: 0,
  info: 0,
  low: 0,
  moderate: 0,
  high: 0,
  critical: 0
};

const generateStatistics = (
  ignores: readonly string[],
  results: AuditResults
): Statistics => {
  const statistics: Statistics = {
    dependencies: results.dependencyStatistics,
    severities: { ...severityCountsWithTotal },
    vulnerable: { ...severityCountsWithTotal },
    ignored: { ...severityCountsWithTotal }
  };

  Object.values(results.findings).forEach(({ id, paths, severity }) => {
    const { length: count } = paths.filter(path =>
      ignores.includes(`${id}|${path}`)
    );

    const vulnerable = paths.length - count;
    const ignored = count;

    statistics.severities[severity] += ignored + vulnerable;
    statistics.severities.total += ignored + vulnerable;

    statistics.vulnerable[severity] += vulnerable;
    statistics.vulnerable.total += vulnerable;

    statistics.ignored[severity] += ignored;
    statistics.ignored.total += ignored;
  });

  return statistics;
};

export const generateReport = (
  ignores: readonly string[],
  results: AuditResults
): AuditReport => {
  const [
    vulnerable, //
    ignored,
    missing
  ] = Object.values(results.findings)
    .reduce<string[]>(
      (allPaths, { id, paths }) =>
        allPaths.concat(paths.map(path => `${id}|${path}`)),
      []
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

  return {
    findings: results.findings,
    statistics: generateStatistics(ignores, results),
    vulnerable,
    ignored,
    missing
  };
};
