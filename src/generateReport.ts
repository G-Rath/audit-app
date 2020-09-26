import { AuditResults } from './audit';
import { Advisories, SeverityCountsWithTotal, Statistics } from './types';

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

  Object.values(results.advisories).forEach(({ id, findings, severity }) => {
    const { vulnerable, ignored } = findings.reduce(
      (sums, { paths }) => {
        const { length: count } = paths.filter(path =>
          ignores.includes(`${id}|${path}`)
        );

        sums.vulnerable += paths.length - count;
        sums.ignored += count;

        return sums;
      },
      { vulnerable: 0, ignored: 0 }
    );

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
  ] = Object.entries(results.advisories)
    .reduce<string[]>(
      (paths, [, advisory]) =>
        paths.concat(
          advisory.findings.reduce<string[]>(
            (acc, finding) =>
              acc.concat(finding.paths.map(path => `${advisory.id}|${path}`)),
            []
          )
        ),
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
    advisories: results.advisories,
    statistics: generateStatistics(ignores, results),
    vulnerable,
    ignored,
    missing
  };
};
