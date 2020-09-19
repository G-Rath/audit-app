import stripAnsi from 'strip-ansi';
import { SupportedReportFormat, formatReport } from '../../src/formatReport';
import { AuditReport } from '../../src/generateReport';
import { SeverityCountsWithTotal } from '../../src/types';
import { buildAdvisory } from '../buildAdvisory';

const zeroedSeverityCountsWithTotal: SeverityCountsWithTotal = {
  total: 0,
  info: 0,
  low: 0,
  moderate: 0,
  high: 0,
  critical: 0
};

const emptyStatistics = {
  dependencies: {},
  vulnerable: zeroedSeverityCountsWithTotal,
  severities: zeroedSeverityCountsWithTotal,
  ignored: zeroedSeverityCountsWithTotal
};

const emptyReport: AuditReport = {
  statistics: emptyStatistics,
  advisories: {},
  vulnerable: [],
  ignored: [],
  missing: []
};

const formatReportAndStripAnsi = (
  format: SupportedReportFormat,
  report: Partial<AuditReport>
): string => stripAnsi(formatReport(format, { ...emptyReport, ...report }));

const formatReportAndGetTables = (report: Partial<AuditReport>): string => {
  const summary = formatReportAndStripAnsi('summary', report);
  const tables = formatReportAndStripAnsi('tables', report);

  return tables.substring(0, tables.indexOf(summary) - 1);
};

const prettifyTables = (tables: Array<string | string[]> | string): string =>
  `\n${
    Array.isArray(tables)
      ? tables.map(ln => (Array.isArray(ln) ? ln.join('\n') : ln)).join('\n')
      : tables
  }\n`;

describe('formatReport', () => {
  describe('when the format is "summary"', () => {
    describe('when there are advisories', () => {
      it('reports how many vulnerabilities were found', () => {
        const summary = formatReportAndStripAnsi('summary', {
          statistics: {
            ...emptyStatistics,
            severities: { ...zeroedSeverityCountsWithTotal, total: 3 }
          }
        });

        expect(summary).toMatch(/found 3 vulnerabilities/iu);
      });

      it('includes how many vulnerabilities were ignored', () => {
        const summary = formatReportAndStripAnsi('summary', {
          statistics: {
            ...emptyStatistics,
            ignored: { ...zeroedSeverityCountsWithTotal, total: 2 }
          }
        });

        expect(summary).toMatch(/\(including 2 ignored\)/iu);
      });

      it('gives a breakdown of the severities', () => {
        const summary = formatReportAndStripAnsi('summary', {
          statistics: {
            ...emptyStatistics,
            vulnerable: {
              ...zeroedSeverityCountsWithTotal,
              total: 3,
              low: 2,
              high: 1
            }
          }
        });

        expect(summary).toMatch('2 low');
        expect(summary).toMatch('1 high');
      });

      describe('when there are no vulnerabilities', () => {
        it('does not show a second line', () => {
          const summary = formatReport('summary', {
            ...emptyReport,
            vulnerable: []
          });

          expect(summary).not.toContain('\n');
        });
      });

      describe('when there is only one vulnerability', () => {
        it('uses the singular word', () => {
          const summary = formatReportAndStripAnsi('summary', {
            statistics: {
              ...emptyStatistics,
              severities: { ...zeroedSeverityCountsWithTotal, total: 1 }
            }
          });

          expect(summary).toMatch(/found 1 vulnerability/iu);
        });
      });
    });

    describe('when there are no advisories', () => {
      it('just prints the summary', () => {
        expect(formatReportAndStripAnsi('summary', {})).toMatchInlineSnapshot(
          `" found 0 vulnerabilities (including 0 ignored) across \\"some\\" packages"`
        );
      });
    });

    describe('when dependency statistics are present', () => {
      it('includes them in the summary', () => {
        expect(
          formatReportAndStripAnsi('summary', {
            statistics: {
              ...emptyStatistics,
              dependencies: { totalDependencies: 5 }
            }
          })
        ).toMatchInlineSnapshot(
          `" found 0 vulnerabilities (including 0 ignored) across 5 packages"`
        );
      });

      describe('when there is only one dependency', () => {
        it('uses the singular word', () => {
          expect(
            formatReportAndStripAnsi('summary', {
              statistics: {
                ...emptyStatistics,
                dependencies: { totalDependencies: 1 }
              }
            })
          ).toMatch(/across 1 package/iu);
        });
      });
    });
  });

  describe('when the format is "tables"', () => {
    describe('when there are advisories', () => {
      describe('the tables', () => {
        it('prints a table with information on the advisory', () => {
          const tables = formatReportAndGetTables({
            advisories: {
              '1234': buildAdvisory({
                findings: [{ version: '10.1.0', paths: ['one'] }],
                title: 'My Second Advisory',
                id: 1234,
                severity: 'high'
              })
            },
            vulnerable: ['one']
          });

          expect(prettifyTables(tables)).toMatchInlineSnapshot(`
            "
            ┌────────────┬────────────────────────────────────────────────────────────────────┐
            │ high       │ My Second Advisory (#1234)                                         │
            ├────────────┼────────────────────────────────────────────────────────────────────┤
            │ Package    │ yargs-parser v10.1.0                                               │
            ├────────────┼────────────────────────────────────────────────────────────────────┤
            │ Patched in │                                                                    │
            ├────────────┼────────────────────────────────────────────────────────────────────┤
            │ More info  │ https://npmjs.com/advisories/1500                                  │
            └────────────┴────────────────────────────────────────────────────────────────────┘
            "
          `);
        });

        it('wraps the value columns to a fixed width', () => {
          const tables = formatReportAndGetTables({
            advisories: {
              '1234': buildAdvisory({
                findings: [{ version: '10.1.0', paths: ['one'] }],
                title: `The advisory with a very l${'o'.repeat(50)}ng name`,
                patched_versions: `>=1.0.${'0'.repeat(50)} < 1.5.0`,
                id: 1234,
                severity: 'high'
              })
            },
            vulnerable: ['one']
          });

          expect(prettifyTables(tables)).toMatchInlineSnapshot(`
            "
            ┌────────────┬────────────────────────────────────────────────────────────────────┐
            │ high       │ The advisory with a very                                           │
            │            │ loooooooooooooooooooooooooooooooooooooooooooooooooong name         │
            │            │ (#1234)                                                            │
            ├────────────┼────────────────────────────────────────────────────────────────────┤
            │ Package    │ yargs-parser v10.1.0                                               │
            ├────────────┼────────────────────────────────────────────────────────────────────┤
            │ Patched in │ >=1.0.00000000000000000000000000000000000000000000000000 < 1.5.0   │
            ├────────────┼────────────────────────────────────────────────────────────────────┤
            │ More info  │ https://npmjs.com/advisories/1500                                  │
            └────────────┴────────────────────────────────────────────────────────────────────┘
            "
          `);
        });

        describe('when an advisory has multiple findings', () => {
          it('prints one table per advisory', () => {
            const tables = formatReportAndGetTables({
              advisories: {
                '1500': buildAdvisory({
                  findings: [{ version: '10.1.0', paths: ['one', 'two'] }],
                  title: 'My First Advisory',
                  id: 1500,
                  severity: 'low'
                }),
                '1234': buildAdvisory({
                  findings: [{ version: '10.1.0', paths: ['three', 'four'] }],
                  title: 'My Second Advisory',
                  id: 1234,
                  severity: 'high'
                })
              },
              vulnerable: ['one', 'two', 'three', 'four']
            });

            expect(tables.match(/My First Advisory/gu)).toHaveLength(1);
            expect(tables.match(/My Second Advisory/gu)).toHaveLength(1);
          });
        });

        it('sorts advisories by their module_name first', () => {
          const tables = formatReportAndGetTables({
            advisories: {
              '1': buildAdvisory({ module_name: 'B', id: 1 }),
              '2': buildAdvisory({ module_name: 'C', id: 2 }),
              '3': buildAdvisory({ module_name: 'A', id: 3 })
            }
          });

          expect(
            prettifyTables([
              '┌────────────┬────────────────────────────────────────────────────────────────────┐',
              tables.split('\n').filter(line => line.includes(' Package  ')),
              '└────────────┴────────────────────────────────────────────────────────────────────┘'
            ])
          ).toMatchInlineSnapshot(`
            "
            ┌────────────┬────────────────────────────────────────────────────────────────────┐
            │ Package    │ A v10.1.0, v9.0.2                                                  │
            │ Package    │ B v10.1.0, v9.0.2                                                  │
            │ Package    │ C v10.1.0, v9.0.2                                                  │
            └────────────┴────────────────────────────────────────────────────────────────────┘
            "
          `);
        });

        it('sorts advisories by their severity second', () => {
          const tables = formatReportAndGetTables({
            advisories: {
              '1': buildAdvisory({
                title: 'My Advisory',
                id: 1,
                severity: 'high',
                module_name: 'A'
              }),
              '2': buildAdvisory({
                title: 'My Advisory',
                id: 2,
                severity: 'critical',
                module_name: 'A'
              }),
              '3': buildAdvisory({
                title: 'My Advisory',
                id: 3,
                severity: 'low',
                module_name: 'A'
              })
            }
          });

          expect(
            prettifyTables([
              '┌────────────┬────────────────────────────────────────────────────────────────────┐',
              tables
                .split('\n')
                .filter(line => line.includes(' My Advisory (')),
              '└────────────┴────────────────────────────────────────────────────────────────────┘'
            ])
          ).toMatchInlineSnapshot(`
            "
            ┌────────────┬────────────────────────────────────────────────────────────────────┐
            │ critical   │ My Advisory (#2)                                                   │
            │ high       │ My Advisory (#1)                                                   │
            │ low        │ My Advisory (#3)                                                   │
            └────────────┴────────────────────────────────────────────────────────────────────┘
            "
          `);
        });
      });

      it('includes the summary', () => {
        const report: Partial<AuditReport> = {
          advisories: {
            '1500': buildAdvisory({
              findings: [{ version: '10.1.0', paths: ['one', 'two'] }],
              id: 1500,
              severity: 'low'
            }),
            '1234': buildAdvisory({
              findings: [{ version: '10.1.0', paths: ['three'] }],
              id: 1234,
              severity: 'high'
            })
          },
          vulnerable: ['one', 'two', 'three'],
          ignored: ['four', 'five']
        };
        const summary = formatReportAndStripAnsi('summary', report);
        const tables = formatReportAndStripAnsi('tables', report);

        expect(tables).toContain(summary);
      });
    });

    describe('when there are no advisories', () => {
      it('just prints the summary', () => {
        expect(formatReportAndStripAnsi('tables', {})).toMatchInlineSnapshot(
          `" found 0 vulnerabilities (including 0 ignored) across \\"some\\" packages"`
        );
      });
    });
  });

  describe('when the format is "paths"', () => {
    it('returns a list containing each vulnerable path', () => {
      const vulnerable = [
        '118|gulp>vinyl-fs>glob-watcher>gaze>globule>glob>minimatch',
        '118|gulp>vinyl-fs>glob-watcher>gaze>globule>minimatch',
        '577|gulp>vinyl-fs>glob-watcher>gaze>globule>lodash',
        '782|gulp>vinyl-fs>glob-watcher>gaze>globule>lodash',
        '1065|gulp>vinyl-fs>glob-watcher>gaze>globule>lodash',
        '1084|webpack>yargs>os-locale>mem',
        '1500|webpack>yargs>yargs-parser',
        '1500|webpack-dev-server>yargs>yargs-parser'
      ];

      expect(
        formatReport('paths', {
          ...emptyReport,
          vulnerable
        })
      ).toBe(vulnerable.join('\n'));
    });

    describe('when there are no vulnerable paths', () => {
      it('returns an empty string', () => {
        expect(
          formatReport('paths', {
            ...emptyReport,
            vulnerable: [],
            ignored: [
              '118|gulp>vinyl-fs>glob-watcher>gaze>globule>glob>minimatch',
              '118|gulp>vinyl-fs>glob-watcher>gaze>globule>minimatch',
              '577|gulp>vinyl-fs>glob-watcher>gaze>globule>lodash',
              '782|gulp>vinyl-fs>glob-watcher>gaze>globule>lodash',
              '1065|gulp>vinyl-fs>glob-watcher>gaze>globule>lodash',
              '1084|webpack>yargs>os-locale>mem',
              '1500|webpack>yargs>yargs-parser',
              '1500|webpack-dev-server>yargs>yargs-parser'
            ]
          })
        ).toBe('');
      });
    });
  });

  describe('when the format is "json"', () => {
    it('returns the stringified report', () => {
      expect(
        formatReport('json', {
          ...emptyReport,
          vulnerable: ['1|a', '1|a>b', '2|c>b'],
          ignored: ['2|a>b']
        })
      ).toMatchInlineSnapshot(
        `"{\\"statistics\\":{\\"dependencies\\":{},\\"vulnerable\\":{\\"total\\":0,\\"info\\":0,\\"low\\":0,\\"moderate\\":0,\\"high\\":0,\\"critical\\":0},\\"severities\\":{\\"total\\":0,\\"info\\":0,\\"low\\":0,\\"moderate\\":0,\\"high\\":0,\\"critical\\":0},\\"ignored\\":{\\"total\\":0,\\"info\\":0,\\"low\\":0,\\"moderate\\":0,\\"high\\":0,\\"critical\\":0}},\\"advisories\\":{},\\"vulnerable\\":[\\"1|a\\",\\"1|a>b\\",\\"2|c>b\\"],\\"ignored\\":[\\"2|a>b\\"],\\"missing\\":[]}"`
      );
    });
  });
});

// const comparePaths = (a: string, b: string): number => {
//   const [aId, aPath] = a.split('|');
//   const [bId, bPath] = b.split('|');
//
//   return parseInt(aId) - parseInt(bId) || aPath.localeCompare(bPath);
// };
