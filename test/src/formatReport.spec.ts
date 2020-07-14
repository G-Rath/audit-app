import stripAnsi from 'strip-ansi';
import { formatReport as formatReportFn } from '../../src/formatReport';
import { AuditReport } from '../../src/generateReport';
import { Advisory } from '../../src/types';

const emptyReport: AuditReport = {
  statistics: {},
  advisories: {},
  vulnerable: [],
  ignored: [],
  missing: []
};

const buildAdvisory = (advisory: Partial<Advisory>): Advisory => ({
  findings: [
    {
      version: '10.1.0',
      paths: ['@commitlint/cli>meow>yargs-parser']
    },
    {
      version: '9.0.2',
      paths: [
        'semantic-release>@semantic-release/npm>npm>libnpx>yargs>yargs-parser'
      ]
    }
  ],
  id: 1500,
  created: '2020-03-26T19:21:50.174Z',
  updated: '2020-05-01T01:05:15.020Z',
  deleted: null,
  title: 'Prototype Pollution',
  found_by: { link: '', name: 'Snyk Security Team', email: '' },
  reported_by: { link: '', name: 'Snyk Security Team', email: '' },
  module_name: 'yargs-parser',
  cves: [],
  vulnerable_versions: '',
  patched_versions: '',
  overview: '',
  recommendation: '',
  references: '',
  access: 'public',
  severity: 'low',
  cwe: 'CWE-471',
  metadata: { module_type: '', exploitability: 1, affected_components: '' },
  url: 'https://npmjs.com/advisories/1500',
  ...advisory
});

const formatReport = (report: Partial<AuditReport>): string =>
  stripAnsi(formatReportFn({ ...emptyReport, ...report })).trim();

const formatReportAndGetTables = (report: Partial<AuditReport>): string =>
  formatReport(report).split('\n').slice(0, -2).join('\n').trim();

const formatReportAndGetSummary = (report: Partial<AuditReport>): string =>
  formatReport(report).split('\n').slice(-2).join('\n').trim();

describe('formatReport', () => {
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

        expect(`\n${tables}\n`).toMatchInlineSnapshot(`
          "
          ┌────────────┬────────────────────────────────────────────────────────────────────┐
          │ high       │ My Second Advisory (#1234)                                         │
          ├────────────┼────────────────────────────────────────────────────────────────────┤
          │ Package    │ yargs-parser                                                       │
          ├────────────┼────────────────────────────────────────────────────────────────────┤
          │ Patched in │                                                                    │
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
    });

    describe('the summary', () => {
      it('reports how many vulnerabilities were found', () => {
        const summary = formatReportAndGetSummary({
          vulnerable: ['one', 'two', 'three']
        });

        expect(summary).toMatch(/found 3 vulnerabilities/iu);
      });

      it('includes how many vulnerabilities were ignored', () => {
        const summary = formatReportAndGetSummary({
          vulnerable: ['one', 'two', 'three'],
          ignored: ['four', 'five']
        });

        expect(summary).toMatch(/\(including 2 ignored\)/iu);
      });

      it('gives a breakdown of the severities', () => {
        const summary = formatReportAndGetSummary({
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
          vulnerable: ['one', 'two', 'three']
        });

        expect(summary).toMatch('2 low');
        expect(summary).toMatch('1 high');
      });

      describe('when there are no vulnerabilities', () => {
        it('does not show a second line', () => {
          const summary = formatReportAndGetSummary({ vulnerable: [] });

          expect(summary).not.toContain('\n');
        });
      });
    });
  });

  describe('when there are no advisories', () => {
    it('just prints the summary', () => {
      expect(formatReport({})).toMatchInlineSnapshot(
        `"found 0 vulnerabilities (including 0 ignored) across \\"some\\" packages"`
      );
    });
  });
});
