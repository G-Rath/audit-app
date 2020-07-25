import { AuditResults } from '../../src/audit';
import { AuditReport, generateReport } from '../../src/generateReport';
import { Advisory } from '../../src/types';

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

describe('generateReport', () => {
  const results: AuditResults = {
    statistics: {},
    advisories: {
      '1234': buildAdvisory({
        findings: [{ version: '10.1.0', paths: ['one', 'two'] }],
        id: 1234,
        severity: 'high'
      }),
      '1500': buildAdvisory({
        findings: [
          { version: '10.1.0', paths: ['three'] },
          { version: '10.1.0', paths: ['four', 'five'] }
        ],
        id: 1500,
        severity: 'low'
      })
    }
  };

  it('collects the paths from the findings of each advisory', () => {
    const report = generateReport([], results);

    expect(report).toStrictEqual<AuditReport>({
      ...results,
      vulnerable: [
        '1234|one',
        '1234|two',
        '1500|three',
        '1500|four',
        '1500|five'
      ],
      ignored: [],
      missing: []
    });
  });

  describe('when there are paths to ignore', () => {
    it('includes them as ignored', () => {
      const report = generateReport(['1234|one', '1500|five'], results);

      expect(report).toStrictEqual<AuditReport>({
        ...results,
        vulnerable: ['1234|two', '1500|three', '1500|four'],
        ignored: ['1234|one', '1500|five'],
        missing: []
      });
    });

    describe('when a path to ignore is not found to be vulnerable', () => {
      it('includes them as missing', () => {
        const report = generateReport(
          ['1234|one', '1500|five', '1500|six'],
          results
        );

        expect(report).toStrictEqual<AuditReport>({
          ...results,
          vulnerable: ['1234|two', '1500|three', '1500|four'],
          ignored: ['1234|one', '1500|five'],
          missing: ['1500|six']
        });
      });
    });
  });

  describe('when there are no advisories', () => {
    it('generates an empty report', () => {
      const report = generateReport([], { statistics: {}, advisories: {} });

      expect(report).toStrictEqual<AuditReport>({
        statistics: {},
        advisories: {},
        vulnerable: [],
        ignored: [],
        missing: []
      });
    });
  });
});
