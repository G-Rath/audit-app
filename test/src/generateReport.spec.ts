import { AuditResults } from '../../src/audit';
import { AuditReport, generateReport } from '../../src/generateReport';
import { buildAdvisory } from '../buildAdvisory';

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
