import { AuditResults } from '../../src/audit';
import { AuditReport, generateReport } from '../../src/generateReport';
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

describe('generateReport', () => {
  const AnyStatistics = expect.any(Object) as AuditReport['statistics'];

  const advisories: AuditResults['advisories'] = {
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
  };

  const results: AuditResults = {
    dependencyStatistics: {},
    advisories
  };

  it('collects the paths from the findings of each advisory', () => {
    const report = generateReport([], results);

    expect(report).toStrictEqual<AuditReport>({
      statistics: AnyStatistics,
      advisories,
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

  describe('when there are no paths to ignore', () => {
    it('counts them as severities', () => {
      const { statistics } = generateReport([], results);

      expect(statistics.severities).toStrictEqual<SeverityCountsWithTotal>({
        total: 5,
        info: 0,
        low: 3,
        moderate: 0,
        high: 2,
        critical: 0
      });
    });

    it('counts them all as vulnerable', () => {
      const { statistics } = generateReport([], results);

      expect(statistics.vulnerable).toStrictEqual<SeverityCountsWithTotal>({
        total: 5,
        info: 0,
        low: 3,
        moderate: 0,
        high: 2,
        critical: 0
      });
    });
  });

  describe('when there are paths to ignore', () => {
    it('includes them as ignored', () => {
      const report = generateReport(['1234|one', '1500|five'], results);

      expect(report).toStrictEqual<AuditReport>({
        statistics: AnyStatistics,
        advisories,
        vulnerable: ['1234|two', '1500|three', '1500|four'],
        ignored: ['1234|one', '1500|five'],
        missing: []
      });
    });

    it('counts them as severities', () => {
      const { statistics } = generateReport(['1234|one', '1500|five'], results);

      expect(statistics.severities).toStrictEqual<SeverityCountsWithTotal>({
        total: 5,
        info: 0,
        low: 3,
        moderate: 0,
        high: 2,
        critical: 0
      });
    });

    it('counts them as ignored', () => {
      const { statistics } = generateReport(['1234|one', '1500|five'], results);

      expect(statistics.ignored).toStrictEqual<SeverityCountsWithTotal>({
        total: 2,
        info: 0,
        low: 1,
        moderate: 0,
        high: 1,
        critical: 0
      });
    });

    it('does not count them as vulnerable', () => {
      const { statistics } = generateReport(['1234|one', '1500|five'], results);

      expect(statistics.vulnerable).toStrictEqual<SeverityCountsWithTotal>({
        total: 3,
        info: 0,
        low: 2,
        moderate: 0,
        high: 1,
        critical: 0
      });
    });

    describe('when a path to ignore is not found to be vulnerable', () => {
      it('includes them as missing', () => {
        const report = generateReport(
          ['1234|one', '1500|five', '1500|six'],
          results
        );

        expect(report).toStrictEqual<AuditReport>({
          statistics: AnyStatistics,
          advisories,
          vulnerable: ['1234|two', '1500|three', '1500|four'],
          ignored: ['1234|one', '1500|five'],
          missing: ['1500|six']
        });
      });
    });
  });

  describe('when there are no advisories', () => {
    it('generates an empty report', () => {
      const report = generateReport([], {
        dependencyStatistics: {},
        advisories: {}
      });

      expect(report).toStrictEqual<AuditReport>({
        statistics: {
          dependencies: {},
          vulnerable: zeroedSeverityCountsWithTotal,
          severities: zeroedSeverityCountsWithTotal,
          ignored: zeroedSeverityCountsWithTotal
        },
        advisories: {},
        vulnerable: [],
        ignored: [],
        missing: []
      });
    });
  });
});
