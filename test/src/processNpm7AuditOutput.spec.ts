import { processNpm7AuditOutput } from '../../src/processNpm7AuditOutput';
import { Npm7AuditOutput } from '../../src/types';
import fixtures from '../fixtures';

type ParsedNpm7Fixture = Npm7AuditOutput;

describe('processNpm7AuditResults', () => {
  it('processes the output correctly', () => {
    const fixture = fixtures.mkdirp_minimist;
    const auditOutput = JSON.parse(fixture['npm@7']) as ParsedNpm7Fixture;
    const results = processNpm7AuditOutput(auditOutput);

    expect(results.findings).toMatchInlineSnapshot(`
        Object {
          "1179": Object {
            "id": 1179,
            "name": "minimist",
            "paths": Array [
              "minimist",
            ],
            "range": "<0.2.1 || >=1.0.0 <1.2.3",
            "severity": "low",
            "title": "Prototype Pollution",
            "url": "https://npmjs.com/advisories/1179",
            "versions": Array [],
          },
        }
      `);
    expect(results.dependencyStatistics).toStrictEqual({
      dependencies: auditOutput.metadata.dependencies.prod,
      devDependencies: auditOutput.metadata.dependencies.dev,
      optionalDependencies: auditOutput.metadata.dependencies.optional,
      totalDependencies: auditOutput.metadata.dependencies.total
    });
  });

  describe('when there are multiple vulnerabilities against the same package', () => {
    it('includes them as separate findings', () => {
      const fixture = fixtures['serialize-to-js'];
      const auditOutput = JSON.parse(fixture['npm@7']) as ParsedNpm7Fixture;
      const results = processNpm7AuditOutput(auditOutput);

      expect(results.findings).toMatchInlineSnapshot(`
          Object {
            "1429": Object {
              "id": 1429,
              "name": "serialize-to-js",
              "paths": Array [
                "serialize-to-js",
              ],
              "range": "<3.0.1",
              "severity": "moderate",
              "title": "Cross-Site Scripting",
              "url": "https://npmjs.com/advisories/1429",
              "versions": Array [],
            },
            "790": Object {
              "id": 790,
              "name": "serialize-to-js",
              "paths": Array [
                "serialize-to-js",
              ],
              "range": "<2.0.0",
              "severity": "high",
              "title": "Denial of Service",
              "url": "https://npmjs.com/advisories/790",
              "versions": Array [],
            },
          }
        `);
      expect(results.dependencyStatistics).toStrictEqual({
        dependencies: auditOutput.metadata.dependencies.prod,
        devDependencies: auditOutput.metadata.dependencies.dev,
        optionalDependencies: auditOutput.metadata.dependencies.optional,
        totalDependencies: auditOutput.metadata.dependencies.total
      });
    });
  });
});
