import { promises as fs } from 'fs';
import path from 'path';
import { processNpm7AuditOutput } from '../../src/processNpm7AuditOutput';
import { Npm7AuditOutput } from '../../src/types';
import fixtures from '../fixtures';

type ParsedNpm7Fixture = Npm7AuditOutput;

const pullIntoMemoryFS = async (filename: string) => {
  const actualFS = jest.requireActual<typeof import('fs')>('fs').promises;

  await fs.writeFile(filename, await actualFS.readFile(filename));
};

const loadNpmAuditFixture = async <TFixture extends keyof typeof fixtures>(
  name: TFixture
): Promise<[fixture: typeof fixtures[TFixture], path: string]> => {
  const fixturePath = path.join(__dirname, '..', 'fixtures', name);

  await fs.mkdir(fixturePath, { recursive: true });
  await pullIntoMemoryFS(path.join(fixturePath, 'package.json'));
  await pullIntoMemoryFS(path.join(fixturePath, 'package-lock.json'));

  return [fixtures[name], fixturePath];
};

describe('processNpm7AuditResults', () => {
  it('handles a single advisory affecting a child dependency', async () => {
    const [fixture, pathToFixture] = await loadNpmAuditFixture('mkdirp');

    const auditOutput = JSON.parse(fixture['npm@7']) as ParsedNpm7Fixture;
    const results = await processNpm7AuditOutput(auditOutput, pathToFixture);

    expect(results.findings).toMatchInlineSnapshot(`
      Object {
        "1066649": Object {
          "id": 1066649,
          "name": "minimist",
          "paths": Array [
            "mkdirp>minimist",
          ],
          "range": "<0.2.1",
          "severity": "moderate",
          "title": "Prototype Pollution in minimist",
          "url": "https://github.com/advisories/GHSA-vh95-rmgr-6w4m",
          "versions": Array [
            "0.0.8",
          ],
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

  it('handles a single advisory affecting a top-level and de-duplicated nested dependency', async () => {
    const [fixture, pathToFixture] = await loadNpmAuditFixture(
      'mkdirp_minimist'
    );
    const auditOutput = JSON.parse(fixture['npm@7']) as ParsedNpm7Fixture;
    const results = await processNpm7AuditOutput(auditOutput, pathToFixture);

    expect(results.findings).toMatchInlineSnapshot(`
      Object {
        "1066649": Object {
          "id": 1066649,
          "name": "minimist",
          "paths": Array [
            "mkdirp>minimist",
            "minimist",
          ],
          "range": "<0.2.1",
          "severity": "moderate",
          "title": "Prototype Pollution in minimist",
          "url": "https://github.com/advisories/GHSA-vh95-rmgr-6w4m",
          "versions": Array [
            "0.0.8",
            "0.0.8",
          ],
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
    it('includes them as separate findings', async () => {
      const [fixture, pathToFixture] = await loadNpmAuditFixture(
        'serialize-to-js'
      );
      const auditOutput = JSON.parse(fixture['npm@7']) as ParsedNpm7Fixture;
      const results = await processNpm7AuditOutput(auditOutput, pathToFixture);

      expect(results.findings).toMatchInlineSnapshot(`
        Object {
          "1066118": Object {
            "id": 1066118,
            "name": "serialize-to-js",
            "paths": Array [
              "serialize-to-js",
            ],
            "range": "<2.0.0",
            "severity": "high",
            "title": "Denial of Service in serialize-to-js",
            "url": "https://github.com/advisories/GHSA-w5q7-3pr9-x44w",
            "versions": Array [
              "1.0.0",
            ],
          },
          "1066700": Object {
            "id": 1066700,
            "name": "serialize-to-js",
            "paths": Array [
              "serialize-to-js",
            ],
            "range": "<3.0.1",
            "severity": "moderate",
            "title": "Cross-Site Scripting in serialize-to-js",
            "url": "https://github.com/advisories/GHSA-3fjq-93xj-3f3f",
            "versions": Array [
              "1.0.0",
            ],
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
