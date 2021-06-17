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

    expect(results.findings).toStrictEqual({
      1179: {
        id: 1179,
        name: 'minimist',
        paths: ['mkdirp>minimist'],
        versions: ['0.0.8'],
        range: '<0.2.1 || >=1.0.0 <1.2.3',
        severity: 'low',
        title: 'Prototype Pollution',
        url: 'https://npmjs.com/advisories/1179'
      }
    });
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

    expect(results.findings).toStrictEqual({
      1179: {
        id: 1179,
        name: 'minimist',
        paths: ['mkdirp>minimist', 'minimist'],
        versions: ['0.0.8', '0.0.8'],
        range: '<0.2.1 || >=1.0.0 <1.2.3',
        severity: 'low',
        title: 'Prototype Pollution',
        url: 'https://npmjs.com/advisories/1179'
      }
    });
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

      expect(results.findings).toStrictEqual({
        1429: {
          id: 1429,
          name: 'serialize-to-js',
          paths: ['serialize-to-js'],
          versions: ['1.0.0'],
          range: '<3.0.1',
          severity: 'moderate',
          title: 'Cross-Site Scripting',
          url: 'https://npmjs.com/advisories/1429'
        },
        790: {
          id: 790,
          name: 'serialize-to-js',
          paths: ['serialize-to-js'],
          versions: ['1.0.0'],
          range: '<2.0.0',
          severity: 'high',
          title: 'Denial of Service',
          url: 'https://npmjs.com/advisories/790'
        }
      });

      expect(results.dependencyStatistics).toStrictEqual({
        dependencies: auditOutput.metadata.dependencies.prod,
        devDependencies: auditOutput.metadata.dependencies.dev,
        optionalDependencies: auditOutput.metadata.dependencies.optional,
        totalDependencies: auditOutput.metadata.dependencies.total
      });
    });
  });
});
