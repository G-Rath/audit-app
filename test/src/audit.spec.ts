import { ChildProcess, spawn } from 'child_process';
import { PassThrough, Writable } from 'stream';
import { mocked } from 'ts-jest/utils';
import { audit } from '../../src/audit';
import {
  Npm6AuditOutput,
  Npm7AuditOutput,
  PnpmAuditOutput
} from '../../src/types';
import fixtures from '../fixtures';

type WithOptionalVulnerabilitiesInMetadata<
  T extends { metadata: { vulnerabilities: unknown } }
> = Omit<T, 'metadata'> & {
  metadata: Omit<T['metadata'], 'vulnerabilities'> &
    Partial<Pick<T['metadata'], 'vulnerabilities'>>;
};

type ParsedNpm6Fixture = WithOptionalVulnerabilitiesInMetadata<Npm6AuditOutput>;
type ParsedNpm7Fixture = WithOptionalVulnerabilitiesInMetadata<Npm7AuditOutput>;
type ParsedPnpmFixture = WithOptionalVulnerabilitiesInMetadata<PnpmAuditOutput>;

jest.mock('child_process');

const spawnMock = mocked(spawn);

const mockSpawnProperties = (): { stdout: Writable; stderr: Writable } => {
  const out = {
    stdout: new PassThrough(),
    stderr: new PassThrough()
  };

  spawnMock.mockReturnValue(
    new Proxy<ChildProcess>({} as ChildProcess, {
      get(_, property: keyof typeof out): unknown {
        if (property in out) {
          return out[property];
        }

        throw new Error(`"${property.toString()} is stubbed`);
      }
    })
  );

  return out;
};

/*
  todo - tests to write:

    * test that errors are rejected (tryOrCall)
      - mock spawn to get control of stdout
        yarn:
          - feed stdout a line that is invalid json
          -> it should error and reject
        npm:
          - feed some lines of invalid json
          - call 'close' on the stream to trigger JSON.parse
          -> it should error and reject
 */

describe('audit', () => {
  describe('when auditing with npm', () => {
    it('calls audit --json in the given directory', async () => {
      mockSpawnProperties().stdout.end(JSON.stringify({ advisories: {} }));

      const doAudit = audit('my-dir', 'npm');

      await doAudit;

      expect(spawnMock).toHaveBeenCalledWith(
        'npm',
        ['audit', '--json', '--prefix', '.'],
        { cwd: 'my-dir' }
      );
    });

    it('returns the parsed audit results', async () => {
      const fixture = fixtures.mkdirp;
      const { stdout } = mockSpawnProperties();

      const auditRun = audit('my-dir', 'npm');

      fixture['npm@6'].split('\n').forEach(line => stdout.write(`${line}\n`));
      stdout.end();

      const results = await auditRun;

      const auditOutput = JSON.parse(fixture['npm@6']) as ParsedNpm6Fixture;

      delete auditOutput.metadata.vulnerabilities;

      expect(results.findings).toMatchInlineSnapshot(`
        Object {
          "1179": Object {
            "id": 1179,
            "name": "minimist",
            "paths": Array [
              "mkdirp>minimist",
            ],
            "range": "<0.2.1 || >=1.0.0 <1.2.3",
            "severity": "low",
            "title": "Prototype Pollution",
            "url": "https://npmjs.com/advisories/1179",
          },
        }
      `);
      expect(results.dependencyStatistics).toStrictEqual(auditOutput.metadata);
    });

    it('parses line-by-line', async () => {
      const fixture = fixtures.mkdirp_minimist;
      const { stdout } = mockSpawnProperties();

      const auditRun = audit('my-dir', 'npm');

      fixture['npm@6'].split('').forEach(char => stdout.write(char));
      stdout.end();

      const results = await auditRun;

      const auditOutput = JSON.parse(fixture['npm@6']) as ParsedNpm6Fixture;

      delete auditOutput.metadata.vulnerabilities;

      expect(results.findings).toMatchInlineSnapshot(`
        Object {
          "1179": Object {
            "id": 1179,
            "name": "minimist",
            "paths": Array [
              "mkdirp>minimist",
              "minimist",
            ],
            "range": "<0.2.1 || >=1.0.0 <1.2.3",
            "severity": "low",
            "title": "Prototype Pollution",
            "url": "https://npmjs.com/advisories/1179",
          },
        }
      `);
      expect(results.dependencyStatistics).toStrictEqual(auditOutput.metadata);
    });

    describe('when the json is not parsable', () => {
      it('rejects', async () => {
        const fixture = fixtures.mkdirp_minimist;
        const { stdout } = mockSpawnProperties();

        const auditRun = audit('my-dir', 'npm');

        fixture['npm@6']
          .substr(5)
          .split('')
          .forEach(char => stdout.write(char));
        stdout.end();

        await expect(auditRun).rejects.toThrow(Error);
      });
    });

    describe('when there are multiple vulnerabilities against the same package', () => {
      it('includes them as separate findings', async () => {
        const fixture = fixtures['serialize-to-js'];
        const { stdout } = mockSpawnProperties();

        const auditRun = audit('my-dir', 'npm');

        fixture['npm@6'].split('\n').forEach(line => stdout.write(`${line}\n`));
        stdout.end();

        const results = await auditRun;

        const auditOutput = JSON.parse(fixture['npm@6']) as ParsedNpm7Fixture;

        delete auditOutput.metadata.vulnerabilities;

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
            },
          }
        `);
        expect(results.dependencyStatistics).toStrictEqual(
          auditOutput.metadata
        );
      });
    });

    describe('when an error occurs', () => {
      it('rejects with the error as the message', async () => {
        const { stdout } = mockSpawnProperties();

        const auditRun = audit('my-dir', 'npm');

        stdout.end(
          JSON.stringify({
            error: {
              code: 'EAUDITNOLOCK',
              summary:
                'Neither npm-shrinkwrap.json nor package-lock.json found: Cannot audit a project without a lockfile',
              detail: 'Try creating one first with: npm i --package-lock-only'
            }
          })
        );

        await expect(auditRun).rejects.toThrow(
          'EAUDITNOLOCK: Neither npm-shrinkwrap.json nor package-lock.json found'
        );
      });
    });
  });

  describe('when auditing with npm@7', () => {
    it('calls audit --json in the given directory', async () => {
      mockSpawnProperties().stdout.end(JSON.stringify({ advisories: {} }));

      const doAudit = audit('my-dir', 'npm');

      await doAudit;

      expect(spawnMock).toHaveBeenCalledWith(
        'npm',
        ['audit', '--json', '--prefix', '.'],
        { cwd: 'my-dir' }
      );
    });

    it('returns the parsed audit results', async () => {
      const fixture = fixtures.mkdirp;
      const { stdout } = mockSpawnProperties();

      const auditRun = audit('my-dir', 'npm');

      fixture['npm@7'].split('\n').forEach(line => stdout.write(`${line}\n`));
      stdout.end();

      const results = await auditRun;

      const auditOutput = JSON.parse(fixture['npm@7']) as ParsedNpm7Fixture;

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

    it('parses line-by-line', async () => {
      const fixture = fixtures.mkdirp_minimist;
      const { stdout } = mockSpawnProperties();

      const auditRun = audit('my-dir', 'npm');

      fixture['npm@7'].split('').forEach(char => stdout.write(char));
      stdout.end();

      const results = await auditRun;

      const auditOutput = JSON.parse(fixture['npm@7']) as ParsedNpm7Fixture;

      delete auditOutput.metadata.vulnerabilities;

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
        const fixture = fixtures['serialize-to-js'];
        const { stdout } = mockSpawnProperties();

        const auditRun = audit('my-dir', 'npm');

        fixture['npm@7'].split('\n').forEach(line => stdout.write(`${line}\n`));
        stdout.end();

        const results = await auditRun;

        const auditOutput = JSON.parse(fixture['npm@7']) as ParsedNpm7Fixture;

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

    describe('when the json is not parsable', () => {
      it('rejects', async () => {
        const fixture = fixtures.mkdirp_minimist;
        const { stdout } = mockSpawnProperties();

        const auditRun = audit('my-dir', 'npm');

        fixture['npm@7']
          .substr(5)
          .split('')
          .forEach(char => stdout.write(char));
        stdout.end();

        await expect(auditRun).rejects.toThrow(Error);
      });
    });

    // todo
    // eslint-disable-next-line jest/no-commented-out-tests
    //     describe('when an error occurs', () => {
    // eslint-disable-next-line jest/no-commented-out-tests
    //       it('rejects with the error as the message', async () => {
    //         const { stderr } = mockSpawnProperties();
    //
    //         const auditRun = audit('my-dir', 'npm');
    //
    //         stderr.end(
    //           `npm ERR! code ENOLOCK
    // npm ERR! audit This command requires an existing lockfile.
    // npm ERR! audit Try creating one first with: npm i --package-lock-only
    // npm ERR! audit Original error: loadVirtual requires existing shrinkwrap file
    // {
    //   "error": {
    //     "code": "ENOLOCK",
    //     "summary": "This command requires an existing lockfile.",
    //     "detail": "Try creating one first with: npm i --package-lock-only\\nOriginal error: loadVirtual requires existing shrinkwrap file"
    //   }
    // }
    //
    // npm ERR! A complete log of this run can be found in:
    // npm ERR!     /home/user/.npm/_logs/2021-02-03T01_12_36_093Z-debug.log
    // `
    //         );
    //
    //         await expect(auditRun).rejects.toThrow(
    //           'EAUDITNOLOCK: Neither npm-shrinkwrap.json nor package-lock.json found'
    //         );
    //       });
    //     });
  });

  describe('when auditing with pnpm', () => {
    it('calls audit --json in the given directory', async () => {
      mockSpawnProperties().stdout.end(JSON.stringify({ advisories: {} }));

      await audit('my-dir', 'pnpm');

      expect(spawnMock).toHaveBeenCalledWith(
        'pnpm',
        ['audit', '--json', '--prefix', '.'],
        { cwd: 'my-dir' }
      );
    });

    it('returns the parsed audit results', async () => {
      const fixture = fixtures.mkdirp;
      const { stdout } = mockSpawnProperties();

      const auditRun = audit('my-dir', 'pnpm');

      fixture.pnpm.split('\n').forEach(line => stdout.write(`${line}\n`));
      stdout.end();

      const results = await auditRun;

      const auditOutput = JSON.parse(fixture.pnpm) as ParsedPnpmFixture;

      delete auditOutput.metadata.vulnerabilities;

      expect(results.findings).toMatchInlineSnapshot(`
        Object {
          "1179": Object {
            "id": 1179,
            "name": "minimist",
            "paths": Array [
              ".>mkdirp>minimist",
            ],
            "range": "<0.2.1 || >=1.0.0 <1.2.3",
            "severity": "low",
            "title": "Prototype Pollution",
            "url": "https://npmjs.com/advisories/1179",
          },
        }
      `);
      expect(results.dependencyStatistics).toStrictEqual(auditOutput.metadata);
    });

    it('parses line-by-line', async () => {
      const fixture = fixtures.mkdirp_minimist;
      const { stdout } = mockSpawnProperties();

      const auditRun = audit('my-dir', 'npm');

      fixture.pnpm.split('').forEach(char => stdout.write(char));
      stdout.end();

      const results = await auditRun;

      const auditOutput = JSON.parse(fixture.pnpm) as ParsedPnpmFixture;

      delete auditOutput.metadata.vulnerabilities;

      expect(results.findings).toMatchInlineSnapshot(`
        Object {
          "1179": Object {
            "id": 1179,
            "name": "minimist",
            "paths": Array [
              ".>minimist",
            ],
            "range": "<0.2.1 || >=1.0.0 <1.2.3",
            "severity": "low",
            "title": "Prototype Pollution",
            "url": "https://npmjs.com/advisories/1179",
          },
        }
      `);
      expect(results.dependencyStatistics).toStrictEqual(auditOutput.metadata);
    });

    describe('when there are multiple vulnerabilities against the same package', () => {
      it('includes them as separate findings', async () => {
        const fixture = fixtures['serialize-to-js'];
        const { stdout } = mockSpawnProperties();

        const auditRun = audit('my-dir', 'pnpm');

        fixture.pnpm.split('\n').forEach(line => stdout.write(`${line}\n`));
        stdout.end();

        const results = await auditRun;

        const auditOutput = JSON.parse(fixture.pnpm) as ParsedPnpmFixture;

        delete auditOutput.metadata.vulnerabilities;

        expect(results.findings).toMatchInlineSnapshot(`
          Object {
            "1429": Object {
              "id": 1429,
              "name": "serialize-to-js",
              "paths": Array [
                ".>serialize-to-js",
              ],
              "range": "<3.0.1",
              "severity": "moderate",
              "title": "Cross-Site Scripting",
              "url": "https://npmjs.com/advisories/1429",
            },
            "790": Object {
              "id": 790,
              "name": "serialize-to-js",
              "paths": Array [
                ".>serialize-to-js",
              ],
              "range": "<2.0.0",
              "severity": "high",
              "title": "Denial of Service",
              "url": "https://npmjs.com/advisories/790",
            },
          }
        `);
        expect(results.dependencyStatistics).toStrictEqual(
          auditOutput.metadata
        );
      });
    });

    describe('when the json is not parsable', () => {
      it('rejects', async () => {
        const fixture = fixtures.mkdirp_minimist;
        const { stdout } = mockSpawnProperties();

        const auditRun = audit('my-dir', 'pnpm');

        fixture.pnpm
          .substr(5)
          .split('')
          .forEach(char => stdout.write(char));
        stdout.end();

        await expect(auditRun).rejects.toThrow(Error);
      });
    });

    describe('when an error occurs', () => {
      it('rejects with the error as the message', async () => {
        const { stdout } = mockSpawnProperties();

        const auditRun = audit('my-dir', 'npm');

        stdout.end(
          ' ERROR  No pnpm-lock.yaml found: Cannot audit a project without a lockfile'
        );

        await expect(auditRun).rejects.toThrow(
          ' ERROR  No pnpm-lock.yaml found'
        );
      });
    });
  });

  describe('when auditing with yarn', () => {
    it('calls audit --json in the given directory', async () => {
      mockSpawnProperties().stdout.end(JSON.stringify({ advisories: {} }));

      await audit('my-dir', 'yarn');

      expect(spawnMock).toHaveBeenCalledWith(
        'yarn',
        ['audit', '--json', '--cwd', '.'],
        { cwd: 'my-dir' }
      );
    });

    it('returns the parsed audit results', async () => {
      const fixture = fixtures.mkdirp;
      const { stdout } = mockSpawnProperties();

      const auditRun = audit('my-dir', 'yarn');

      fixture.yarn.split('\n').forEach(line => stdout.write(`${line}\n`));
      stdout.end();

      const results = await auditRun;

      expect(results.findings).toMatchInlineSnapshot(`
        Object {
          "1179": Object {
            "id": 1179,
            "name": "minimist",
            "paths": Array [
              "mkdirp>minimist",
            ],
            "range": "<0.2.1 || >=1.0.0 <1.2.3",
            "severity": "low",
            "title": "Prototype Pollution",
            "url": "https://npmjs.com/advisories/1179",
          },
        }
      `);
      expect(results.dependencyStatistics).toMatchInlineSnapshot(`
        Object {
          "dependencies": 2,
          "devDependencies": 0,
          "optionalDependencies": 0,
          "totalDependencies": 2,
        }
      `);
    });

    describe('when there are multiple results for the same advisory', () => {
      it('merges them', async () => {
        const fixture = fixtures.mkdirp_minimist;
        const { stdout } = mockSpawnProperties();

        const auditRun = audit('my-dir', 'yarn');

        fixture.yarn.split('\n').forEach(line => stdout.write(`${line}\n`));
        stdout.end();

        const results = await auditRun;

        expect(results.findings).toMatchInlineSnapshot(`
          Object {
            "1179": Object {
              "id": 1179,
              "name": "minimist",
              "paths": Array [
                "mkdirp>minimist",
                "minimist",
              ],
              "range": "<0.2.1 || >=1.0.0 <1.2.3",
              "severity": "low",
              "title": "Prototype Pollution",
              "url": "https://npmjs.com/advisories/1179",
            },
          }
        `);
        expect(results.dependencyStatistics).toMatchInlineSnapshot(`
          Object {
            "dependencies": 3,
            "devDependencies": 0,
            "optionalDependencies": 0,
            "totalDependencies": 3,
          }
        `);
      });
    });

    describe('when there are multiple vulnerabilities against the same package', () => {
      it('includes them as separate findings', async () => {
        const fixture = fixtures['serialize-to-js'];
        const { stdout } = mockSpawnProperties();

        const auditRun = audit('my-dir', 'yarn');

        fixture.yarn.split('\n').forEach(line => stdout.write(`${line}\n`));
        stdout.end();

        const results = await auditRun;

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
            },
          }
        `);
        expect(results.dependencyStatistics).toMatchInlineSnapshot(`
          Object {
            "dependencies": 17,
            "devDependencies": 0,
            "optionalDependencies": 0,
            "totalDependencies": 17,
          }
        `);
      });
    });

    describe('when the output is missing "auditSummary"', () => {
      it('is fine', async () => {
        const fixture = fixtures.mkdirp_minimist;
        const { stdout } = mockSpawnProperties();

        const auditRun = audit('my-dir', 'yarn');

        fixture.yarn
          .trim()
          .split('\n')
          .slice(0, -1)
          .forEach(line => stdout.write(`${line}\n`));
        stdout.end();

        const results = await auditRun;

        expect(results.dependencyStatistics).toMatchInlineSnapshot(`Object {}`);
      });
    });

    describe('when the json is not parsable', () => {
      it('rejects', async () => {
        const fixture = fixtures.mkdirp_minimist;
        const { stdout } = mockSpawnProperties();

        const auditRun = audit('my-dir', 'yarn');

        fixture.yarn
          .substr(5)
          .split('')
          .forEach(char => stdout.write(char));
        stdout.end();

        await expect(auditRun).rejects.toThrow(Error);
      });
    });
  });
});
