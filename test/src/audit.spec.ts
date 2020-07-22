import { ChildProcess, spawn } from 'child_process';
import { PassThrough, Writable } from 'stream';
import { mocked } from 'ts-jest/utils';
import { audit } from '../../src/audit';
import { AuditOutput } from '../../src/types';
import fixtures from '../fixtures';

jest.mock('child_process');

const spawnMock = mocked(spawn);

const mockSpawnStdoutStream = (): Writable => {
  const stdout = new PassThrough();

  spawnMock.mockReturnValue(
    new Proxy<ChildProcess>({} as ChildProcess, {
      get(_, property): unknown {
        if (property === 'stdout') {
          return stdout;
        }

        throw new Error(`"${property.toString()} is stubbed`);
      }
    })
  );

  return stdout;
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
      mockSpawnStdoutStream().end('{}');

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
      const stdout = mockSpawnStdoutStream();

      const auditRun = audit('my-dir', 'npm');

      fixture.npm.split('\n').forEach(line => stdout.write(`${line}\n`));
      stdout.end();

      const results = await auditRun;

      const auditOutput = JSON.parse(fixture.npm) as AuditOutput;

      delete auditOutput.metadata.vulnerabilities;

      expect(results.advisories).toStrictEqual(auditOutput.advisories);
      expect(results.statistics).toStrictEqual(auditOutput.metadata);
    });

    it('parses line-by-line', async () => {
      const fixture = fixtures.mkdirp_minimist;
      const stdout = mockSpawnStdoutStream();

      const auditRun = audit('my-dir', 'npm');

      fixture.npm.split('').forEach(char => stdout.write(char));
      stdout.end();

      const results = await auditRun;

      const auditOutput = JSON.parse(fixture.npm) as AuditOutput;

      delete auditOutput.metadata.vulnerabilities;

      expect(results.advisories).toStrictEqual(auditOutput.advisories);
      expect(results.statistics).toStrictEqual(auditOutput.metadata);
    });

    describe('when the json is not parsable', () => {
      it('rejects', async () => {
        const fixture = fixtures.mkdirp_minimist;
        const stdout = mockSpawnStdoutStream();

        const auditRun = audit('my-dir', 'npm');

        fixture.npm
          .substr(5)
          .split('')
          .forEach(char => stdout.write(char));
        stdout.end();

        await expect(auditRun).rejects.toThrow(Error);
      });
    });

    describe('when an error occurs', () => {
      it('rejects with the error as the message', async () => {
        const stdout = mockSpawnStdoutStream();

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

  describe('when auditing with pnpm', () => {
    it('calls audit --json in the given directory', async () => {
      mockSpawnStdoutStream().end('{}');

      await audit('my-dir', 'pnpm');

      expect(spawnMock).toHaveBeenCalledWith(
        'pnpm',
        ['audit', '--json', '--prefix', '.'],
        { cwd: 'my-dir' }
      );
    });

    it('returns the parsed audit results', async () => {
      const fixture = fixtures.mkdirp;
      const stdout = mockSpawnStdoutStream();

      const auditRun = audit('my-dir', 'pnpm');

      fixture.pnpm.split('\n').forEach(line => stdout.write(`${line}\n`));
      stdout.end();

      const results = await auditRun;

      const auditOutput = JSON.parse(fixture.pnpm) as AuditOutput;

      delete auditOutput.metadata.vulnerabilities;

      expect(results.advisories).toStrictEqual(auditOutput.advisories);
      expect(results.statistics).toStrictEqual(auditOutput.metadata);
    });

    it('parses line-by-line', async () => {
      const fixture = fixtures.mkdirp_minimist;
      const stdout = mockSpawnStdoutStream();

      const auditRun = audit('my-dir', 'npm');

      fixture.pnpm.split('').forEach(char => stdout.write(char));
      stdout.end();

      const results = await auditRun;

      const auditOutput = JSON.parse(fixture.pnpm) as AuditOutput;

      delete auditOutput.metadata.vulnerabilities;

      expect(results.advisories).toStrictEqual(auditOutput.advisories);
      expect(results.statistics).toStrictEqual(auditOutput.metadata);
    });

    describe('when the json is not parsable', () => {
      it('rejects', async () => {
        const fixture = fixtures.mkdirp_minimist;
        const stdout = mockSpawnStdoutStream();

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
        const stdout = mockSpawnStdoutStream();

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
      mockSpawnStdoutStream().end('{}');

      await audit('my-dir', 'yarn');

      expect(spawnMock).toHaveBeenCalledWith(
        'yarn',
        ['audit', '--json', '--cwd', '.'],
        { cwd: 'my-dir' }
      );
    });

    it('returns the parsed audit results', async () => {
      const fixture = fixtures.mkdirp;
      const stdout = mockSpawnStdoutStream();

      const auditRun = audit('my-dir', 'yarn');

      fixture.yarn.split('\n').forEach(line => stdout.write(`${line}\n`));
      stdout.end();

      const results = await auditRun;

      const npmResults = JSON.parse(fixture.npm) as AuditOutput;

      expect(results.advisories).toStrictEqual(npmResults.advisories);
      expect(results.statistics).toMatchInlineSnapshot(`
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
        const stdout = mockSpawnStdoutStream();

        const auditRun = audit('my-dir', 'yarn');

        fixture.yarn.split('\n').forEach(line => stdout.write(`${line}\n`));
        stdout.end();

        const results = await auditRun;

        const npmResults = JSON.parse(fixture.npm) as AuditOutput;

        expect(results.advisories).toStrictEqual(npmResults.advisories);
        expect(results.statistics).toMatchInlineSnapshot(`
          Object {
            "dependencies": 3,
            "devDependencies": 0,
            "optionalDependencies": 0,
            "totalDependencies": 3,
          }
        `);
      });
    });

    describe('when the output is missing "auditSummary"', () => {
      it('is fine', async () => {
        const fixture = fixtures.mkdirp_minimist;
        const stdout = mockSpawnStdoutStream();

        const auditRun = audit('my-dir', 'yarn');

        fixture.yarn
          .trim()
          .split('\n')
          .slice(0, -1)
          .forEach(line => stdout.write(`${line}\n`));
        stdout.end();

        const results = await auditRun;

        expect(results.statistics).toMatchInlineSnapshot(`Object {}`);
      });
    });

    describe('when the json is not parsable', () => {
      it('rejects', async () => {
        const fixture = fixtures.mkdirp_minimist;
        const stdout = mockSpawnStdoutStream();

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
