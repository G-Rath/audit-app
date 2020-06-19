import {
  SpawnSyncOptionsWithStringEncoding,
  SpawnSyncReturns
} from 'child_process';
import { spawnSync } from 'child_process';
import { audit } from '../../src/audit';
import { AuditResults } from '../../src/types';
import fixtures from '../fixtures';

jest.mock('child_process');

const spawnSyncMock = (spawnSync as unknown) as jest.MockedFunction<
  (
    command: string,
    args?: readonly string[],
    options?: SpawnSyncOptionsWithStringEncoding
  ) => SpawnSyncReturns<string>
>;

const mockSpawnStdout = (stdout: string): void => {
  spawnSyncMock.mockReturnValue({
    output: [],
    pid: 0,
    signal: null,
    status: null,
    stderr: '',
    stdout
  });
};

describe('audit', () => {
  describe('when auditing with npm', () => {
    beforeEach(() => mockSpawnStdout(fixtures.mkdirp.npm));

    it('calls audit --json in the given directory', async () => {
      await audit('my-dir', 'npm');

      expect(spawnSyncMock).toHaveBeenCalledWith(
        'npm',
        ['audit', '--json', '--prefix', '.'],
        { encoding: 'utf-8', cwd: 'my-dir' }
      );
    });

    it('returns the parsed audit results', async () => {
      await expect(audit('my-dir', 'npm')).resolves.toStrictEqual(
        JSON.parse(fixtures.mkdirp.npm)
      );
    });
  });

  describe('when auditing with pnpm', () => {
    beforeEach(() => mockSpawnStdout(fixtures.mkdirp.pnpm));

    it('calls audit --json in the given directory', async () => {
      await audit('my-dir', 'pnpm');

      expect(spawnSyncMock).toHaveBeenCalledWith(
        'pnpm',
        ['audit', '--json', '--prefix', '.'],
        { encoding: 'utf-8', cwd: 'my-dir' }
      );
    });

    it('returns the parsed audit results', async () => {
      await expect(audit('my-dir', 'pnpm')).resolves.toStrictEqual(
        JSON.parse(fixtures.mkdirp.pnpm)
      );
    });
  });

  describe('when auditing with yarn', () => {
    it('calls audit --json in the given directory', async () => {
      mockSpawnStdout(fixtures.mkdirp.yarn);

      await audit('my-dir', 'yarn');

      expect(spawnSyncMock).toHaveBeenCalledWith(
        'yarn',
        ['audit', '--json', '--cwd', '.'],
        { encoding: 'utf-8', cwd: 'my-dir' }
      );
    });

    it('returns the parsed audit results', async () => {
      const fixture = fixtures.mkdirp;

      mockSpawnStdout(fixture.yarn);
      const npmResults = JSON.parse(fixture.npm) as AuditResults;

      const results = await audit('my-dir', 'yarn');

      expect(results.advisories).toStrictEqual(npmResults.advisories);
      expect(results.metadata).toMatchInlineSnapshot(`
        Object {
          "dependencies": 2,
          "devDependencies": 0,
          "optionalDependencies": 0,
          "totalDependencies": 2,
          "vulnerabilities": Object {
            "critical": 0,
            "high": 0,
            "info": 0,
            "low": 1,
            "moderate": 0,
          },
        }
      `);
    });

    describe('when there are multiple results for the same advisory', () => {
      it('merges them', async () => {
        const fixture = fixtures.mkdirp_minimist;

        mockSpawnStdout(fixture.yarn);
        const npmResults = JSON.parse(fixture.npm) as AuditResults;

        const results = await audit('my-dir', 'yarn');

        expect(results.advisories).toStrictEqual(npmResults.advisories);
        expect(results.metadata).toMatchInlineSnapshot(`
          Object {
            "dependencies": 3,
            "devDependencies": 0,
            "optionalDependencies": 0,
            "totalDependencies": 3,
            "vulnerabilities": Object {
              "critical": 0,
              "high": 0,
              "info": 0,
              "low": 2,
              "moderate": 0,
            },
          }
        `);
      });
    });

    describe('when the output is missing "auditSummary"', () => {
      it('throws', async () => {
        mockSpawnStdout(
          fixtures.mkdirp.yarn.trim().split('\n').slice(0, -1).join('\n')
        );

        await expect(async () => audit('my-dir', 'yarn')).rejects.toThrow(
          'Could not find "auditSummary" in `yarn audit` output'
        );
      });
    });
  });
});
