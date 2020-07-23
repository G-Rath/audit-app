import { mocked } from 'ts-jest/utils';
import { Options, auditApp } from '../../src';
import { audit } from '../../src/audit';

jest.mock('../../src/audit');

const mockedAudit = mocked(audit);

let consoleErrorSpy: jest.SpiedFunction<typeof console.error>;

const buildOptions = (options: Partial<Options> = {}): Options => ({
  packageManager: 'npm',
  directory: process.cwd(),
  ignore: [],
  debug: false,
  ...options
});

describe('auditApp', () => {
  beforeEach(() => {
    mockedAudit.mockResolvedValue({
      advisories: {},
      statistics: {}
    });

    consoleErrorSpy = jest.spyOn(console, 'error').mockReturnValue();
  });

  describe('when an error occurs', () => {
    beforeEach(() => mockedAudit.mockRejectedValue(new Error('oh noes!')));

    describe('when debug is false', () => {
      const options = buildOptions({ debug: false });

      it('does not throw', async () => {
        await expect(auditApp(options)).resolves.toBeUndefined();
      });

      it('sets the exit code', async () => {
        try {
          await auditApp(options);
        } catch {
          // we don't care if it errors
        }

        expect(process.exitCode).toBe(1);
      });

      it('logs that an error happened', async () => {
        try {
          await auditApp(options);
        } catch {
          // we don't care if it errors
        }

        expect(consoleErrorSpy).toHaveBeenCalledWith(
          expect.stringMatching(/error happened while auditing/iu)
        );
      });
    });

    describe('when debug is true', () => {
      const options = buildOptions({ debug: true });

      it('sets the exit code', async () => {
        try {
          await auditApp(options);
        } catch {
          // we don't care if it errors
        }

        expect(process.exitCode).toBe(1);
      });

      it('rethrows the error', async () => {
        await expect(auditApp(options)).rejects.toThrow('oh noes!');
      });
    });
  });
});
