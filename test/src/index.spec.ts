import { mocked } from 'ts-jest/utils';
import { Options, auditApp } from '../../src';
import { audit } from '../../src/audit';
import { formatReport } from '../../src/formatReport';
import { buildFinding } from '../buildFinding';

jest.mock('../../src/audit');
jest.mock('../../src/formatReport');

const mockedAudit = mocked(audit);
const mockedFormatReport = mocked(formatReport);

let consoleLogSpy: jest.SpiedFunction<typeof console.log>;
let consoleErrorSpy: jest.SpiedFunction<typeof console.error>;

const emptyOptions: Options = {
  packageManager: 'npm',
  directory: process.cwd(),
  ignore: [],
  debug: false,
  output: 'tables'
};

describe('auditApp', () => {
  beforeEach(() => {
    mockedAudit.mockResolvedValue({
      findings: {},
      dependencyStatistics: {}
    });

    consoleLogSpy = jest.spyOn(console, 'log').mockReturnValue();
    consoleErrorSpy = jest.spyOn(console, 'error').mockReturnValue();
  });

  describe('when there are vulnerabilities', () => {
    beforeEach(() => {
      mockedAudit.mockResolvedValue({
        findings: {
          1500: buildFinding({
            paths: ['one', 'two'],
            id: 1500,
            severity: 'low'
          }),
          1234: buildFinding({
            paths: ['three'],
            id: 1234,
            severity: 'high'
          })
        },
        dependencyStatistics: {}
      });
    });

    it('sets the exit code to 1', async () => {
      await auditApp(emptyOptions);

      expect(process.exitCode).toBe(1);
    });

    describe('when the vulnerable paths are ignored', () => {
      it('sets the exit code to 0', async () => {
        await auditApp({
          ...emptyOptions,
          ignore: ['1500|one', '1500|two', '1234|three']
        });

        expect(process.exitCode).toBe(0);
      });
    });
  });

  describe('when there are no vulnerabilities', () => {
    it('sets the exit code to 0', async () => {
      await auditApp(emptyOptions);

      expect(process.exitCode).toBe(0);
    });

    describe('when there are ignored vulnerable paths', () => {
      it('sets the exit code to 1', async () => {
        await auditApp({
          ...emptyOptions,
          ignore: ['1500|one', '1500|two', '1234|three']
        });

        expect(process.exitCode).toBe(1);
      });
    });
  });

  it('formats the report based on the desired output', async () => {
    await auditApp({ ...emptyOptions, output: 'paths' });

    expect(mockedFormatReport).toHaveBeenCalledWith<
      Parameters<typeof formatReport>
    >('paths', expect.any(Object));
  });

  it('logs the formatted report', async () => {
    mockedFormatReport.mockReturnValue('<formatted report>');

    await auditApp({ ...emptyOptions });

    expect(consoleLogSpy).toHaveBeenCalledWith('<formatted report>');
  });

  describe('when an error occurs', () => {
    beforeEach(() => mockedAudit.mockRejectedValue(new Error('oh noes!')));

    describe('when debug is false', () => {
      const options: Options = { ...emptyOptions, debug: false };

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
      const options: Options = { ...emptyOptions, debug: true };

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
