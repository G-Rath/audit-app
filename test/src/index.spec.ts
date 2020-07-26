import { mocked } from 'ts-jest/utils';
import { Options, auditApp } from '../../src';
import { audit } from '../../src/audit';
import { formatReport } from '../../src/formatReport';
import { Advisory } from '../../src/types';

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

const buildOptions = (options: Partial<Options> = {}): Options => ({
  ...emptyOptions,
  ...options
});

const buildAdvisory = (advisory: Partial<Advisory>): Advisory => ({
  findings: [],
  id: 1500,
  created: '2020-03-26T19:21:50.174Z',
  updated: '2020-05-01T01:05:15.020Z',
  deleted: null,
  title: 'Prototype Pollution',
  found_by: { link: '', name: 'Snyk Security Team', email: '' },
  reported_by: { link: '', name: 'Snyk Security Team', email: '' },
  module_name: 'yargs-parser',
  cves: [],
  vulnerable_versions: '',
  patched_versions: '',
  overview: '',
  recommendation: '',
  references: '',
  access: 'public',
  severity: 'low',
  cwe: 'CWE-471',
  metadata: { module_type: '', exploitability: 1, affected_components: '' },
  url: 'https://npmjs.com/advisories/1500',
  ...advisory
});

describe('auditApp', () => {
  beforeEach(() => {
    mockedAudit.mockResolvedValue({
      advisories: {},
      statistics: {}
    });

    consoleLogSpy = jest.spyOn(console, 'log').mockReturnValue();
    consoleErrorSpy = jest.spyOn(console, 'error').mockReturnValue();
  });

  describe('when there are vulnerabilities', () => {
    beforeEach(() => {
      mockedAudit.mockResolvedValue({
        advisories: {
          '1500': buildAdvisory({
            findings: [{ version: '10.1.0', paths: ['one', 'two'] }],
            id: 1500,
            severity: 'low'
          }),
          '1234': buildAdvisory({
            findings: [{ version: '10.1.0', paths: ['three'] }],
            id: 1234,
            severity: 'high'
          })
        },
        statistics: {}
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