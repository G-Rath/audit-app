import { promises as fs } from 'fs';
import { createOrUpdateConfig } from '../../src/createOrUpdateConfig';
import { AuditReport } from '../../src/generateReport';

const EmptyStatistics = {} as AuditReport['statistics'];

const readConfig = async (configPath: string) => {
  return JSON.parse(await fs.readFile(configPath, 'utf-8')) as unknown;
};

describe('createOrUpdateConfig', () => {
  it('adds new vulnerabilities', async () => {
    await createOrUpdateConfig('my-config.json', {
      findings: {},
      ignored: [],
      missing: [],
      statistics: EmptyStatistics,
      vulnerable: ['1', '2', '3']
    });

    await expect(readConfig('my-config.json')).resolves.toHaveProperty(
      'ignore',
      ['1', '2', '3']
    );
  });

  it('preserves existing ignores', async () => {
    await createOrUpdateConfig('my-config.json', {
      findings: {},
      ignored: ['1', '2', '3'],
      missing: [],
      statistics: EmptyStatistics,
      vulnerable: []
    });

    await expect(readConfig('my-config.json')).resolves.toHaveProperty(
      'ignore',
      ['1', '2', '3']
    );
  });

  describe('when the config does not exist', () => {
    it('creates it', async () => {
      await createOrUpdateConfig('my-config.json', {
        findings: {},
        ignored: [],
        missing: [],
        statistics: EmptyStatistics,
        vulnerable: ['1', '2', '3']
      });

      await expect(readConfig('my-config.json')).resolves.toHaveProperty(
        'ignore',
        ['1', '2', '3']
      );
    });
  });

  describe('when the config already exists', () => {
    beforeEach(async () => {
      await fs.writeFile(
        'my-config.json',
        JSON.stringify({ packageManager: 'npm' }),
        'utf-8'
      );
    });

    it('preserves existing properties', async () => {
      await createOrUpdateConfig('my-config.json', {
        findings: {},
        ignored: [],
        missing: [],
        statistics: EmptyStatistics,
        vulnerable: ['1', '2', '3']
      });

      await expect(readConfig('my-config.json')).resolves.toStrictEqual({
        packageManager: 'npm',
        ignore: ['1', '2', '3']
      });
    });
  });
});
