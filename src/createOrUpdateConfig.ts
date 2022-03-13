import { promises as fs } from 'fs';
import { AuditReport } from './generateReport';
import { Options } from './index';
import { sortVulnerabilityPaths } from './sortVulnerabilityPaths';

type RelevantConfigOptions = Pick<Options, 'ignore'>;

const tryReadConfig = async (
  configPath: string
): Promise<RelevantConfigOptions> => {
  try {
    return JSON.parse(
      await fs.readFile(configPath, 'utf-8')
    ) as RelevantConfigOptions;
  } catch {
    return { ignore: [] };
  }
};

export const createOrUpdateConfig = async (
  configPath: string,
  report: AuditReport
): Promise<void> => {
  const configContents = await tryReadConfig(configPath);

  configContents.ignore = sortVulnerabilityPaths([
    ...report.vulnerable,
    ...report.ignored
  ]);

  await fs.writeFile(
    configPath,
    `${JSON.stringify(configContents, null, 2)}\n`,
    'utf-8'
  );
};
