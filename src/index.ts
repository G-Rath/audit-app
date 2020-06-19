import { SupportedPackageManager, audit } from './audit';
import { generateReport } from './generateReport';

export interface Options {
  packageManager: SupportedPackageManager;
  allowlist: string[];
  directory: string;
}

export const auditApp = async (options: Options): Promise<void> => {
  const results = await audit(options.directory, options.packageManager);
  const report = generateReport(options, results);

  console.log(report);
};
