import { SupportedPackageManager, audit } from './audit';
import { formatReport } from './formatReport';
import { generateReport } from './generateReport';

export interface Options {
  packageManager: SupportedPackageManager;
  allowlist: string[];
  directory: string;
  debug: boolean;
}

export const auditApp = async (options: Options): Promise<void> => {
  if (options.debug) {
    console.log('auditing...');
  }

  try {
    const results = await audit(options.directory, options.packageManager);
    const report = generateReport(options, results);

    console.log(formatReport(report));
  } catch (error) {
    if (options.debug) {
      throw error;
    }

    console.log('an error happened while auditing');
  }
};
