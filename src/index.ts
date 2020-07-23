import { SupportedPackageManager, audit } from './audit';
import { formatReport } from './formatReport';
import { generateReport } from './generateReport';

export interface Options {
  packageManager: SupportedPackageManager;
  directory: string;
  debug: boolean;
  ignore: string[];
}

export const auditApp = async (options: Options): Promise<void> => {
  console.log(`auditing with ${options.packageManager}...`);

  try {
    const results = await audit(options.directory, options.packageManager);
    const report = generateReport(options, results);

    console.log(formatReport(report));
  } catch (error) {
    process.exitCode = 1;

    if (options.debug) {
      throw error;
    }

    console.error('an error happened while auditing');
  }
};
