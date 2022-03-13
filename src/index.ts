import { SupportedPackageManager, audit } from './audit';
import { SupportedReportFormat, formatReport } from './formatReport';
import { generateReport } from './generateReport';

export interface Options {
  packageManager: SupportedPackageManager;
  directory: string;
  debug: boolean;
  ignore: string[];
  output: SupportedReportFormat;
}

export const auditApp = async (options: Options): Promise<void> => {
  if (options.debug) {
    console.log(`auditing with ${options.packageManager}...`);
  }

  try {
    const results = await audit(options.directory, options.packageManager);
    const report = generateReport(options.ignore, results);

    process.exitCode = (report.vulnerable.length || report.missing.length) && 1;

    console.log(formatReport(options.output, report));
  } catch (error) {
    process.exitCode = 1;

    if (options.debug) {
      throw error;
    }

    console.error('an error happened while auditing');
  }
};
