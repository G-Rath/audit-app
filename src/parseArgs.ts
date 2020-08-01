import fs from 'fs';
import * as path from 'path';
import yargs from 'yargs/yargs';
import { SupportedPackageManager, SupportedPackageManagers } from './audit';
import { SupportedReportFormat, SupportedReportFormats } from './formatReport';
import { Options as ParsedArgs } from './index';

type PackageManagerOption = 'auto' | SupportedPackageManager;

const determinePackageManager = (dir: string): SupportedPackageManager => {
  // eslint-disable-next-line no-sync
  const files = fs.readdirSync(dir);

  if (files.includes('package-lock.json')) {
    return 'npm';
  }

  if (files.includes('yarn.lock')) {
    return 'yarn';
  }

  if (files.includes('pnpm-lock.yaml')) {
    return 'pnpm';
  }

  throw new Error('unable to determine package manager to use');
};

const parseConfigFile = (filepath: string): Record<string, unknown> => {
  const ext = path.parse(filepath).ext.substr(1);

  if (ext !== 'json') {
    throw new Error(`Unsupported file type "${ext}"`);
  }

  // eslint-disable-next-line no-sync
  const contents = fs.readFileSync(filepath).toString();

  try {
    return JSON.parse(contents) as Record<string, unknown>;
  } catch (e) {
    const err = e as Error;

    err.message = `Failed to parse config: ${err.message}`;

    throw err;
  }
};

interface ParsedArgvWithConfig {
  argv: Omit<ParsedArgs, 'packageManager'> & {
    packageManager: PackageManagerOption;
    output: SupportedReportFormat;
    config?: string | false;
  };
}

const DefaultConfigFile = '.auditapprc.json';

const parseWithConfig = (args: string[], configPath?: string): ParsedArgs => {
  const { argv }: ParsedArgvWithConfig = yargs(args)
    .completion('completion', false)
    .options({
      config: {
        alias: 'c',
        string: true,
        config: !!configPath,
        default: configPath ?? DefaultConfigFile,
        configParser: parseConfigFile
      },
      debug: { boolean: true, default: false },
      directory: {
        string: true,
        default: process.cwd(),
        defaultDescription: 'cwd'
      },
      packageManager: {
        default: 'auto' as PackageManagerOption,
        choices: ['auto'].concat(SupportedPackageManagers),
        description: [
          'Specifies which package manager to use for auditing.',
          '"auto" will attempt to figure out what to use based on lock files.'
        ].join('\n')
      },
      ignore: { array: true, default: [] },
      output: {
        default: 'tables' as const,
        choices: SupportedReportFormats
      }
    })
    .strict();

  const pathToDefaultConfig = path.join(argv.directory, DefaultConfigFile);

  if (
    !configPath &&
    argv.config &&
    // we don't want to error if the default config file doesn't exist
    // eslint-disable-next-line no-sync
    (argv.config !== DefaultConfigFile || fs.existsSync(pathToDefaultConfig))
  ) {
    return parseWithConfig(
      args,
      argv.config === DefaultConfigFile ? pathToDefaultConfig : argv.config
    );
  }

  const packageManager =
    argv.packageManager === 'auto'
      ? determinePackageManager(argv.directory)
      : argv.packageManager;

  return { ...argv, packageManager };
};

export const parseArgs = (args: string[]): ParsedArgs => parseWithConfig(args);
