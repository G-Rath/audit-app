import fs from 'fs';
import * as path from 'path';
import yargs from 'yargs/yargs';
import { SupportedPackageManager, SupportedPackageManagers } from './audit';
import { Options } from './index';

type PackageManagerOption = 'auto' | SupportedPackageManager;

const determinePackageManager = (): SupportedPackageManager => {
  // eslint-disable-next-line no-sync
  const files = fs.readdirSync('.');

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

export interface Config {
  packageManager: PackageManagerOption;
  preferNpmOverYarn: boolean;
  directory: string;
}

interface ArgvConfig {
  argv: Config & { config?: string | false };
}

const DefaultConfigFile = '.auditapprc.json';

const parseArgsWithConfig = (args: string[], configPath?: string): Options => {
  const { argv }: ArgvConfig = yargs(args)
    .options({
      config: {
        string: true,
        config: !!configPath,
        default: DefaultConfigFile,
        configParser: parseConfigFile
      },
      directory: {
        string: true,
        default: process.cwd(),
        defaultDescription: 'cwd'
      },
      packageManager: {
        default: 'auto' as PackageManagerOption,
        choices: ['auto'].concat(SupportedPackageManagers)
      },
      preferNpmOverYarn: { boolean: true, default: false }
    })
    .strict();

  if (
    !configPath &&
    argv.config &&
    // we don't want to error if the default config file doesn't exist
    // eslint-disable-next-line no-sync
    (argv.config !== DefaultConfigFile || fs.existsSync(DefaultConfigFile))
  ) {
    return parseArgsWithConfig(args, argv.config);
  }

  const packageManager =
    argv.packageManager === 'auto'
      ? determinePackageManager()
      : argv.packageManager;

  return {
    packageManager,
    allowlist: [],
    directory: argv.directory
  };
};

export const parseArgs = (args: string[]): Options => parseArgsWithConfig(args);
