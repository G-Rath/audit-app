/* eslint-disable node/no-sync */

import fs from 'fs';
import path from 'path';
import { Options as ParsedArgs } from '../../src';
import { SupportedPackageManager } from '../../src/audit';
import { parseArgs } from '../../src/parseArgs';

type ConfigFileContents = Partial<ParsedArgs & { $schema: string }>;

const writeConfigFile = (name: string, config: ConfigFileContents): void => {
  fs.writeFileSync(name, JSON.stringify(config, null, 2));
};

const lockFiles: Record<SupportedPackageManager, string> = {
  yarn: 'yarn.lock',
  pnpm: 'pnpm-lock.yaml',
  npm: 'package-lock.json'
};

const writeLockFile = (
  packageManager: SupportedPackageManager,
  dir: string
): void => {
  fs.mkdirSync(dir, { recursive: true });

  const lockFile = lockFiles[packageManager];

  fs.writeFileSync(path.join(dir, lockFile), '');
};

let processExitSpy: jest.SpiedFunction<typeof process.exit>;
let consoleErrorSpy: jest.SpiedFunction<typeof console.error>;

describe('parseArgs', () => {
  beforeEach(() => {
    consoleErrorSpy = jest.spyOn(console, 'error').mockReturnValue();
    processExitSpy = jest.spyOn(process, 'exit').mockImplementation(code => {
      throw new Error(`yargs exited, code ${code ?? 'none'}`);
    });
  });

  describe('when an rc file exists', () => {
    beforeEach(() => {
      writeConfigFile('.auditapprc.json', { packageManager: 'yarn' });
    });

    // todo: are array flags merged or overridden
    // todo: test accepting different file types (?)

    it('parses the rc file', () => {
      expect(parseArgs([])).toHaveProperty('packageManager', 'yarn');
    });

    describe('when the config file contains the $schema property', () => {
      beforeEach(() => {
        writeConfigFile('.auditapprc.json', {
          $schema: '../config.schema.json',
          packageManager: 'yarn'
        });
      });

      it('does not error when parsing', () => {
        expect(() => parseArgs([])).not.toThrow();

        expect(parseArgs([])).toHaveProperty('packageManager', 'yarn');
      });
    });

    it('favors flags over config', () => {
      expect(parseArgs(['--package-manager', 'npm'])).toHaveProperty(
        'packageManager',
        'npm'
      );
    });

    describe('when the rc file is not valid json', () => {
      it('errors', () => {
        fs.writeFileSync('.auditapprc.json', 'hello world!');

        expect(() => parseArgs([])).toThrow('yargs exited');

        expect(processExitSpy).toHaveBeenCalledWith(1);
        expect(consoleErrorSpy).toHaveBeenCalledWith(
          expect.stringContaining('Failed to parse config')
        );
      });
    });

    describe('when the --directory flag is set', () => {
      beforeEach(() => {
        fs.mkdirSync('path/to/app', { recursive: true });

        writeConfigFile('.auditapprc.json', { packageManager: 'npm' });
        writeConfigFile('path/to/app/.auditapprc.json', {
          packageManager: 'yarn'
        });
      });

      it('looks in the given directory for the rc file', () => {
        expect(parseArgs(['--directory', 'path/to/app'])).toHaveProperty(
          'packageManager',
          'yarn'
        );
      });
    });
  });

  describe('flags', () => {
    describe('--package-manager <package-manager>', () => {
      describe('when provided with the name of a package manager', () => {
        it('ignores any existing lock files', () => {
          fs.writeFileSync('yarn.lock', '');

          expect(parseArgs(['--package-manager', 'pnpm'])).toHaveProperty(
            'packageManager',
            'pnpm'
          );
        });
      });

      describe('when provided with "auto"', () => {
        it('determines the package manager based on the lock file', () => {
          fs.writeFileSync('yarn.lock', '');

          expect(parseArgs([])).toHaveProperty('packageManager', 'yarn');
        });

        describe('when no lock files can be found', () => {
          it('errors', () => {
            expect(() => parseArgs([])).toThrow(
              'unable to determine package manager'
            );
          });
        });

        describe('when combined with the --directory flag', () => {
          it('checks the given dir for a lock file', () => {
            const dir = 'path/to/app';

            writeLockFile('yarn', '.');
            writeLockFile('pnpm', dir);

            expect(parseArgs(['--directory', '.'])).toHaveProperty(
              'packageManager',
              'yarn'
            );
            expect(parseArgs(['--directory', dir])).toHaveProperty(
              'packageManager',
              'pnpm'
            );
          });
        });
      });
    });

    describe('--config <config-path>', () => {
      describe('when the path points to a valid config', () => {
        beforeEach(() => {
          writeConfigFile('config.json', { packageManager: 'yarn' });
        });

        it('parses the config', () => {
          expect(parseArgs(['--config', 'config.json'])).toHaveProperty(
            'packageManager',
            'yarn'
          );
        });

        it('favors flags over config', () => {
          expect(
            parseArgs([
              ...['--config', 'config.json'],
              ...['--package-manager', 'npm']
            ])
          ).toHaveProperty('packageManager', 'npm');
        });
      });

      describe('when the path points to an invalid config', () => {
        it('errors', () => {
          fs.writeFileSync('config.json', 'hello world!');

          expect(() => parseArgs(['--config', 'config.json'])).toThrow(
            'yargs exited'
          );

          expect(processExitSpy).toHaveBeenCalledWith(1);
          expect(consoleErrorSpy).toHaveBeenCalledWith(
            expect.stringContaining('Failed to parse config')
          );
        });
      });

      describe('when the path points to a config of an unsupported file type', () => {
        it('errors', () => {
          fs.writeFileSync('config.toml', 'hello world!');

          expect(() => parseArgs(['--config', 'config.toml'])).toThrow(
            'yargs exited'
          );

          expect(processExitSpy).toHaveBeenCalledWith(1);
          expect(consoleErrorSpy).toHaveBeenCalledWith(
            expect.stringContaining('Unsupported file type "toml"')
          );
        });
      });

      describe('when the path is invalid', () => {
        it('errors', () => {
          expect(() => parseArgs(['--config', '1.json'])).toThrow(
            'yargs exited'
          );

          expect(processExitSpy).toHaveBeenCalledWith(1);
          expect(consoleErrorSpy).toHaveBeenCalledWith(
            expect.stringContaining('ENOENT: no such file or directory')
          );
        });
      });

      describe('when the --directory flag is set', () => {
        beforeEach(() => {
          writeConfigFile('config.json', { packageManager: 'yarn' });
        });

        it('makes no difference', () => {
          expect(
            parseArgs(['--config', 'config.json', '--directory', 'path/to/app'])
          ).toHaveProperty('packageManager', 'yarn');
        });
      });
    });

    describe('--directory <directory-path>', () => {
      it('uses the given value for the directory', () => {
        const dir = 'path/to/app';

        writeLockFile('pnpm', dir);

        expect(parseArgs(['--directory', dir])).toHaveProperty(
          'directory',
          dir
        );
      });
    });

    describe('--output <output-format>', () => {
      it('passes the value on as the "output" property', () => {
        writeLockFile('npm', process.cwd());

        expect(parseArgs(['--output', 'paths'])).toHaveProperty(
          'output',
          'paths'
        );
      });
    });

    describe('--ignore <vulnerability>', () => {
      beforeEach(() => writeLockFile('npm', process.cwd()));

      it('can be passed multiple values', () => {
        expect(
          parseArgs(['--ignore', '1|a>b', '1|c>d', '1|d>e'])
        ).toHaveProperty('ignore', ['1|a>b', '1|c>d', '1|d>e']);
      });

      it('can be passed multiple times', () => {
        expect(
          parseArgs([
            '--ignore',
            '1|a>b',
            '--ignore',
            '1|c>d',
            '--ignore',
            '1|d>e'
          ])
        ).toHaveProperty('ignore', ['1|a>b', '1|c>d', '1|d>e']);
      });

      it('supports both multiple values and multiple times', () => {
        expect(
          parseArgs(['--ignore', '1|a>b', '1|c>d', '--ignore', '1|d>e'])
        ).toHaveProperty('ignore', ['1|a>b', '1|c>d', '1|d>e']);
      });

      describe('when there is a config file with ignores', () => {
        it('favors the flag', () => {
          writeConfigFile('.auditapprc.json', { ignore: ['1|a>b'] });

          expect(
            parseArgs(['--ignore', '1|c>d', '--ignore', '1|d>e'])
          ).toHaveProperty('ignore', ['1|c>d', '1|d>e']);
        });
      });
    });
  });
});
