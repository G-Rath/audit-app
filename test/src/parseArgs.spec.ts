/* eslint-disable no-sync */

import * as fs from 'fs';
import { Config, parseArgs } from '../../src/parseArgs';

const writeConfigFile = (name: string, config: Partial<Config>): void => {
  fs.writeFileSync(name, JSON.stringify(config, null, 2));
};

let processExitSpy: jest.SpiedFunction<typeof process.exit>;
let consoleErrorSpy: jest.SpiedFunction<typeof console.error>;

describe('parseArgs', () => {
  beforeEach(() => {
    consoleErrorSpy = jest.spyOn(console, 'error');
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
    });
  });
});