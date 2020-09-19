#!/usr/bin/env ts-node-transpile-only

/* eslint-disable node/no-sync */

import { spawn } from 'child_process';
import fs from 'fs';
import path from 'path';
import {
  SupportedPackageManager,
  SupportedPackageManagers
} from '../src/audit';

type AuditFixture = Record<SupportedPackageManager, string>;

const pathToFixtures = path.join('test', 'fixtures');
const fixturesJson: Record<string, AuditFixture> = {};

const generateAuditOutput = async (
  dir: string,
  packageManager: SupportedPackageManager
): Promise<string> =>
  new Promise<string>((resolve, reject) => {
    const proc = spawn(
      packageManager,
      [
        'audit',
        '--json',
        `--${packageManager === 'yarn' ? 'cwd' : 'prefix'}`,
        '.'
      ],
      { cwd: dir, env: { ...process.env, npm_config_loglevel: undefined } }
    );

    let output = '';

    proc.stdout.on('data', (chunk: Buffer) => {
      try {
        output += chunk;
      } catch (error) {
        reject(error);
        proc.kill();
      }
    });

    proc.on('close', () => resolve(output));
    proc.on('error', reject);
  });

// const writeFixtureOutput = async (fixture: string): Promise<void> => {
//   await fs.promises.writeFile(
//     path.join(dir, `audit-output-${packageManager}-raw.txt`),
//     value
//   );
// };

const fixtures = fs
  .readdirSync(pathToFixtures, { withFileTypes: true })
  .filter(dir => dir.isDirectory())
  .map(dir => dir.name);

/**
 * Replaces the `runId` property in the raw output from `npm audit --json` calls
 * with a hardcoded runId to reduce meaningless diffing.
 *
 * @param {string} output
 *
 * @return {string}
 */
const replaceRunId = (output: string): string =>
  output.replace(
    /"runId": "[0-9a-f]{8}-[0-9a-f]{4}-[0-5][0-9a-f]{3}-[089ab][0-9a-f]{3}-[0-9a-f]{12}"\n/u,
    '"runId": "71a5d4e1-1563-4d63-8bbb-99624ba6de30"\n'
  );

Promise.all(
  fixtures.map(async fixture => {
    fixturesJson[fixture] = {
      npm: '',
      pnpm: '',
      yarn: ''
    };

    return Promise.all(
      SupportedPackageManagers.map(async packageManager =>
        generateAuditOutput(path.join(pathToFixtures, fixture), packageManager)
          .then(output => {
            console.log(`${fixture}: generated ${packageManager} audit output`);

            fixturesJson[fixture][packageManager] = replaceRunId(output); // .split('\n');

            // fixturesJson[fixture][packageManager] =
            //   packageManager === 'yarn' //
            //     ? output.split('\n')
            //     : [output];
          })
          .catch((error: Error) => {
            error.message += ` (occurred generating audit output for ${fixture} using ${packageManager})`;

            throw error;
          })
      )
    );
  })
)
  .then(async () =>
    fs.promises.writeFile(
      path.join(pathToFixtures, 'fixtures.json'),
      JSON.stringify(fixturesJson, null, 2)
    )
  )
  .then(() => console.log('finished'))
  .catch(console.error);
