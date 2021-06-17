import { promises as fs } from 'fs';
import path from 'path';
import { determineVulnerablePackages } from '../../src/determineVulnerablePackages';
import { Npm7Advisory, NpmPackageLock, PackageJson } from '../../src/types';

const writeJsonFile = async <TContents>(
  dir: string,
  filename: string,
  contents: TContents
) => {
  await fs.writeFile(
    path.join(dir, filename),
    JSON.stringify(contents, null, 2)
  );
};

const writePackageJsonAndLock = async (
  dir: string,
  json: PackageJson,
  dependencies: NpmPackageLock['dependencies']
) => {
  await fs.mkdir(dir, { recursive: true });

  await writeJsonFile<PackageJson>(dir, 'package.json', json);
  await writeJsonFile<NpmPackageLock>(dir, 'package-lock.json', {
    version: '1.0.0',
    dependencies
  });
};

const advisory: Npm7Advisory = {
  dependency: '',
  name: '',
  range: '*', // match all by default
  severity: 'high',
  source: 1,
  title: '',
  url: ''
} as const;

describe('determineVulnerablePackages', () => {
  beforeEach(async () => {
    await fs.mkdir('my-dir', { recursive: true });
  });

  describe('when there is no package.json', () => {
    beforeEach(async () => {
      await writeJsonFile<NpmPackageLock>('my-dir', 'package-lock.json', {
        version: '1.0.0',
        dependencies: {}
      });
    });

    it('throws an error', async () => {
      await expect(determineVulnerablePackages([], 'my-dir')).rejects.toThrow(
        /no such file or directory.+'my-dir\/package\.json'/iu
      );
    });
  });

  describe('when there is no package-lock.json', () => {
    beforeEach(async () => {
      await writeJsonFile<PackageJson>('my-dir', 'package.json', {});
    });

    it('throws an error', async () => {
      await expect(determineVulnerablePackages([], 'my-dir')).rejects.toThrow(
        /no such file or directory.+'my-dir\/package-lock\.json'/iu
      );
    });
  });

  describe('when the package-lock.json is missing a dependency', () => {
    beforeEach(async () => {
      await writePackageJsonAndLock(
        'my-dir',
        { dependencies: { a: '^1.0.0' } },
        {
          a: { version: '1.0.0', requires: { b: '^1.0.0' } }
        }
      );
    });

    it('throws an error', async () => {
      await expect(determineVulnerablePackages([], 'my-dir')).rejects.toThrow(
        /Could not find parent dependency for b/iu
      );
    });
  });

  describe('when the package-lock.json is empty', () => {
    beforeEach(async () => {
      await writePackageJsonAndLock(
        'my-dir',
        { dependencies: { a: '^1.0.0' } },
        {}
      );
    });

    it('throws an error', async () => {
      await expect(determineVulnerablePackages([], 'my-dir')).rejects.toThrow(
        /Could not find top-level dependency a/iu
      );
    });
  });

  describe('when there is a valid package.json and package-lock.json', () => {
    describe('when there are no advisories', () => {
      it('returns an empty object', async () => {
        await writePackageJsonAndLock(
          'my-dir',
          { dependencies: { a: '^1.0.0' } },
          {
            a: { version: '1.0.0', requires: { b: '^1.0.0' } },
            b: { version: '1.0.0', requires: { c: '^1.0.0' } },
            c: { version: '1.0.0', requires: { d: '^1.0.0' } },
            d: { version: '1.0.0' }
          }
        );

        await expect(
          determineVulnerablePackages([], 'my-dir')
        ).resolves.toStrictEqual({});
      });
    });

    it('finds vulnerable top level packages', async () => {
      await writePackageJsonAndLock(
        'my-dir',
        { dependencies: { a: '^1.0.0' } },
        {
          a: { version: '1.0.0', requires: { b: '^1.0.0' } },
          b: { version: '1.0.0' }
        }
      );

      await expect(
        determineVulnerablePackages([{ ...advisory, name: 'a' }], 'my-dir')
      ).resolves.toStrictEqual({ 1: [['a', '1.0.0']] });
    });

    it('finds vulnerable nested packages', async () => {
      await writePackageJsonAndLock(
        'my-dir',
        { dependencies: { a: '1' } },
        {
          a: { version: '1.0.0', requires: { b: '^1.0.0' } },
          b: { version: '1.0.0' }
        }
      );

      await expect(
        determineVulnerablePackages([{ ...advisory, name: 'b' }], 'my-dir')
      ).resolves.toStrictEqual({ 1: [['a>b', '1.0.0']] });
    });

    it('finds multiple nested vulnerable packages', async () => {
      await writePackageJsonAndLock(
        'my-dir',
        { dependencies: { a: '^1.0.0' } },
        {
          a: {
            version: '1.0.0',
            requires: { b: '^1.0.0', c: '^1.0.0', d: '^1.0.0' }
          },
          b: { version: '1.0.0' },
          c: { version: '1.0.0' },
          d: { version: '1.0.0' }
        }
      );

      await expect(
        determineVulnerablePackages(
          [
            { ...advisory, name: 'b', source: 1 },
            { ...advisory, name: 'c', source: 2 },
            { ...advisory, name: 'd', source: 3 }
          ],
          'my-dir'
        )
      ).resolves.toStrictEqual({
        1: [['a>b', '1.0.0']],
        2: [['a>c', '1.0.0']],
        3: [['a>d', '1.0.0']]
      });
    });

    it('finds vulnerable dependencies that also have vulnerable dependencies', async () => {
      await writePackageJsonAndLock(
        'my-dir',
        { dependencies: { a: '^1.0.0' } },
        {
          a: { version: '1.0.0', requires: { b: '^1.0.0' } },
          b: { version: '1.0.0', requires: { c: '^1.0.0' } },
          c: { version: '1.0.0', requires: { d: '^1.0.0' } },
          d: { version: '1.0.0' }
        }
      );

      await expect(
        determineVulnerablePackages(
          [
            { ...advisory, name: 'b', source: 1 },
            { ...advisory, name: 'd', source: 2 }
          ],
          'my-dir'
        )
      ).resolves.toStrictEqual({
        1: [['a>b', '1.0.0']],
        2: [['a>b>c>d', '1.0.0']]
      });
    });

    it('supports nested trees with mid-level deduplication', async () => {
      await writePackageJsonAndLock(
        'my-dir',
        {
          dependencies: {
            'has-flag': '^5.0.0',
            'supports-color': '^9.0.1',
            'supports-hyperlinks': '^2.2.0'
          }
        },
        {
          'has-flag': { version: '5.0.0' },
          'supports-color': {
            version: '9.0.1',
            requires: { 'has-flag': '^5.0.0' }
          },
          'supports-hyperlinks': {
            version: '2.2.0',
            requires: {
              'has-flag': '^4.0.0',
              'supports-color': '^7.0.0'
            },
            dependencies: {
              'has-flag': { version: '4.0.0' },
              'supports-color': {
                version: '7.2.0',
                requires: { 'has-flag': '^4.0.0' }
              }
            }
          }
        }
      );

      // We have 'has-flag' and 'supports-color' as dependencies along with v2 of
      // 'supports-hyperlinks', which also requires 'has-flag' and 'supports-color'.
      // Finally, 'supports-color' also requires 'has-flag'.
      //
      // The versions of 'has-flag' & 'supports-color' specified by us are not
      // compatible with the versions required by 'supports-hyperlinks', so they
      // must be nested within 'supports-hyperlinks' on the tree (since our direct
      // dependencies have to placed at the top of the tree).
      //
      // The version of `has-flag` specified by `supports-hyperlinks` & the version
      // of `supports-color` that it requires is compatible with both packages.
      //
      // This means that we only need *two* instances of `has-flag` in the tree,
      // with the second version sitting "next" to the nested `supports-color`,
      // and that that version is *not* the same version as the `has-flag` instance
      // that sits at the top level of the dependency tree
      await expect(
        determineVulnerablePackages(
          [{ ...advisory, name: 'has-flag' }],
          'my-dir'
        )
      ).resolves.toStrictEqual({
        1: [
          ['has-flag', '5.0.0'],
          ['supports-color>has-flag', '5.0.0'],
          ['supports-hyperlinks>has-flag', '4.0.0'],
          ['supports-hyperlinks>supports-color>has-flag', '4.0.0']
        ]
      });
    });

    it('supports aliases', async () => {
      await writePackageJsonAndLock(
        'my-dir',
        { dependencies: { myp: 'npm:mkdirp@^0.5.0' } },
        {
          minimist: { version: '0.0.8' },
          myp: {
            version: 'npm:mkdirp@0.5.0',
            requires: { minimist: '0.0.8' }
          }
        }
      );

      await expect(
        determineVulnerablePackages(
          [
            {
              source: 1179,
              name: 'minimist',
              dependency: 'minimist',
              title: 'Prototype Pollution',
              url: 'https://npmjs.com/advisories/1179',
              severity: 'low',
              range: '<0.2.1 || >=1.0.0 <1.2.3'
            }
          ],
          'my-dir'
        )
      ).resolves.toStrictEqual({
        1179: [['myp>minimist', '0.0.8']]
      });
    });

    it('supports different types of dependencies', async () => {
      await writePackageJsonAndLock(
        'my-dir',
        {
          optionalDependencies: { a: '^1.0.0' },
          peerDependencies: { c: '^1.0.0' }
        },
        {
          a: {
            version: '1.0.0',
            requires: { b: '^1.0.0', c: '^1.0.0', d: '^1.0.0' }
          },
          b: { version: '1.0.0' },
          c: { version: '1.0.0' },
          d: { version: '1.0.0' }
        }
      );

      await expect(
        determineVulnerablePackages(
          [
            { ...advisory, name: 'b', source: 1 },
            { ...advisory, name: 'c', source: 2 },
            { ...advisory, name: 'd', source: 3 }
          ],
          'my-dir'
        )
      ).resolves.toStrictEqual({
        1: [['a>b', '1.0.0']],
        2: [
          ['a>c', '1.0.0'],
          ['c', '1.0.0']
        ],
        3: [['a>d', '1.0.0']]
      });
    });

    it('handles basic semver ranges', async () => {
      await writePackageJsonAndLock(
        'my-dir',
        {
          dependencies: {
            a: '^1.0.0',
            c: '^1.0.0'
          }
        },
        {
          a: { version: '1.0.0', requires: { b: '^1.0.0' } },
          b: { version: '1.0.4' },
          c: {
            version: '1.0.1',
            requires: { b: '^2.0.0' },
            dependencies: {
              b: { version: '2.3.0' }
            }
          }
        }
      );

      await expect(
        determineVulnerablePackages(
          [{ ...advisory, name: 'b', range: '^1.0.2' }],
          'my-dir'
        )
      ).resolves.toStrictEqual({
        1: [['a>b', '1.0.4']]
      });
    });

    it('handles complex semver ranges', async () => {
      await writePackageJsonAndLock(
        'my-dir',
        {
          dependencies: {
            a: '^1.0.0',
            c: '^1.0.0',
            d: '^1.1.0',
            e: '^2.0.0'
          }
        },
        {
          a: {
            version: '1.0.0',
            requires: { b: '^1.0.0' }
          },
          b: { version: '1.0.4' },
          c: {
            version: '1.0.1',
            requires: { b: '^2.0.0' },
            dependencies: {
              b: { version: '2.3.0' }
            }
          },
          d: {
            version: '1.2.1',
            requires: { b: '^2.0.0', c: '^1.0.0' },
            dependencies: {
              b: { version: '2.3.1' },
              c: { version: '1.0.1', requires: { b: '^2.0.0' } }
            }
          },
          e: {
            version: '2.5.8',
            requires: { b: '^3.0.0', c: '^2.0.4' },
            dependencies: {
              b: { version: '3.1.0' },
              c: {
                version: '2.0.5',
                requires: { b: '^3.0.0' }
              }
            }
          }
        }
      );

      await expect(
        determineVulnerablePackages(
          [{ ...advisory, name: 'b', range: '<1.0.5 || >=2.0.0 <2.3.1' }],
          'my-dir'
        )
      ).resolves.toStrictEqual({
        1: [
          ['a>b', '1.0.4'],
          ['c>b', '2.3.0']
        ]
      });
    });

    it('handles different ranges for different dependencies', async () => {
      await writePackageJsonAndLock(
        'my-dir',
        {
          dependencies: {
            a: '^1.0.0',
            c: '^1.0.0',
            d: '^1.1.0',
            e: '^2.0.0'
          }
        },
        {
          a: {
            version: '1.0.0',
            requires: { b: '^1.0.0' }
          },
          b: { version: '1.0.4' },
          c: {
            version: '1.0.1',
            requires: { b: '^2.0.0' },
            dependencies: {
              b: { version: '2.3.0' }
            }
          },
          d: {
            version: '1.2.1',
            requires: { b: '^2.0.0', c: '^1.0.0' },
            dependencies: {
              b: { version: '2.3.1' },
              c: { version: '1.0.1', requires: { b: '^2.0.0' } }
            }
          },
          e: {
            version: '2.5.8',
            requires: { b: '^3.0.0', c: '^2.0.4' },
            dependencies: {
              b: { version: '3.1.0' },
              c: {
                version: '2.0.5',
                requires: { b: '^3.0.0' }
              }
            }
          }
        }
      );

      await expect(
        determineVulnerablePackages(
          [
            {
              ...advisory,
              source: 1,
              name: 'b',
              range: '<1.0.5 || >=2.0.0 <2.3.1'
            },
            { ...advisory, source: 2, name: 'c', range: '>= 2.0.0' },
            { ...advisory, source: 3, name: 'e', range: '< 0.5.0' }
          ],
          'my-dir'
        )
      ).resolves.toStrictEqual({
        1: [
          ['a>b', '1.0.4'],
          ['c>b', '2.3.0']
        ],
        2: [['e>c', '2.0.5']],
        3: []
      });
    });
  });
});