import { promises as fs } from 'fs';
import { Npm7Advisory } from './types';

interface NpmLockDependency {
  version: string;
  requires?: Record<string, string>;
  dependencies?: Record<string, NpmLockDependency>;
}

type PathAndVersion = [path: string, version: string];

interface NpmLockDependencyWithLinks {
  version: string;
  requires?: Record<string, string>;
  dependencies?: Record<string, NpmLockDependency>;
  nodes?: Record<string, NpmLockDependencyWithLinks>;
  parent?: NpmLockDependencyWithLinks;
  paths?: PathAndVersion[];
}

interface NpmPackageLock {
  version: string;
  dependencies: Record<string, NpmLockDependency>;
}

interface PackageLockWithLinks {
  version: string;
  dependencies: Record<string, NpmLockDependencyWithLinks>;
}

interface PackageJson {
  name?: string;
  version?: string;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
}

/**
 * Resolves the dependency's `name` to it's position on the dependency tree
 *
 * @param {string} name
 * @param {NpmLockDependencyWithLinks} parent
 *
 * @return {NpmLockDependencyWithLinks}
 */
const resolveDependency = (
  name: string,
  parent: NpmLockDependencyWithLinks
): NpmLockDependencyWithLinks => {
  if (parent.dependencies && name in parent.dependencies) {
    return parent.dependencies[name];
  }

  if (parent.nodes && name in parent.nodes) {
    return parent.nodes[name];
  }

  if (!parent.parent) {
    throw new Error(`${name} does not have a parent`);
  }

  return resolveDependency(name, parent.parent);
};

/**
 * Links the given `dependency` with the related packages in the dependency tree
 *
 * @param {NpmLockDependencyWithLinks} dependency
 * @param {NpmLockDependencyWithLinks} parent
 */
const linkDependency = (
  dependency: NpmLockDependencyWithLinks,
  parent: NpmLockDependencyWithLinks
) => {
  dependency.parent = parent;

  if (!dependency.requires) {
    return; // nothing to do
  }

  if (!dependency.nodes) {
    dependency.nodes = {};

    for (const name of Object.keys(dependency.requires)) {
      if (name in dependency.nodes) {
        console.warn(`${name} is already in nodes`);
      }

      dependency.nodes[name] = resolveDependency(name, dependency);
    }
  }

  if (dependency.dependencies) {
    linkDependencies(dependency.dependencies, dependency);
  }
};

/**
 * Links the given `dependencies` with related packages in the dependency tree
 *
 * @param {Record<string, NpmLockDependencyWithLinks>} dependencies
 * @param {NpmLockDependencyWithLinks} parent
 */
const linkDependencies = (
  dependencies: Record<string, NpmLockDependencyWithLinks>,
  parent: NpmLockDependencyWithLinks
) => {
  for (const dependency of Object.values(dependencies)) {
    linkDependency(dependency, parent);
  }
};

/**
 * Links the given `lock` so that all the dependencies in it's tree are linked
 * to each other
 *
 * @param {NpmPackageLock} lock
 *
 * @return {asserts lock is PackageLockWithLinks}
 */
function linkLock(lock: NpmPackageLock): asserts lock is PackageLockWithLinks {
  linkDependencies(lock.dependencies, lock);
}

const listTopLevelDependencies = (json: PackageJson): string[] => {
  return Object.keys({
    ...json.dependencies,
    ...json.devDependencies,
    ...json.optionalDependencies,
    ...json.peerDependencies
  });
};

const collectDependencyPaths = (
  name: string,
  dependency: NpmLockDependencyWithLinks
): PathAndVersion[] => {
  if (dependency.paths) {
    return dependency.paths;
  }

  dependency.paths = [[name, dependency.version]];

  if (!dependency.nodes) {
    return dependency.paths;
  }

  for (const node of Object.entries(dependency.nodes)) {
    for (const [[path, version]] of collectDependencyPaths(...node)) {
      dependency.paths.push([`${name}>${path}`, version]);
    }
  }

  return dependency.paths;
};

const flattenLockToPaths = (
  lock: PackageLockWithLinks,
  json: PackageJson
): PathAndVersion[] => {
  return listTopLevelDependencies(json).reduce<PathAndVersion[]>(
    (ps, name) =>
      ps.concat(collectDependencyPaths(name, lock.dependencies[name])),
    []
  );
};

const readPackageJson = async (dir: string): Promise<PackageJson> => {
  return JSON.parse(
    await fs.readFile(`${dir}/package.json`, 'utf-8')
  ) as PackageJson;
};

const readPackageLockJson = async (dir: string): Promise<NpmPackageLock> => {
  return JSON.parse(
    await fs.readFile(`${dir}/package-lock.json`, 'utf-8')
  ) as NpmPackageLock;
};

const determinePackagePaths = async (dir: string) => {
  const packageLock = await readPackageLockJson(dir);
  const packageJson = await readPackageJson(dir);

  linkLock(packageLock);

  return flattenLockToPaths(packageLock, packageJson);
};

export const determineVulnerableNpmPackages = async (
  advisories: Npm7Advisory[],
  dir: string
): Promise<PathAndVersion[]> => {
  const packagePaths = await determinePackagePaths(dir);

  return packagePaths;
};
