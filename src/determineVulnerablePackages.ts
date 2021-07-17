import { promises as fs } from 'fs';
import { satisfies } from 'semver';
import {
  Npm7Advisory,
  NpmLockDependency,
  NpmPackageLock,
  PackageJson
} from './types';

type PathAndVersion = [path: string, version: string];

interface NpmLockDependencyBeingLinked {
  version: string;
  requires?: Record<string, string>;
  dependencies?: Record<string, NpmLockDependency>;
  nodes?: Record<string, NpmLockDependencyBeingLinked>;
  parent?: NpmLockDependencyBeingLinked;
}

interface NpmLockDependencyWithLinks {
  version: string;
  requires?: Record<string, string>;
  dependencies?: Record<string, NpmLockDependency>;
  nodes: Record<string, NpmLockDependencyWithLinks>;
  parent: NpmLockDependencyWithLinks | PackageLockWithLinks;
}

interface NpmLockDependencyWithLinksAndPaths
  extends NpmLockDependencyWithLinks {
  paths?: PathAndVersion[];
}

interface PackageLockWithLinks {
  version: string;
  dependencies: Record<string, NpmLockDependencyWithLinks>;
}

/**
 * Resolves the dependency's `name` to it's position on the dependency tree
 */
const resolveDependency = (
  name: string,
  parent: NpmLockDependencyBeingLinked
): NpmLockDependencyBeingLinked => {
  if (parent.dependencies && name in parent.dependencies) {
    return parent.dependencies[name];
  }

  if (!parent.parent) {
    throw new Error(
      `Could not find parent dependency for ${name} - ensure your package-lock.json is valid and matches your package.json`
    );
  }

  return resolveDependency(name, parent.parent);
};

/**
 * Links the given `dependency` with the related packages in the dependency tree
 */
const linkDependency = (
  dependency: NpmLockDependencyBeingLinked,
  parent: NpmLockDependencyBeingLinked
) => {
  dependency.parent = parent;
  dependency.nodes = {};

  if (!dependency.requires) {
    return; // nothing to do
  }

  for (const name of Object.keys(dependency.requires)) {
    dependency.nodes[name] = resolveDependency(name, dependency);
  }

  if (dependency.dependencies) {
    linkDependencies(dependency.dependencies, dependency);
  }
};

/**
 * Links the given `dependencies` with related packages in the dependency tree
 */
const linkDependencies = (
  dependencies: Record<string, NpmLockDependencyBeingLinked>,
  parent: NpmLockDependencyBeingLinked
) => {
  for (const dependency of Object.values(dependencies)) {
    linkDependency(dependency, parent);
  }
};

/**
 * Links the given `lock` so that all the dependencies in its tree are linked
 * to each other
 */
function linkLock(lock: NpmPackageLock): asserts lock is PackageLockWithLinks {
  linkDependencies(lock.dependencies, lock);
}

const listTopLevelDependencies = (
  json: PackageJson,
  lock: PackageLockWithLinks
): string[] => {
  const topLevelDependencies = {
    ...json.dependencies,
    ...json.devDependencies,
    ...json.optionalDependencies,
    ...json.peerDependencies
  };

  // account for workspaces, which will be `file:` dependencies that are not in
  // the `package.json` as a top-level dependency
  for (const [name, { version, parent }] of Object.entries(lock.dependencies)) {
    if (version.startsWith('file:') && parent === lock) {
      topLevelDependencies[name] = version;
    }
  }

  return Object.keys(topLevelDependencies);
};

const collectDependencyPaths = (
  name: string,
  dependency: NpmLockDependencyWithLinksAndPaths
): PathAndVersion[] => {
  if (dependency.paths) {
    return dependency.paths;
  }

  dependency.paths = [[name, dependency.version]];

  for (const node of Object.entries(dependency.nodes)) {
    for (const [path, version] of collectDependencyPaths(...node)) {
      dependency.paths.push([`${name}>${path}`, version]);
    }
  }

  return dependency.paths;
};

const flattenLockToPaths = (
  lock: PackageLockWithLinks,
  json: PackageJson
): PathAndVersion[] => {
  return listTopLevelDependencies(json, lock).reduce<PathAndVersion[]>(
    (ps, name) => {
      if (!(name in lock.dependencies)) {
        throw new Error(
          `Could not find top-level dependency ${name} - ensure your package-lock.json is valid and matches your package.json`
        );
      }

      return ps.concat(collectDependencyPaths(name, lock.dependencies[name]));
    },
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

const isVulnerable = (
  advisory: Npm7Advisory,
  [path, version]: PathAndVersion
): boolean => {
  return (
    (path === advisory.name || path.endsWith(`>${advisory.name}`)) &&
    satisfies(version, advisory.range)
  );
};

const mapPathsToAdvisories = (
  packagePaths: PathAndVersion[],
  advisories: Npm7Advisory[]
): Record<number, PathAndVersion[]> => {
  const results: Record<number, PathAndVersion[]> = {};

  for (const advisory of advisories) {
    results[advisory.source] = packagePaths.filter(info =>
      isVulnerable(advisory, info)
    );
  }

  return results;
};

/**
 * Determines which packages are vulnerable to the given advisories by walking
 * the dependency tree laid out by the `package.json` & `package-lock.json` at
 * the given `dir` and comparing the name & version of each package to the name
 * and range described in each advisory.
 *
 * @return map of advisories to the packages that they impact
 */
export const determineVulnerablePackages = async (
  advisories: Npm7Advisory[],
  dir: string
): Promise<Record<number, PathAndVersion[]>> => {
  const packagePaths = await determinePackagePaths(dir);

  return mapPathsToAdvisories(packagePaths, advisories);
};
