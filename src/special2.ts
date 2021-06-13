import { promises as fs } from 'fs';

interface NpmLockDependency {
  version: string;
  requires?: Record<string, string>;
  dependencies?: Record<string, NpmLockDependency>;
}

type PathAndVersion = [path: string, version: string];

interface LockDepWithLinks {
  version: string;
  requires?: Record<string, string>;
  dependencies?: Record<string, NpmLockDependency>;
  nodes?: Record<string, LockDepWithLinks>;
  parent?: LockDepWithLinks;
  paths?: PathAndVersion[];
}

interface PackageLock {
  version: string;
  dependencies: Record<string, NpmLockDependency>;
}

interface PackageLockWithLinks {
  version: string;
  dependencies: Record<string, LockDepWithLinks>;
}

interface NpmLockPackage {
  version: string;
  resolved: string;
  integrity?: string;
  dev?: boolean;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
}

interface PackageLockfileV2 {
  name: string;
  version: string;
  lockfileVersion: 2;
  requires: boolean;
  packages: Record<string, NpmLockPackage> & { '': PackageJson };
  dependencies: Record<string, NpmLockDependency>;
}

interface PackageJson {
  name?: string;
  version?: string;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
}

const resolveDependency = (
  name: string,
  parent: LockDepWithLinks,
  top: PackageLock
): LockDepWithLinks => {
  console.log(`resolving ${name}`);

  if (parent.dependencies && name in parent.dependencies) {
    return parent.dependencies[name];
  }

  if (parent.nodes && name in parent.nodes) {
    return parent.nodes[name];
  }

  if (!parent.parent) {
    throw new Error(`${name} does not have a parent`);
  }

  return resolveDependency(name, parent.parent, top);
};

const linkDependency = (
  dependency: LockDepWithLinks,
  parent: LockDepWithLinks,
  top: PackageLock
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
      dependency.nodes[name] = resolveDependency(name, dependency, top);
    }
  }

  if (dependency.dependencies) {
    linkDependencies(dependency.dependencies, dependency, top);
  }
};

const linkDependencies = (
  dependencies: Record<string, LockDepWithLinks>,
  parent: LockDepWithLinks,
  top: PackageLock
) => {
  for (const dependency of Object.values(dependencies)) {
    linkDependency(dependency, parent, top);
  }
};

function linkLock(lock: PackageLock): asserts lock is PackageLockWithLinks {
  linkDependencies(lock.dependencies, lock, lock);
}

const listTopLevelDependencies = (json: PackageJson): string[] => {
  return Object.keys({
    ...json.dependencies,
    ...json.devDependencies,
    ...json.optionalDependencies,
    ...json.peerDependencies
  });
};

const findTopLevelDependencies = (lock: PackageLockWithLinks) => {
  return Object.keys(lock.dependencies).filter(
    k => lock.dependencies[k].parent === lock
  );
};

const collectDependencyPaths = (
  name: string,
  dependency: LockDepWithLinks
): PathAndVersion[] => {
  if (dependency.paths) {
    return dependency.paths;
  }

  // dependency.paths = [`${name}@${dependency.version}`];
  dependency.paths = [[name, dependency.version]];

  if (!dependency.nodes) {
    return dependency.paths;
  }

  for (const [nodeName, nodeDependency] of Object.entries(dependency.nodes)) {
    dependency.paths.push(
      ...collectDependencyPaths(nodeName, nodeDependency).map<PathAndVersion>(
        ([path, version]) => [`${name}>${path}`, version]
      )
    );
  }

  return dependency.paths;
};

const flattenLockToPaths = (lock: PackageLockWithLinks, json: PackageJson) => {
  const topLevelDependencies = listTopLevelDependencies(json);

  const paths = topLevelDependencies.reduce<PathAndVersion[]>(
    (ps, name) =>
      ps.concat(collectDependencyPaths(name, lock.dependencies[name])),
    []
  );

  console.log(paths.map(p => p.join('@')).join('\n'));
  console.log(paths.length, 'vs', new Set(paths).size);
};

const readPackageJson = async (dir: string): Promise<PackageJson> => {
  return JSON.parse(
    await fs.readFile(`${dir}/package.json`, 'utf-8')
  ) as PackageJson;
};

const readPackageLockJson = async (dir: string): Promise<PackageLockfileV2> => {
  return JSON.parse(
    await fs.readFile(`${dir}/package-lock.json`, 'utf-8')
  ) as PackageLockfileV2;
};

export const special2 = async (dir: string): Promise<void> => {
  const packageLock = await readPackageLockJson(dir);
  const packageJson = await readPackageJson(dir);

  linkLock(packageLock);

  console.log('flattening packages...');
  flattenLockToPaths(packageLock, packageJson);
};
