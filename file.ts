import { inspect } from 'util';

interface NpmLockDependency {
  version: string;
  requires?: Record<string, string>;
  dependencies?: Record<string, NpmLockDependency>;
}

interface LockDepWithLinks {
  version: string;
  requires?: Record<string, string>;
  dependencies?: Record<string, NpmLockDependency>;
  nodes?: Record<string, LockDepWithLinks>;
  parent?: LockDepWithLinks;
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
  for (const [name, dependency] of Object.entries(dependencies)) {
    console.log(`linking ${name}`);
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

/*
  if (dependency.paths) {
    console.log('cache hit');
    return dependency.paths;
  }

  dependency.paths = [`${name}@${dependency.version}`];

  if (!dependency.nodes) {
    return dependency.paths;
  }

  for (const [nodeName, nodeDependency] of Object.entries(dependency.nodes)) {
    const subPaths = collectDependencyPaths(nodeName, nodeDependency);

    dependency.paths.push(...subPaths);
  }

  return dependency.paths;
 */
const collectDependencyPaths = (
  name: string,
  dependency: LockDepWithLinks
): string[] => {
  if (dependency.paths) {
    return dependency.paths;
  }

  dependency.paths = [`${name}@${dependency.version}`];

  if (!dependency.nodes) {
    return dependency.paths;
  }

  for (const [nodeName, nodeDependency] of Object.entries(dependency.nodes)) {
    dependency.paths.push(
      ...collectDependencyPaths(nodeName, nodeDependency).map(
        p => `${name}>${p}`
      )
    );
  }

  return dependency.paths;
};

const flattenLockToPaths = (lock: PackageLockWithLinks, json: PackageJson) => {
  const topLevelDependencies = listTopLevelDependencies(json);

  const paths = topLevelDependencies.reduce<string[]>(
    (ps, name) =>
      ps.concat(collectDependencyPaths(name, lock.dependencies[name])),
    []
  );

  console.log(paths.join('\n'));
};

const packageJson: PackageJson = {
  dependencies: {
    a: '^1.0.0',
    c: '^1.0.0',
    d: '^1.1.0',
    e: '^2.0.0'
  }
};

const packageLock: PackageLock = {
  version: '1.0.0',
  dependencies: {
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
        b: { version: '2.3.0' },
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
};

linkLock(packageLock);
// console.log(inspect(packageLock, { colors: true, depth: Infinity }));
console.log('flattening packages...');
flattenLockToPaths(packageLock, packageJson);
