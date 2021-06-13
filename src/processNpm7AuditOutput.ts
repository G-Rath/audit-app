import { spawn } from 'child_process';
import ReadlineTransform from 'readline-transform';
import { satisfies } from 'semver';
import { AuditResults, toMapOfFindings } from './audit';
import {
  Finding,
  Npm7Advisory,
  Npm7AuditMetadata,
  Npm7AuditOutput,
  Npm7Vulnerability,
  Statistics
} from './types';

type DependencyStatistics = Statistics['dependencies'];

interface NpmListResult {
  name: string;
  version: string;
  dependencies: Record<string, NpmDependency>;
}

interface NpmDependency {
  version: string;
  from: string;
  resolved: string;
  dependencies?: Record<string, NpmDependency>;
}

interface NpmError {
  error: {
    code: string;
    summary: string;
    detail: string;
  };
}

type ParsedNpmListOutput = NpmListResult | NpmError;

type NameAndRange = [name: string, range: string];

/**
 * Collects the results of calling `npm list` in the given `dir`
 *
 * @param {NameAndRange[]} packages
 * @param {string} dir
 *
 * @return {Promise<Record<string, NpmDependency>>}
 */
const collectNpmListResults = async (packages: NameAndRange[], dir: string) => {
  console.log('listing...');
  const stdout = spawn(
    '/home/g-rath/my-npm',
    [
      'ls',
      `--prefix`,
      '.',
      '--json',
      // '--all'
      ...packages.map(([name, range]) => `${name}@${range}`)
    ],
    {
      cwd: dir
    }
  ).stdout.pipe(new ReadlineTransform({ skipEmpty: true }));
  let json = '';

  for await (const line of stdout) {
    json += line;
  }

  if (json.trim().startsWith('ERROR')) {
    console.log(json);

    throw new Error(json);
  }

  const listOutput = JSON.parse(json) as ParsedNpmListOutput;

  if ('error' in listOutput) {
    const errorMessage = `${listOutput.error.code}: ${listOutput.error.summary}`;

    console.log(errorMessage);

    throw new Error(errorMessage);
  }

  return listOutput.dependencies;
};

/**
 * Walks the given dependency tree, calling `onWalk` at every node
 *
 * @param {NpmListResult["dependencies"]} tree
 * @param {(dependency: string, path: string, version: string) => void} onWalk
 *
 * @param {string} path
 */
const walkDependencyTree = (
  tree: NpmListResult['dependencies'],
  onWalk: (dependency: string, path: string, version: string) => void,
  path = ''
) => {
  let currentPath = path;

  for (const [name, dependency] of Object.entries(tree)) {
    if (currentPath.length) {
      currentPath += '>';
    }

    currentPath += name;
    // currentPath += `${name}>`;

    onWalk(name, currentPath, dependency.version);

    if (dependency.dependencies) {
      walkDependencyTree(dependency.dependencies, onWalk, currentPath);
    }

    currentPath = path;
  }
};

/**
 * Calculates the vulnerability paths for the given npm 7 `advisories` by using
 * the dependency tree provided by `npm list`.
 *
 * @param {Array<Npm7Advisory>} advisories
 * @param {string} dir
 *
 * @return {Promise<Record<number, Array<string>>>}
 */
const calculateVulnerabilityPaths = async (
  advisories: Npm7Advisory[],
  dir: string
): Promise<Record<number, string[] | undefined>> => {
  const packages = Object.values(advisories).map<NameAndRange>(
    ({ name, range }) => [name, range]
  );

  const dependenciesList = await collectNpmListResults(packages, dir);

  const results: Record<number, string[]> = {};

  walkDependencyTree(dependenciesList, (dependency, path, version) => {
    const relevantAdvisories = advisories.filter(
      value => value.name === dependency && satisfies(version, value.range)
    );

    relevantAdvisories.forEach(advisory => {
      results[advisory.source] ||= [];
      results[advisory.source].push(path);
    });
  });

  return results;
};

/**
 * Extracts the dependency statistics from the auditing metadata provided by
 * `npm` v7
 *
 * @param {Npm7AuditMetadata} metadata
 *
 * @return {DependencyStatistics}
 */
const extractDependencyStatistics = (
  metadata: Npm7AuditMetadata
): DependencyStatistics => ({
  dependencies: metadata.dependencies.prod,
  devDependencies: metadata.dependencies.dev,
  optionalDependencies: metadata.dependencies.optional,
  totalDependencies: metadata.dependencies.total
});

/**
 * Builds a `fining` from an `npm` v7 `advisory`
 *
 * @param {Npm7Advisory} advisory
 * @param {Array<string>} paths
 * @param versions
 *
 * @return {Finding}
 */
const buildFinding = (
  advisory: Npm7Advisory,
  paths: string[],
  versions: string[]
): Finding => ({
  id: advisory.source,
  name: advisory.name,
  paths,
  versions,
  range: advisory.range,
  severity: advisory.severity,
  title: advisory.title,
  url: advisory.url
});

/**
 * Finds all the advisories that are included with the given record of
 * `vulnerabilities` provided by the audit output of `npm` v7.
 *
 * @param {Record<string, Npm7Vulnerability>} vulnerabilities
 *
 * @return {Array<Npm7Advisory>}
 */
const findAdvisories = (
  vulnerabilities: Record<string, Npm7Vulnerability>
): Npm7Advisory[] => {
  return Object.values(vulnerabilities)
    .reduce<Array<Npm7Advisory | string>>((all, { via }) => all.concat(via), [])
    .filter((via): via is Npm7Advisory => typeof via === 'object');
};

/**
 * Processes the given audit output provided by the `audit` command of `npm` v7,
 * normalizing it into audit results.
 *
 * @param {Npm7AuditOutput} auditOutput
 * @param {string} dir
 *
 * @return {Promise<AuditResults>}
 */
export const processNpm7AuditOutput = async (
  auditOutput: Npm7AuditOutput,
  dir: string
): Promise<AuditResults> => {
  const advisories = findAdvisories(auditOutput.vulnerabilities);
  const vulnerablePackages = await determineVulnerablePackages(advisories, dir);

  return {
    findings: toMapOfFindings(
      advisories.map(via => {
        return buildFinding(
          via,
          vulnerablePackages[via.source]?.[0] ?? [`???>${via.name}`],
          vulnerablePackages[via.source]?.[1] ?? []
        );
      })
    ),
    dependencyStatistics: extractDependencyStatistics(auditOutput.metadata)
  };
};
