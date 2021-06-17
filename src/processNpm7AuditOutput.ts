import { AuditResults, toMapOfFindings } from './audit';
import { determineVulnerablePackages } from './determineVulnerablePackages';
import {
  Finding,
  Npm7Advisory,
  Npm7AuditMetadata,
  Npm7AuditOutput,
  Npm7Vulnerability,
  Statistics
} from './types';

type DependencyStatistics = Statistics['dependencies'];

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

const transpose = (
  arr: Array<[a: string, b: string]>
): [a: string[], b: string[]] => {
  const result: [a: string[], b: string[]] = [[], []];

  for (const [a, b] of arr) {
    result[0].push(a);
    result[1].push(b);
  }

  return result;
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
        const [paths, versions] = transpose(vulnerablePackages[via.source]);

        return buildFinding(via, paths, versions);
      })
    ),
    dependencyStatistics: extractDependencyStatistics(auditOutput.metadata)
  };
};
