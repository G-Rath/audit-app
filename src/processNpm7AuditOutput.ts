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
 *
 * @return {Finding}
 */
const buildFinding = (advisory: Npm7Advisory): Finding => ({
  id: advisory.source,
  name: advisory.name,
  paths: [advisory.dependency],
  versions: [],
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
 *
 * @return {AuditResults}
 */
export const processNpm7AuditOutput = (
  auditOutput: Npm7AuditOutput
): AuditResults => {
  const advisories = findAdvisories(auditOutput.vulnerabilities);

  return {
    findings: toMapOfFindings(advisories.map(via => buildFinding(via))),
    dependencyStatistics: extractDependencyStatistics(auditOutput.metadata)
  };
};
