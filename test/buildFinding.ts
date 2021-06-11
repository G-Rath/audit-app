import { Finding } from '../src/types';

export const buildFinding = (finding: Partial<Finding>): Finding => ({
  id: 1500,
  name: 'yargs-parser',
  paths: [`${finding.id ?? 1500}|${finding.name ?? 'yargs-parser'}`],
  versions: ['9.0.2', '10.1.0'],
  range: '<13.1.2 || >=14.0.0 <15.0.1 || >=16.0.0 <18.1.2',
  severity: 'low',
  title: 'Prototype Pollution',
  url: `https://npmjs.com/advisories/${finding.id ?? 1}`,
  ...finding
});
