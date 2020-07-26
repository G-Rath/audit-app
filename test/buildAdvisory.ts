import { Advisory } from '../src/types';

export const buildAdvisory = (advisory: Partial<Advisory>): Advisory => ({
  findings: [
    {
      version: '10.1.0',
      paths: ['@commitlint/cli>meow>yargs-parser']
    },
    {
      version: '9.0.2',
      paths: [
        'semantic-release>@semantic-release/npm>npm>libnpx>yargs>yargs-parser'
      ]
    }
  ],
  id: 1500,
  created: '2020-03-26T19:21:50.174Z',
  updated: '2020-05-01T01:05:15.020Z',
  deleted: null,
  title: 'Prototype Pollution',
  found_by: { link: '', name: 'Snyk Security Team', email: '' },
  reported_by: { link: '', name: 'Snyk Security Team', email: '' },
  module_name: 'yargs-parser',
  cves: [],
  vulnerable_versions: '',
  patched_versions: '',
  overview: '',
  recommendation: '',
  references: '',
  access: 'public',
  severity: 'low',
  cwe: 'CWE-471',
  metadata: { module_type: '', exploitability: 1, affected_components: '' },
  url: 'https://npmjs.com/advisories/1500',
  ...advisory
});
