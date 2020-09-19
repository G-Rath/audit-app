import chalk from 'chalk';
import stripAnsi from 'strip-ansi';
import { AuditReport } from './generateReport';
import { Advisory, Severity, SeverityCounts } from './types';

export const SupportedReportFormats = [
  'summary',
  'tables',
  'paths',
  'json'
] as const;

export type SupportedReportFormat = typeof SupportedReportFormats[number];

type ReportFormatter = (report: AuditReport) => string;

const PluralToSingularMap = {
  vulnerabilities: 'vulnerability',
  packages: 'package'
} as const;

type PluralizableWord = keyof typeof PluralToSingularMap;

const wordWithCount = (
  count: number | string,
  word: PluralizableWord,
  countColor?: chalk.ChalkFunction
) => {
  const countString = countColor?.(count) ?? count;
  const wordString = count === 1 ? PluralToSingularMap[word] : word;

  return `${countString} ${wordString}`;
};

const countStr = (str: string): number => stripAnsi(str).length;
const pad = (str: string): string => ` ${str.trim()} `;
const wrap = (str: string, width: number): string[] => {
  const regexp = new RegExp(
    `.{1,${width}}(?:[\\s\u200B]+|$)|[^\\s\u200B]+?(?:[\\s\u200B]+|$)`,
    'gu'
  );

  // eslint-disable-next-line @typescript-eslint/prefer-regexp-exec
  return str.match(regexp) ?? [];
};

enum BoxChar {
  LightVertical = '│',
  LightVerticalAndLeft = '┤',
  LightDownAndLeft = '┐',
  LightUpAndRight = '└',
  LightUpAndHorizontal = '┴',
  LightDownAndHorizontal = '┬',
  LightVerticalAndRight = '├',
  LightHorizontal = '─',
  LightVerticalAndHorizontal = '┼',
  LightUpAndLeft = '┘',
  LightDownAndRight = '┌'
}

const buildTableSpacer = (
  start: BoxChar,
  labelWidth: number,
  middle: BoxChar,
  valueWidth: number,
  end: BoxChar
): string =>
  chalk.grey(
    [
      start,
      BoxChar.LightHorizontal.repeat(labelWidth),
      middle,
      BoxChar.LightHorizontal.repeat(valueWidth),
      end
    ].join('')
  );

const warpInTopAndBottomBorders = (
  labelWidth: number,
  valueWidth: number,
  rows: readonly string[]
): string[] => [
  buildTableSpacer(
    BoxChar.LightDownAndRight,
    labelWidth,
    BoxChar.LightDownAndHorizontal,
    valueWidth,
    BoxChar.LightDownAndLeft
  ),
  ...rows,
  buildTableSpacer(
    BoxChar.LightUpAndRight,
    labelWidth,
    BoxChar.LightUpAndHorizontal,
    valueWidth,
    BoxChar.LightUpAndLeft
  )
];

const createRow = (
  [labelWidth, label]: [number, string],
  [valueWidth, value]: [number, string]
): string[] => [
  chalk.grey(BoxChar.LightVertical),
  label,
  ' '.repeat(labelWidth - countStr(label)),
  chalk.grey(BoxChar.LightVertical),
  value,
  ' '.repeat(valueWidth - countStr(value)),
  chalk.grey(BoxChar.LightVertical)
];

const buildTable = (
  contents: ReadonlyArray<[string, string]>,
  size = 80
): string[] => {
  const maxLabelWidth: number = contents
    .map(([label]) => countStr(pad(label)))
    .reduce((width, length) => (length > width ? length : width), 0);

  const maxValueWidth = size - maxLabelWidth;

  const rowSpacer = buildTableSpacer(
    BoxChar.LightVerticalAndRight,
    maxLabelWidth,
    BoxChar.LightVerticalAndHorizontal,
    maxValueWidth,
    BoxChar.LightVerticalAndLeft
  );

  return warpInTopAndBottomBorders(
    maxLabelWidth,
    maxValueWidth,
    contents.flatMap(([label, value], index) => {
      const lines = wrap(pad(value), maxValueWidth);

      return [
        index && rowSpacer,
        ...lines.map((v, i) =>
          createRow(
            [maxLabelWidth, i === 0 ? pad(label) : ''],
            [maxValueWidth, pad(v)]
          ).join('')
        )
      ].filter((s): s is string => typeof s === 'string');
    })
  );
};

const severityColors: Record<Severity, chalk.ChalkFunction> = {
  info: chalk.grey,
  low: chalk.whiteBright,
  moderate: chalk.yellow,
  high: chalk.red,
  critical: chalk.magenta
};

const Severities = Object.keys(severityColors) as Severity[];

const buildAdvisoryTable = (advisory: Advisory): string =>
  buildTable([
    [
      severityColors[advisory.severity](advisory.severity),
      chalk.whiteBright(`${advisory.title} (#${advisory.id})`)
    ],
    [
      'Package',
      `${advisory.module_name} ${Array.from(
        new Set(advisory.findings.map(finding => `v${finding.version}`))
      ).join(', ')}`
    ],
    ['Patched in', advisory.patched_versions],
    ['More info', advisory.url]
  ]).join('\n');

const getHighestSeverity = (severities: SeverityCounts): Severity =>
  (Object.keys(severityColors).reverse() as Array<keyof SeverityCounts>).find(
    severity => severities[severity] > 0
  ) ?? 'info';

const compareAdvisories = (a: Advisory, b: Advisory): number =>
  a.module_name.localeCompare(b.module_name) ||
  Severities.indexOf(b.severity) - Severities.indexOf(a.severity);

const buildReportTables = (report: AuditReport): string[] =>
  Object.values(report.advisories)
    .sort(compareAdvisories)
    .map(buildAdvisoryTable);

const buildReportSummary = (report: AuditReport): string[] => {
  const {
    statistics: {
      dependencies: { totalDependencies = '"some"' },
      severities,
      vulnerable,
      ignored
    }
  } = report;

  return [
    [
      '', // leading space
      `found ${wordWithCount(
        severities.total,
        'vulnerabilities',
        severityColors[getHighestSeverity(severities)]
      )}`,
      `(including ${ignored.total} ignored)`,
      `across ${wordWithCount(totalDependencies, 'packages')}`
    ],
    vulnerable.total && [
      '\t  \\:',
      Severities.filter(severity => vulnerable[severity] > 0)
        .map(
          severity =>
            `${vulnerable[severity]} ${severityColors[severity](severity)}`
        )
        .join(', ')
    ]
  ]
    .filter(Array.isArray)
    .map(arr => arr.join(' '));
};

const formatters: Record<SupportedReportFormat, ReportFormatter> = {
  json: JSON.stringify,
  paths: (report): string => report.vulnerable.join('\n'),
  summary: (report): string => buildReportSummary(report).join('\n'),
  tables: (report): string =>
    [
      ...buildReportTables(report), //
      ...buildReportSummary(report)
    ].join('\n')
};

export const formatReport = (
  format: SupportedReportFormat,
  report: AuditReport
): string => formatters[format](report);
