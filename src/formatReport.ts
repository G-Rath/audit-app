import chalk from 'chalk';
import stripAnsi from 'strip-ansi';
import { AuditReport } from './generateReport';
import { Advisory, Severity, SeverityCounts } from './types';

type FalsyValue = null | undefined | 0 | false | '';

const pad = (str: string): string => ` ${str.trim()} `;

export const wrap = (str: string, width: number): string => {
  const regexp = new RegExp(
    `.{1,${width}}(?:[\\s\u200B]+|$)|[^\\s\u200B]+?(?:[\\s\u200B]+|$)`,
    'gu'
  );
  // eslint-disable-next-line @typescript-eslint/prefer-regexp-exec
  const result: string[] = str.match(regexp) ?? [];

  return result
    .map(l => (l.endsWith('\n') ? l.slice(0, l.length - 1) : l))
    .join('\n');
};

const f = <T>(...vs: Array<T | FalsyValue>): T[] =>
  vs.filter((v): v is T => !!v);

// const l = (...segments: Array<string | FalsyValue>): string =>
//   f(segments).join(' ');

const countSeverities = (report: AuditReport): Record<Severity, number> =>
  Object.values(report.advisories).reduce(
    (counts, advisory) => {
      counts[advisory.severity] += advisory.findings.reduce(
        (sum, findings) => sum + findings.paths.length,
        0
      );

      return counts;
    },
    { info: 0, low: 0, moderate: 0, high: 0, critical: 0 }
  );

enum BoxChar {
  LightVertical = '│',
  LightVerticalAndLeft = '┤',
  VerticalSingleAndLeftDouble = '╡',
  VerticalDoubleAndLeftSingle = '╢',
  DownDoubleAndLeftSingle = '╖',
  DownSingleAndLeftDouble = '╕',
  DoubleVerticalAndLeft = '╣',
  DoubleVertical = '║',
  DoubleDownAndLeft = '╗',
  DoubleUpAndLeft = '╝',
  UpDoubleAndLeftSingle = '╜',
  UpSingleAndLeftDouble = '╛',
  LightDownAndLeft = '┐',
  LightUpAndRight = '└',
  LightUpAndHorizontal = '┴',
  LightDownAndHorizontal = '┬',
  LightVerticalAndRight = '├',
  LightHorizontal = '─',
  LightVerticalAndHorizontal = '┼',
  VerticalSingleAndRightDoube = '╞',
  VerticalDoubleAndRightSingle = '╟',
  DoubleUpAndRight = '╚',
  DoubleDownAndRight = '╔',
  DoubleUpAndHorizontal = '╩',
  DoubleDownAndHorizontal = '╦',
  DoubleVerticalAndRight = '╠',
  DoubleHorizontal = '═',
  DoubleVerticalAndHorizontal = '╬',
  UpSingleAndHorizontalDouble = '╧',
  UpDoubleAndHorizontalSingle = '╨',
  DownSingleAndHorizontalDouble = '╤',
  DownDoubleAndHorizontalSingle = '╥',
  UpDoubleAndRightSingle = '╙',
  UpSingleAndRightDouble = '╘',
  DownSingleAndRightDouble = '╒',
  DownDoubleAndRightSingle = '╓',
  VerticalDoubleAndHorizontalSingle = '╫',
  VerticalSingleAndHorizontalDouble = '╪',
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
  rows: string[]
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

const countStr = (str: string): number => stripAnsi(str).length;

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
    .map(([label]) => pad(stripAnsi(label)))
    .reduce((width, { length }) => (length > width ? length : width), 0);

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
      const lines = wrap(pad(value), maxValueWidth).split('\n');

      return f(
        index && rowSpacer,
        ...lines.map((v, i) =>
          createRow(
            [maxLabelWidth, i === 0 ? pad(label) : ''],
            [maxValueWidth, pad(v)]
          ).join('')
        )
      );
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

const buildAdvisoryTable = (advisory: Advisory, _report: AuditReport): string =>
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
  (Object.keys(severities).reverse() as Array<keyof SeverityCounts>).find(
    severity => severities[severity] > 0
  ) ?? 'info';

const sortAdvisories = (advisories: Advisory[]): Advisory[] =>
  advisories.sort(
    (a, b) =>
      a.module_name.localeCompare(b.module_name) ||
      Severities.indexOf(b.severity) - Severities.indexOf(a.severity)
  );

export const formatReport = (report: AuditReport): string => {
  const severities = countSeverities(report);
  const {
    advisories, //
    vulnerable: { length: vulnerabilities },
    statistics
  } = report;
  /*
    - how many packages were audited?
      - ("x dev")
    - how long did it take to audit them?
    - how many advisories?
      - "+x that were ignored"
      - "x <severity> (+y ignored)"

   - "found x vulnerabilities affecting y packages"
 */

  const lines: string[] = [
    ...sortAdvisories(Object.values(advisories)).flatMap(advisory => [
      buildAdvisoryTable(advisory, report),
      '\n'
    ])
  ].concat(
    f(
      [
        '', // leading space
        `found ${severityColors[getHighestSeverity(severities)](
          vulnerabilities
        )} vulnerabilities`,
        `(including ${report.ignored.length} ignored)`,
        `across ${statistics.totalDependencies ?? '"some"'} packages`
      ],
      vulnerabilities && [
        '\t  \\:',
        (Object.entries(severities) as Array<[Severity, number]>)
          .filter(([, count]) => count > 0)
          .map(([severity, c]) => `${c} ${severityColors[severity](severity)}`)
          .join(', ')
      ]
    ).map(arr => arr.join(' '))
  );

  return lines.join('\n');
};
