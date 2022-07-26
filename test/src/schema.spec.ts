import Ajv, { ErrorObject } from 'ajv';
import schema from '../../config.schema.json';
import { Options as ParsedArgs } from '../../src';

const ajv = new Ajv();

const validate = (data: Partial<ParsedArgs>) => {
  ajv.validate(schema, data);

  return ajv.errors ?? [];
};

type TestCase = [data: Partial<ParsedArgs>, expectedErrors: ErrorObject[]];

describe('config schema', () => {
  it.each<string>([
    '|',
    '|@commitlint/cli>@commitlint/lint>@commitlint/rules>@commitlint/ensure',
    '|@commitlint/cli',
    '|meow>@commitlint/cli',
    '1|',
    '1|>',
    '1|a>',
    '1|a>b>',
    '1|a>>b>>c',
    '1|abc> asasdf1|df>asdf>'
  ])('fails "%s"', invalidPath => {
    const invalidPathError: ErrorObject = {
      keyword: 'pattern',
      instancePath: '/ignore/0',
      schemaPath: '#/properties/ignore/items/pattern',
      params: { pattern: expect.any(String) as string },
      message: expect.stringContaining('must match pattern') as string
    };

    expect(validate({ ignore: [invalidPath] })).toStrictEqual([
      invalidPathError
    ]);
  });

  it.each<string>([
    '1|a',
    '1|a>b',
    '1|a>b>c',
    '1|abc',
    '1|abc>a',
    '118|gulp>vinyl-fs>glob-stream>glob>minimatch',
    '813|css-loader>cssnano>postcss-svgo>svgo>js-yaml',
    '1084|webpack>yargs>os-locale>mem',
    '1500|webpack>yargs>yargs-parser',
    '1523|gulp>vinyl-fs>glob-watcher>gaze>globule>lodash',
    '534|ember-cli>testem>socket.io>socket.io-parser>debug',
    '577|ember-cli>ember-try>cli-table2>lodash',
    '577|ember-cli>ember-try>cli-table2',
    '577|cli-table2',
    '534|ember-cli>testem>socket.io>socket.io-parser',
    '534|socket.io>socket.io-parser',
    '534|socket.io-parser',
    '1523|@commitlint/cli>@commitlint/lint>@commitlint/rules>@commitlint/ensure',
    '1523|@commitlint/cli',
    '1523|meow>@commitlint/cli',
    'GHSA-566m-qj78-rww5|css-loader>cssnano>autoprefixer>postcss',
    'abc|gulp>vinyl-fs>glob-stream>glob>minimatch',
    'abc|ember-cli>testem>socket.io>socket.io-parser>debug',
    'abc|socket.io>socket.io-parser'
  ])('allows "%s"', validPath => {
    expect(validate({ ignore: [validPath] })).toStrictEqual([]);
  });

  // misc cases
  it.each<TestCase>([
    [
      // @ts-expect-error this is not a supported value
      { packageManager: 'invalid' },
      [
        {
          keyword: 'enum',
          instancePath: '/packageManager',
          schemaPath: '#/definitions/SupportedPackageManagerOrAuto/enum',
          params: { allowedValues: ['auto', 'npm', 'yarn', 'pnpm'] },
          message: 'must be equal to one of the allowed values'
        }
      ]
    ]
  ])('validates as expected', (data, expectedErrors) => {
    expect(validate(data)).toStrictEqual(expectedErrors);
  });
});
