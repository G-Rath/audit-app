# [Unreleased](https://github.com/G-Rath/audit-app/compare/v0.5.2...HEAD) (YYYY-MM-DD)

### Bug fixes

- support dependencies with multiple vulnerabilities when using `npm` v7
  ([#10][])

# [0.5.2](https://github.com/G-Rath/audit-app/compare/v0.5.1...v0.5.2) (2021-02-24)

### Bug fixes

- use `wrap-ansi` for wrapping text when formatting tables ([191652d8][])

# [0.5.1](https://github.com/G-Rath/audit-app/compare/v0.5.0...v0.5.1) (2021-02-15)

### Bug fixes

- update pattern for `ignore` paths in config schema ([70ced7f9][])

# [0.5.0](https://github.com/G-Rath/audit-app/compare/v0.4.3...v0.5.0) (2021-02-15)

This version dramatically changes the audit report created by `audit-app` in
order to support NPM 7.

In addition to changing the JSON structure outputted by `--output json`, the
format of ignore paths has also changed meaning any existing ignores will need
to be updated.

### Features

- initial support for NPM 7 ([2e10def0][])

# [0.4.3](https://github.com/G-Rath/audit-app/compare/v0.4.2...v0.4.3) (2021-01-06)

### Bug fixes

- update schema to be valid in strict mode ([d5c5fd0e][])

# [0.4.2](https://github.com/G-Rath/audit-app/compare/v0.4.1...v0.4.2) (2020-09-26)

### Bug fixes

- replace use of `flatMap` to support lower versions of node ([86083810][])

# [0.4.1](https://github.com/G-Rath/audit-app/compare/v0.4.0...v0.4.1) (2020-09-20)

### Bug fixes

- listen for `end` event instead of `close` to work on Node <14 ([90ae6214][])

# [0.4.0](https://github.com/G-Rath/audit-app/compare/v0.3.1...v0.4.0) (2020-09-19)

### Features

- exit with error code if report includes missing vulnerabilities ([9a143e24][])
- mention any missing ignored vulnerabilities in summary ([15e9398b][])

# [0.3.1](https://github.com/G-Rath/audit-app/compare/v0.3.0...v0.3.1) (2020-09-19)

### Bug Fixes

- adjust imports to slightly reduce package size ([3dcd1f6d][])
- use singular or plural form for words based on related counts ([7f3c0c9c][])

# [0.3.0](https://github.com/G-Rath/audit-app/compare/v0.2.0...v0.3.0) (2020-09-18)

### Features

- publish `config.schema.json` to use to valid config files ([bfda8ade][])

### Bug Fixes

- ignore `$schema` property if present in config file ([f898766e][])

# [0.2.0](https://github.com/G-Rath/audit-app/compare/v0.1.1...v0.2.0) (2020-09-13)

### Features

- expand `statistics` object in audit report to include more details
  ([79e6ef0d][])

# [0.1.1](https://github.com/G-Rath/audit-app/compare/v0.1.0...v0.1.1) (2020-08-03)

### Bug Fixes

- add `types` property to `package.json` ([e977130b][])

# [0.1.0](https://github.com/G-Rath/audit-app/compare/82aa09aaf47ee736ddc030ee0418ffe40e191adf...v0.1.0) (2020-08-02)

Initial Release 🎉

[#10]: https://github.com/G-Rath/audit-app/pull/10
[191652d8]: https://github.com/G-Rath/audit-app/commit/191652d8
[70ced7f9]: https://github.com/G-Rath/audit-app/commit/70ced7f9
[2e10def0]: https://github.com/G-Rath/audit-app/commit/2e10def0
[d5c5fd0e]: https://github.com/G-Rath/audit-app/commit/d5c5fd0e
[86083810]: https://github.com/G-Rath/audit-app/commit/86083810
[90ae6214]: https://github.com/G-Rath/audit-app/commit/90ae6214
[9a143e24]: https://github.com/G-Rath/audit-app/commit/9a143e24
[15e9398b]: https://github.com/G-Rath/audit-app/commit/15e9398b
[3dcd1f6d]: https://github.com/G-Rath/audit-app/commit/3dcd1f6d
[7f3c0c9c]: https://github.com/G-Rath/audit-app/commit/7f3c0c9c
[bfda8ade]: https://github.com/G-Rath/audit-app/commit/bfda8ade
[f898766e]: https://github.com/G-Rath/audit-app/commit/f898766e
[79e6ef0d]: https://github.com/G-Rath/audit-app/commit/79e6ef0d
[e977130b]: https://github.com/G-Rath/audit-app/commit/e977130b
