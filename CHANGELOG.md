# [Unreleased](https://github.com/G-Rath/audit-app/compare/v0.8.0...HEAD) (YYYY-MM-DD)

# [0.8.0](https://github.com/G-Rath/audit-app/compare/v0.7.0...v0.8.0) (2022-03-14)

This version changes audit findings to use the GHSA as the ID where possible,
which means existing ignores will be incorrect now - luckily this release also
adds a `--update-config-ignores` flag which can be used to automatically update
the `ignore` field in the config with all the vulnerabilities found by the
auditor!

The reason for this change is that the IDs have not been stable since the NPM
advisory was merged into the GitHub advisory database, so CIs often fail due to
ignores being "missing" and "new" vulnerabilities appearing.

This should resolve that, since the GHSA should be stable and present for all
findings with all package managers.

### Features

- use GHSA as ID to improve stability ([#19][])
- support updating ignore list in config file with `--update-config-ignores`
  flag ([#20][])

# [0.7.0](https://github.com/G-Rath/audit-app/compare/v0.6.0...v0.7.0) (2021-07-23)

This version greatly improves NPM 7 support, including restoring dependency
paths used for ignoring vulnerabilities to their full selves as they are with
`yarn` and NPM 6.

This also means workspaces (which are new in NPM 7) and `file:` dependencies are
supported properly - there are a few quirks, but these exist in NPM as well and
are a nature of using local file dependencies so cannot be easily avoided.

All vulnerabilities should be reported, but nested `file:` dependencies may be
listed both as nested & again as top-level dependencies.

### Features

- improve npm v7 support by walking the dependency tree ([b7694d8e][])

# [0.6.0](https://github.com/G-Rath/audit-app/compare/v0.5.3...v0.6.0) (2021-07-16)

### Features

- include vulnerable versions in findings when available ([#14][])
- sort the order of vulnerability paths when using the `paths` output ([#13][])

# [0.5.3](https://github.com/G-Rath/audit-app/compare/v0.5.2...v0.5.3) (2021-06-11)

### Bug fixes

- improve grammar of "missing ignored vulnerabilities" message ([#11][])
- make it more obvious that the "missing ignored vulnerabilities" message is an
  error rather than a warning ([#11][])
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

[#20]: https://github.com/G-Rath/audit-app/pull/20
[#19]: https://github.com/G-Rath/audit-app/pull/19
[#14]: https://github.com/G-Rath/audit-app/pull/14
[#13]: https://github.com/G-Rath/audit-app/pull/13
[#11]: https://github.com/G-Rath/audit-app/pull/11
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
