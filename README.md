# audit-app

A cli tool for auditing apps & packages using their respective package managers,
outputting the results in a form that makes it easy to triage advisories, and
providing support for ignoring advisories to keep your CI passing without having
to sacrifice security.

# NPM 7 workspaces

Workspaces (which are new in `npm@7`) should be supported at about the same
level as `npm audit` itself supports them; standard dependencies should be just
fine, but there may be edge-cases with `file:` dependencies due to limitations
in resolving the dependency tree for these types of dependencies which affect
`npm` itself.

For `audit-app`, these edge-cases _should_ primarily manifest as some
vulnerabilities technically being reported twice, which shouldn't prevent using
`audit-app`.

If you have any other issues with workspaces, please let us know!

Also note that if you have a `file:` dependency that has the same name as a
published `npm` package (e.g. `debug`), `npm` will assume it is that published
package and so mark it affected by any advisories that may exist for the
dependencies version.

# Getting Started

To run `audit-app` as a once-off against an app, you can use `npx`:

    npx audit-app

If you want to use `audit-app` regularly as part of your local development flow,
you can install it globally:

    npm install --global audit-app

## Options

All options can be provided in either camelCase or kebab-case format. These
options can be set either when calling `audit-app` via the commandline, or via a
JSON config file.

## `--directory`, `--dir`, `-d`

Default: the current working directory

Sets the directory that `audit-app` will operate in. This effects other path
related options like `--package-manager` and `--config`.

    audit-app --package-manager pnpm

### `--config`, `-c`

Default: `.auditapprc.json`

Points `audit-app` to the configuration file to load options from. By default
`audit-app` will look for a file called `.auditapprc.json` in the directory that
is being audited (which can be set using `--directory`).

The configuration file must contain standard JSON, with a top-level object, and
with no comments, trailing commas, or single-quotes:

```json
{
  "packageManager": "yarn",
  "ignore": ["1179|mkdirp>minimist"]
}
```

You can disable loading from a config file using `--no-config.`

## `--package-manager`, `-p`

Default: `auto`  
Supported values: `auto`, `npm`, `yarn`, `pnpm`

Sets the package manager `audit-app` will use to perform the audit. If set to
`auto`, the package manager will be determined based on what lock files are
present in the directory being audited.

## `--output`, `-o`

Default: `tables`  
Supported values: `tables`, `summary`, `paths`, `json`

Sets the format that `audit-app` should use to output the audit report. Here's a
brief rundown of the supported formats, and their use-cases:

### `summary` format

Outputs the report as a summary of the vulnerabilities that were found in the
audited app, containing details on the number of instances of packages that have
vulnerabilities, how many packages were checked, how many vulnerabilities were
ignored, and a breakdown of the number of vulnerabilities per severity.

Some of these numbers are based on values provided by the underlying package
manager that was used to perform the audit, so the numbers might not match with
what you'd expect depending on the beliefs and implementations of the package
manager in use.

### `tables` format

Outputs the report as a collection of concise tables along with a summary of the
report, similar to the output of `npm audit`.

Unlike `npm audit` however, the tables are per _advisory_ rather than per
_finding path_, making the output a lot easier to manage when dealing with
advisories for popular packages that might appear a number of times in your
dependency tree (i.e `lodash`).

Building the tables based on the advisories also means that ignored paths are
not factored in to the table output. The number of paths for an advisory does
not factor into if it will be outputted as a table, be it vulnerable, ignored or
missing paths.

Here is an example of the output the `tables` format results in:

```
┌────────────┬────────────────────────────────────────────────────────────────────┐
│ low        │ Prototype Pollution (#1523)                                        │
├────────────┼────────────────────────────────────────────────────────────────────┤
│ Package    │ lodash v4.17.15, v3.10.1                                           │
├────────────┼────────────────────────────────────────────────────────────────────┤
│ Patched in │ >=4.17.19                                                          │
├────────────┼────────────────────────────────────────────────────────────────────┤
│ More info  │ https://npmjs.com/advisories/1523                                  │
└────────────┴────────────────────────────────────────────────────────────────────┘


 found 4327 vulnerabilities (including 0 ignored) across 693 packages
	  \: 4327 low
```

Information on the package the advisory pertains to, such as if the package is a
dev dependency, the path(s) to the package, and what top-level package(s) lead
to the affected package being included in the tree, are deliberately omitted as
this information is typically very verbose and unhelpful at time of output.

Usually the easiest way to do this is by using your apps package manager with
the appropriate command(s) for listing details of packages in the dependency
tree that meet a given semver constraint.

For example, if the app that produced the table output above was using `npm`,
you could get a tree showing what dependencies pulled in the affected versions
of lodash with the following:

    npm ls 'lodash@4.17.15||3.10.1'

Similarly, you could get a tree showing what, if any, versions of lodash existed
in the tree that are patched by using the "Patched in" value:

    npm ls 'lodash@>=4.17.19'

### `paths` format

Outputs a list of paths mapping each instance of an advisory to the top-level
package which results in them being pulled in, in the format
`<advisory-id>|<dependency-path>`.

Since the list is sourced from the reports `vulnerable` array rather than its
`advisories` object, it won't include vulnerabilities that have been ignored.

This allows you to easily update your `ignore` lists, as you can copy and paste
items from the list directly into the config.

This becomes even more powerful when combined with standard commandline
utilities such as `grep` & clipboard utilities.

On Mac OS X you can use `pbcopy`, and for Windows you can use `clip.exe`. Linux
has a few different clipboards, such as `xclip`, `gpm`, and `screen`:

```shell script
audit-app --output paths | pbcopy # on OSX
audit-app --output paths | clip   # on Windows (including WSL)
```

Note that for Windows, `clip` works in both PowerShell & Windows System for
Linux.

Filtering can be done using `grep`:

```shell script
audit-app --output paths | grep '>@commitlint/load>' | clip
```

You can `grep`-like filtering in PowerShell using `findstr`:

```powershell
audit-app --output paths | findstr '>@commitlint/load>' | clip
```

Clipboard contents:

> 1523|@commitlint/cli>@commitlint/load>@commitlint/resolve-extends>lodash\
> 1523|@commitlint/cli>@commitlint/load>lodash

If you're using a json config, you can use `jq` to convert the output into a
valid JSON array that you can paste straight into your config:

```shell script
audit-app --output paths | grep '>@commitlint/load>' | jq -nR '[inputs]'
```

You can do this in PowerShell like so:

```powershell
(audit-app --output paths).split('\n') | ConvertTo-Json
```

### `json` format

Outputs the report as JSON using `JSON.stringify` so that it can be easily used
by other tools.

If you're ignoring vulnerabilities using a json config, you can pipe the output
of the json format to a program like `jq` to pick the `vulnerable` array

If you have a lot of vulnerabilities that you wish to ignore, you can pipe the
json output to a program like `jq` to select just the `vulnerable` array and get
a valid json array as output for your clipboard:

```shell script
audit-app --format json | jq '.vulnerable'
```

If you wish to select only some vulnerabilities, you can use filters like so:

```shell script
audit-app --format json | jq '.vulnerable | map(select(startswith("1556")))'
audit-app --format json | jq '.vulnerable | map(select(startswith("1556")))'
```

If you're using Powershell, you can do this without `jq` like so:

```powershell
(audit-app --format json | ConvertFrom-Json).vulnerable | ConvertTo-Json
```

## `--ignore`, `-i`

Default: []

Tells `audit-app` to ignore a vulnerability when determining if the audit
results should result in a failed audit run.

In the context of `audit-app`, a "vulnerability" is an instance of an advisory,
represented by a string made up of the advisory's id, and the path to the
package on the dependency tree that is affected by the advisory, separated by a
pipe (`|`); for example:

    1179|mkdirp>minimist

You can provide this flag multiple times to ignore multiple vulnerabilities:

```shell script
audit-app \
  --ignore '1213|@commitlint/cli>@commitlint/lint>@commitlint/parse>conventional-changelog-angular>compare-func>dot-prop' \
  --ignore '1213|@commitlint/config-conventional>conventional-changelog-conventionalcommits>compare-func>dot-prop' \
  --ignore '1213|semantic-release>@semantic-release/commit-analyzer>conventional-changelog-angular>compare-func>dot-prop' \
  --ignore '1213|semantic-release>@semantic-release/release-notes-generator>conventional-changelog-angular>compare-func>dot-prop' \
  --ignore '1213|semantic-release>@semantic-release/release-notes-generator>conventional-changelog-writer>compare-func>dot-prop' \
  --ignore '1213|semantic-release>@semantic-release/npm>npm>libnpx>update-notifier>configstore>dot-prop' \
  --ignore '1213|semantic-release>@semantic-release/npm>npm>update-notifier>configstore>dot-prop'
```

However, we recommend using an `.auditapprc.json` file to make it easier to
track and update the list of ignored vulnerabilities:

```json
{
  "packageManager": "yarn",
  "ignore": [
    "1213|@commitlint/cli>@commitlint/lint>@commitlint/parse>conventional-changelog-angular>compare-func>dot-prop",
    "1213|@commitlint/config-conventional>conventional-changelog-conventionalcommits>compare-func>dot-prop",
    "1213|semantic-release>@semantic-release/commit-analyzer>conventional-changelog-angular>compare-func>dot-prop",
    "1213|semantic-release>@semantic-release/release-notes-generator>conventional-changelog-angular>compare-func>dot-prop",
    "1213|semantic-release>@semantic-release/release-notes-generator>conventional-changelog-writer>compare-func>dot-prop",
    "1213|semantic-release>@semantic-release/npm>npm>libnpx>update-notifier>configstore>dot-prop",
    "1213|semantic-release>@semantic-release/npm>npm>update-notifier>configstore>dot-prop"
  ]
}
```

## How it works

When run, `audit-app` calls the audit command of either `npm`, `yarn`, or
`pnpm`, and parses the results, normalising the output into an "audit report".

An audit report is an object with the following structure:

```ts
export interface AuditReport {
  statistics: Statistics;
  advisories: Advisories;
  vulnerable: string[];
  ignored: string[];
  missing: string[];
}
```

The `statistics` property holds an object that contains optional details about
aspects of the auditing run, and it's results, such as counts on the different
package types that were involved (total, dev, optional, etc).

The `advisories` property is an object containing the advisories that were found
to effect at least one package in the tree during auditing, mapped by their id.

The `vulnerable`, `ignored`, and `missing` properties are arrays which list the
vulnerabilities that were (or in the case of `missing`, were not) found, based
on the findings for each advisory.

In the context of `audit-app`, a "vulnerability" is an instance of an advisory,
represented by a string made up of the advisory's id, and the path to the
package on the dependency tree that is affected by the advisory, separated by a
pipe (`|`).

After auditing has finished, `audit-app` runs through the findings of each
advisory to create a list of the vulnerabilities that exist in the app that was
just audited, which is then cross-referenced with a list of vulnerabilities that
should be ignored, with any vulnerability found in both lists being removed from
`vulnerable`. If a vulnerability is found in `ignored` that is not in
`vulnerable`, it's moved out of the `ignored` array into `missing`.

The ignored list is populated using the `ignore` flag, which can be specified
multiple times:

```
audit-app \
  --ignore 1179|mkdirp>minimist
```

There is no support for ignoring an entire advisory, because doing so would mean
new instances of an advisory could be introduced via an unknown path. For the
same reason you also cannot ignore all advisories of a specific level.

While its possible that a very popular package could get an advisory posted
against it that goes unpatch for a long period, resulting in a very large ignore
list, there are two things to keep in mind:

1. Your configuration file represents the security health of your application -
   the fewer vulnerabilities you need to ignore, the healthier your application
   is. This also means you should apply the same way of thinking as you would to
   aspects such as size, dependency count, performance, etc.

2. Advisories are _known_ vulnerabilities, meaning bad actors can find out
   exactly how to exploit a package with very little work.

Ultimately, in the same way that you'd consider replacing a dependency that was
creating a bottleneck for your application, or a dependency that was excessively
large, you should consider replacing a dependency if it's making your app less
secure.

The `paths` output format (detailed above) can be useful in updating your
ignores list by providing a list of all the current vulnerabilities in your apps
dependency tree that can be copied & pasted.
