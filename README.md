# audit-app

A cli tool for auditing apps & packages using their respective package managers.

## Output formats

`audit-app` can output its report in a few different formats, depending on the
use-case for the current audit run.

You can specify which format to use with the `--output` flag, with the default
format being `tables`.

Here's a brief rundown of the supported formats, and their use-cases:

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
audit-app --output paths | clip # on Windows (including WSL)
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

### `json` format

Outputs the report as JSON using `JSON.stringify` so that it can be easily used
by other tools.
