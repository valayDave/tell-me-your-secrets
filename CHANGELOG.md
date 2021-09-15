# Changelog

## v2.4.0 (2021-09-15)

### Added

-   Added support for more Slack token formats

### Improved

-   Changes yaml loading to use the safe loader (#48)
 (#51)

###  Fixed

-   Fix `MANIFEST.in` (#52)
-   Fix output of unique rule names + tidy `setup.py` (#53)

## v2.3.0 (2021-04-22)

### Added

-   Added `--version` flag to print current version (#43)
-   Added support for the new GitHub authentication token format (#45)

## v2.2.1 (2021-03-11)

### Fixed

-   Fixed regression with saving results object (#40)

## v2.2.0 (2021-03-05)

### Added

-   Improved processing to use multiprocessing (#35)

### Improved

-   Return all signature matches within a file (#37)

### Fixed

-   Fixed bug with gitignore flag and non-existent `.gitignore` file (#35)

## v2.1.1 (2020-12-28)

### Fixed

-   Fixed bug with matching refactoring + prevent bug on missing config key (#33)

## v2.1.0 (2020-12-24)

### Added

-   Added whitelisted string functionality (#31)
-   Added dependabot configuration (#30)
-   Added Python 3.9 to test matrix (#28)

## v2.0.0 (2020-10-01)

# Improved

-   Improved config print -- now dynamic (#11)
-   Added new rules from shhgit (#17)

# Breaking

-   Dropped support for Python 3.4 and 3.5 - it was broken before, but now it's explicit

## v1.78 (2020-08-11)

Before semantic versioning.
