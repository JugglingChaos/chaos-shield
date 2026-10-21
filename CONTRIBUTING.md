# Working on Chaos Shield

## Checks

Every pull request runs the Checks workflow: WordPress coding standards and PHP 7.4+
compatibility (`composer install && vendor/bin/phpcs`), a syntax check on PHP 7.4 to 8.4,
and the integration tests on a fresh single site and multisite (see `tests/README.md`).
Merge only when it is green.

## Releasing

1. In one pull request, raise the version in `chaos-shield.php` (the `Version:` header
   and `CSHIELD_VERSION`) and the `Stable tag:` in `readme.txt`, and add a `= x.y.z =`
   changelog entry to `readme.txt`. Merge it once the checks pass.
2. On GitHub, open Actions > Release > Run workflow on `main`. (Pushing a tag such as
   `v1.13.0` does the same.)

The workflow runs the checks again, refuses to release if the versions disagree, builds
`chaos-shield-x.y.z.zip` with `bin/build-zip.sh` and publishes a GitHub release with the
changelog entry as its notes. Sites running Chaos Shield then offer the update in
Dashboard > Updates within six hours.
