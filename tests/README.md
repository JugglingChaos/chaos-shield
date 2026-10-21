# Chaos Shield tests

Integration tests that drive a real WordPress site over HTTP: login limits, two-factor,
firewall and bans, the threat feed and country database, the malware scan, SIEM detections,
the hub API signatures, and escaping on the admin screens.

**Use a disposable test site only.** The tests create users, ban IPs and plant a harmless
file that looks like a web shell (all removed at the end), and they need a must-use helper
that lets a request choose its IP.

    tests/run.sh /path/to/test/wordpress

The site must answer at its home URL, use plain or pretty permalinks, and have Chaos
Shield active. The run exits with 1 if anything fails. The `tests` folder is not part of
release zips.

## Fresh test sites

`tests/ci/setup.sh` builds a disposable single site on port 8080 and a multisite with two
extra sites on port 8081, installs the mocks from `tests/fixtures/mocks` (they answer the
outside services locally) and starts both with PHP's built-in server. It needs WP-CLI,
a MySQL or MariaDB server and the `mysql` client; see the script for its settings. This is
what the Checks workflow on GitHub runs for every pull request:

    tests/ci/setup.sh
    tests/run.sh /tmp/cshield-sites/single
    WP="wp --url=http://localhost:8081" tests/run.sh /tmp/cshield-sites/multi
