=== Chaos Shield ===
Contributors: jugglingchaos
Tags: security, firewall, two-factor, audit log, malware scanner
Requires at least: 6.4
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 1.16.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Security for WordPress in one plugin: hardening, passkeys and two-factor, a firewall, malware scans, an activity log and alerts.

== Description ==

Chaos Shield gives you one dashboard for WordPress security, without slowing your site down and without accounts, keys or a second plugin.

**Hardening, one switch each**

Disable XML-RPC, the file editor and application passwords, hide the WordPress version, block username enumeration, send security headers, limit login attempts and use generic login errors.

**Login protection**

* Passkeys: sign in with a fingerprint, face or device PIN. Passkeys cannot be phished, and count as two-factor.
* Two-factor with any authenticator app, with recovery codes, trusted browsers and an admin reset. Require it, or a passkey, for administrators or all staff, with a grace period.
* Idle sign out, approval of new sign-ups, a warning for authors who publish under their username, and one-click replacement of the wp-config.php security keys.
* Breached passwords are refused, checked with Have I Been Pwned so only five characters of a hash leave your site.
* Comment spam blocking with a hidden field and a time check, no CAPTCHA needed. Bots that keep trying are banned.
* A secret login address, an optional Cloudflare Turnstile or hCaptcha check (also on comments, WooCommerce, Contact Form 7 and WPForms), and a list of signed-in administrator sessions you can end remotely.
* A password policy with optional expiry, and forced resets for one user, many, or all administrators.

**Firewall, bans and rate limits**

* A scoring firewall that decodes and checks every part of a request: the address, form and JSON fields, XML bodies, cookies, headers and upload names. Fourteen rules, from SQL and script injection to PHP object injection, XXE and SSRF, with three sensitivity levels and a 7 day learning mode.
* Blocked visitors see a reference you can look up, and you can let one request through with an exception for that page and field.
* Per-IP rate limits for logins, the REST API, AJAX and searches, and automatic bans for repeat offenders and bots probing for vulnerable files. Your own IP, the allow list and verified Google and Bing crawlers are never banned.
* IP allow and block lists with CIDR and IPv6, country blocking with a built-in country database, and the free Spamhaus DROP and Tor exit lists.
* One click stops PHP from running in the uploads folder.

**Scans and cleanup**

* Daily vulnerability alerts for WordPress, plugins and themes from WPVulnerability.net, with CVE, CVSS, the fixed version and an Update now button. Closed and abandoned plugins are flagged.
* Core, plugin and theme files compared with the official WordPress.org copies, with one-click repair checked against the official checksum.
* Hourly fingerprints of wp-config.php, .htaccess, drop-ins, must-use plugins and other files attackers change first, with line-by-line changes and secrets hidden.
* A malware scan of plugins, themes and uploads, and a database scan for injected scripts and links. Suspicious files can be quarantined where they cannot run.
* A check for backups, logs, .env, .git and API keys that anyone could download.

**Activity log, alerts and SIEM**

* Logs logins, lockouts, blocks, user and role changes, content and settings changes, updates and scans, with filters, CSV export and retention up to two years.
* Alerts by email or in Slack, Discord, Microsoft Teams or Google Chat, plus a weekly report.
* Twelve detection rules mapped to MITRE ATT&CK open incidents with evidence, severity, notes and an assignee. Respond from the incident: ban or block an IP, end sessions or force a password reset.
* Field search, IP and user timelines, live traffic with a world map, and log forwarding to a webhook or syslog for your own SIEM.
* A printable compliance report with the SOC 2 and ISO/IEC 27001 controls each protection supports.

**Edge protection**

* Under attack mode puts a one-second browser check in front of the site during a flood, and switches on by itself.
* A daily look at your pages lists every script they load and alerts you to new or harmful ones, with an optional Content Security Policy.
* HTTPS checks for the certificate, the redirect and mixed content, with safe switches to send visitors to HTTPS.
* Connect Cloudflare and banned IPs are refused at Cloudflare. A ban list address feeds any other firewall or CDN.

**Visitor help**

Blocked or locked-out visitors get a clear page with the reason, what to try and a small help assistant. They can message you even while banned, and you can let them in from the Visitor help tab. A help bubble can answer your own FAQ on every page, matched in the browser with no AI service.

**Backups and restore points**

A restore point is saved before plugin and theme updates, file repairs and settings changes, and one click puts it back. Download the database as SQL, and export settings to another site.

**Multisite and many sites**

Network activate it for one set of settings, one log and one ban list across the network. The hub shows the score, findings, uptime and certificate expiry of every site you connect, and can run scans, release bans and push settings to them.

**Security score**

A score from 0 to 100 with a plain explanation of what to fix, also shown in a dashboard widget.

== Installation ==

1. Search for Chaos Shield under Plugins > Add New, or upload the plugin zip from Plugins > Add New > Upload Plugin.
2. Activate it. Recommended protections switch on immediately.
3. Open Chaos Shield in the admin menu to see your score.

== Frequently Asked Questions ==

= Does it work on multisite? =

Yes, since 1.7. Network activate it: one set of settings and one log cover every site, managed from Network Admin. Activating it on a single site of a network is refused, because one site's firewall and login limits cannot protect a network that shares its users and files. Networks that ran 1.6 per site keep working and are asked to switch; on a network that was activated before 1.7, each site's log moves into the network log on update, and the network starts from the main site's settings.

= Can I roll back a plugin update? =

Yes, when restore points are on (they are by default). Open the Backups tab and restore the point taken before the update. Files come back exactly as they were, but changes the update made to the database stay, so test the result.

= I locked myself out. What now? =

Wait for the lockout to end, log in from another network, or rename the plugin folder over FTP or your host's file manager to switch it off. Add your own IP to the allow list to avoid this.

= Will it slow my site down? =

No. Hardening and the firewall are a few checks per request, and the file scan runs in small steps in the background.

= Does it send data anywhere? =

Nothing that identifies your site's users, unless you turn on log forwarding or connect a chat. Every outside service the plugin can contact, what it sends and when, is listed under External services below, and most of them can be switched off under Hardening. Help messages from visitors (name, email, message and IP) are stored on your site for 30 days and never sent anywhere except your own alert email or chat.

= Does it replace Cloudflare? =

No, it works alongside it. A plugin can only answer requests that reach your server, so a flood big enough to fill the server's connection, a worldwide cache and free certificates still need Cloudflare, another CDN or your host. Chaos Shield covers what a plugin can do (under attack mode, the script monitor, HTTPS and exposure checks) and, once connected, pushes its bans to Cloudflare so they are stopped at the edge. Other services can read the ban list address.

= Why do sign-ups open in a separate window? =

Cloudflare, hCaptcha, Slack and the other services do not allow their pages inside another site, so they cannot open within WordPress. Chaos Shield opens them in a small window next to the dashboard instead, keeps the steps and the paste boxes in WordPress, and checks the result before saving it. If your browser blocks the window, a link opens it in a new tab.

= Can I still sign in with my password after adding a passkey? =

Yes. The password and two-factor login keep working, so a lost phone never locks you out. Remove a lost device's passkey from your profile, or ask an administrator to remove it from yours.

= Can a blocked visitor reach me? =

Yes. The block page has a help assistant with a message form that works even for banned IPs, protected by a signed token, a hidden field and a limit of three messages an hour per IP. Messages land in the Visitor help tab and you are emailed; Allow lets that visitor back in. Switch the form off on the same tab if you prefer.

= Why does the all pages rate limit say it is not active? =

Counting every page view needs a persistent object cache such as Redis or Memcached, so ordinary hosting never pays a database write per visit. Login, API, AJAX and search limits work everywhere.

= Should I make passwords expire? =

Usually not. Current NIST guidance (SP 800-63B) recommends long passwords, breach screening and two-factor login instead of regular expiry, which is why expiry is off by default. Turn it on if a policy you must follow requires it.

= Is there a REST API? =

Routes live under `/wp-json/chaos-shield/v1/` (or `?rest_route=/chaos-shield/v1/` without pretty permalinks).

* Read: `GET /status`, `GET /events`, `GET /scan`, `GET /lockouts`. Accepts a logged-in administrator or a request signed with the hub key (`X-Chaos-Time`, `X-Chaos-Nonce`, `X-Chaos-Signature`), so the key itself never travels. The older `X-Chaos-Key` header still works.
* Write: `POST /scan`, `POST /scan/step`, `DELETE /lockouts/{ip}`, `POST /blocklist`, `GET` and `POST /settings`. Needs an administrator, for example with an application password. The hub key can never write.
* A wrong hub key counts as a failed login, so guessing gets the caller locked out.

= Does it work behind a proxy or CDN? =

By default Chaos Shield reads the visitor IP from REMOTE_ADDR, because forwarded headers can be faked. Under Access you can choose Cloudflare, X-Forwarded-For or X-Real-IP, and the header is only believed when the connection comes from a trusted proxy: by default a private network address, plus Cloudflare's published ranges for the Cloudflare header. List your proxy IPs if they are public. The dashboard warns you when requests arrive through a proxy that is not configured or not trusted.

= What happens to two-factor if my security keys change? =

Two-factor secrets are encrypted with your wp-config.php security keys. Replace the keys with the button on the Hardening tab and Chaos Shield seals every secret again, so nothing breaks. If the keys are changed by hand, users log in with a recovery code and set two-factor up again, or an administrator resets it from their profile.

= Is it tested? =

The plugin source (not the release zip) has an integration suite in `tests/` that drives a live test site over HTTP: logins, two-factor, the firewall, bans, the SIEM, the hub API, restore points, updates and the admin screens, plus network checks when the site is a multisite. Run `tests/run.sh /path/to/wordpress` on a throwaway site, never on production; `tests/ci/setup.sh` builds a fresh single site and multisite for it. On GitHub every pull request runs the coding standards, PHP 7.4 to 8.4 syntax checks and the whole suite on both kinds of site.

= Which filters can developers use? =

* `cshield_client_ip` - the client IP used for login limits.
* `cshield_security_headers` - the array of security headers sent.
* `cshield_critical_files` - the files whose fingerprints are watched, by name, with path, group, text (keep a copy to compare and put back) and appear (report the file appearing).
* `cshield_firewall_rules` - the firewall rules, keyed by id. Each has `label`, `info`, `pattern`, `score` (5 blocks, 3 adds up), `targets` (all, path, agent or file) and an optional `staff` flag to keep checking post content from authors and editors.
* `cshield_scan_signatures` - the malware signatures used by the file scan.
* `cshield_check_pages` - the page addresses the daily page check loads (up to 8).
* `cshield_exposure_paths` - the addresses asked for by the exposed files check, by id, with path and kind.
* `cshield_attack_mode` (action) - runs with true or false when under attack mode switches on or off.
* `cshield_update_repo` - the GitHub repository (owner/name) updates come from.

= How does it update? =

Installed from WordPress.org, Chaos Shield updates from there like any other plugin. The zip on GitHub (chaos-shield-x.y.z.zip on each release) updates from GitHub releases instead: the usual "update available" notice, one-click update, View details and automatic updates all work, sites check GitHub at most every six hours, and "Check again" on Dashboard > Updates asks straight away. To update from a private repository, add a fine-grained GitHub token with read-only access to its contents to wp-config.php as `define( 'CSHIELD_GITHUB_TOKEN', '...' );`. A fork can point updates at itself with `CSHIELD_UPDATE_REPO` or the `cshield_update_repo` filter.

== External services ==

Chaos Shield contacts these services. None of them is contacted for a feature that is switched off.

* **WordPress.org** (api.wordpress.org, downloads.wordpress.org, core.svn.wordpress.org, plugins.svn.wordpress.org, themes.svn.wordpress.org): the file scan fetches the official checksums of WordPress, your plugins and themes, and repair downloads the original copy of a changed file. Only slugs and version numbers are sent. [Privacy policy](https://wordpress.org/about/privacy/).
* **WPVulnerability** (www.wpvulnerability.net): once a day the vulnerability check sends the slug and version of each installed plugin and theme and your WordPress version. [Terms and privacy](https://www.wpvulnerability.com/privacy/).
* **Have I Been Pwned, Pwned Passwords** (api.pwnedpasswords.com): when someone sets a password, the breached password check sends the first five characters of its SHA-1 hash, never the password. [Terms](https://haveibeenpwned.com/TermsOfUse) and [privacy policy](https://haveibeenpwned.com/Privacy).
* **Spamhaus** (www.spamhaus.org): once a day the threat blocklist downloads the public DROP list. Nothing about your site is sent. [Terms](https://www.spamhaus.org/legal/) and [privacy policy](https://www.spamhaus.org/legal/privacy-policy/).
* **Tor Project** (check.torproject.org): when you choose to block Tor, the list of Tor exit addresses is downloaded once a day. Nothing about your site is sent. [Privacy policy](https://www.torproject.org/about/privacy/).
* **GitHub** (github.com, api.github.com): once a week the built-in country lookup downloads the public domain ip-location-db country lists from github.com. The copy of Chaos Shield from GitHub (not the WordPress.org one) also asks api.github.com for its latest release at most every six hours. Only your site's address is sent, in the user agent. [Terms](https://docs.github.com/en/site-policy/github-terms/github-terms-of-service) and [privacy policy](https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement).
* **Cloudflare Turnstile** (challenges.cloudflare.com): with Turnstile as the login CAPTCHA, its script loads on the login page (and on any comment, WooCommerce, Contact Form 7 or WPForms form you turn the check on for) and the token from each login is checked with Cloudflare, together with the visitor's IP. [Terms](https://www.cloudflare.com/website-terms/) and [privacy policy](https://www.cloudflare.com/privacypolicy/).
* **hCaptcha** (js.hcaptcha.com, api.hcaptcha.com): with hCaptcha as the login CAPTCHA, the same as Turnstile. [Terms](https://www.hcaptcha.com/terms) and [privacy policy](https://www.hcaptcha.com/privacy).
* **Cloudflare API** (api.cloudflare.com): only when you connect Cloudflare. Banned IPs, under attack mode changes, cache purges and the Always Use HTTPS switch are sent with your API token. [Terms](https://www.cloudflare.com/website-terms/) and [privacy policy](https://www.cloudflare.com/privacypolicy/).
* **Slack, Discord, Microsoft Teams and Google Chat** (hooks.slack.com, discord.com, your Teams or Power Automate webhook, chat.googleapis.com): only when you connect one. The text of each alert is sent to the channel you chose. [Slack](https://slack.com/trust/privacy/privacy-policy), [Discord](https://discord.com/privacy), [Microsoft](https://privacy.microsoft.com/privacystatement), [Google](https://policies.google.com/privacy).
* **Your own webhook or syslog server**: only when you turn on log forwarding. Events, including usernames and IPs, go to the address you enter.
* **Scripts your pages load**: the daily page check loads your own public pages and downloads the outside scripts they include, so those servers see your server's address.
* **Sites you connect to the hub**: the hub only contacts the sites you add to it.

== Changelog ==

= 1.16.0 =
Forms and spam.
* Comment spam blocking without a CAPTCHA: a hidden field and a signed time stamp stop bots, comments sent without the form go to spam, and a bot refused three times in a day is banned.
* The login CAPTCHA can also guard comments, WooCommerce login, sign-up and lost password, Contact Form 7 and WPForms.
* Login limits, two-factor and passkeys also cover the WooCommerce My Account login. bbPress and Elementor login forms post to the WordPress login, so they are covered too.

= 1.15.0 =
Accounts: everything All-In-One Security offers for logins, free.
* Require two-factor or a passkey for administrators or everyone who can write posts. Each account gets a grace period, then can only reach its profile until it adds one.
* Trusted browsers: a user can skip the code step on their own browser for up to 90 days. A new password forgets every trusted browser.
* Idle sign out after the minutes you choose, for administrators, staff or everyone. An open dashboard tab does not count as activity.
* Approve new sign-ups: accounts visitors make cannot log in until approved from the Users screen, with an email for each one.
* Security keys: replace the wp-config.php keys in one click, from the Hardening tab or a serious incident. Everyone is signed out and two-factor, the hub and connected services keep working.
* A new check warns about authors who publish under their username.

= 1.14.1 =
WordPress.org Plugin Check cleanup.
* The GitHub copy now links to the plugin's real home page, and the WordPress.org copy leaves out the GitHub updater.
* Translations load the way WordPress.org language packs expect, without an extra loader on every page.
* Notes on each database query, time limit, core sign-in hook and .htaccess edit say why it is safe, so Plugin Check no longer flags them.

= 1.14.0 =
Security fixes from a review of everything added in 1.7 to 1.13.
* Under attack mode: the query string can no longer make a page look like the REST API, a solved check buys one pass for one network only, one network can no longer switch the mode on alone, and the redirect after the check stays on this site.
* Visitor help: Allow no longer adds firewall exceptions by itself. The inbox shows which rule, field and page blocked the visitor, and a separate button lets that one request through, only for a block of the sender's own IP and never on the front page. One network can no longer fill the inbox.
* Firewall: exceptions made from a blocked request cover that exact page only. Bodies the REST API reads from PUT, PATCH and DELETE requests are inspected, long values are read in full, field names are checked, and more data than the firewall reads is refused instead of skipped.
* Restore points: restoring the oldest point while the list is full no longer deletes it halfway and writes empty files.
* Settings imports go through the same checks as the settings forms.
* Quarantined files are stored under random names that can neither run nor be downloaded, also on Nginx.
* Critical file fingerprints: a planned change can no longer hide one already waiting for review, sub-sites no longer mark .htaccess as expected, and every quoted value in a changed wp-config.php line is hidden.
* Browser reports from the script policy are never approved in bulk, are capped, and send one alert at a time.
* The daily page check's pass only works while a check runs, never travels over plain http or to another host, and other hosts are fetched the safe way.
* HTTPS redirects never loop behind a proxy, such as Cloudflare's Flexible mode, that already used HTTPS.
* CAPTCHA: oversized tokens are refused, and only a real outage lets logins through without the check.
* Forcing a password reset for a whole group needs network admin rights on a network, and skips users the admin cannot edit.

= 1.13.0 =
* Updates from GitHub: new releases show up as normal plugin updates with one-click and automatic updating, View details with the release notes, and support for private repositories through a token in wp-config.php.
* The new Update URI header tells WordPress.org to skip this plugin, so a different plugin with the same name there can never replace it.

= 1.12.0 =
* Renamed from Sentinel Shield to Chaos Shield, with a new folder, text domain and code prefixes. Settings from an earlier Sentinel Shield install do not carry over.
* New Edge tab: under attack mode with a one-second browser check that switches on by itself during a flood.
* Page script monitor with alerts for new, changed and harmful looking scripts, and a Content Security Policy in report-only or enforce mode.
* HTTPS checks for the certificate, the http redirect and mixed content, with safe switches to send visitors to HTTPS and upgrade mixed content.
* Exposed files and keys check for .env, .git, backups, dumps, logs and live API keys in your pages, with one-click .htaccess blocking.
* Cloudflare connection: bans are refused at Cloudflare, Under Attack mode follows yours, plus cache purge and Always Use HTTPS. A ban list address serves any other firewall or CDN.
* Fix: the server's own address can no longer be banned, and WP-CLI keeps working if it ever was.

= 1.11.0 =
* Visitor help: block, ban, country and rate-limit pages now explain what happened in plain words, show the reference and include a help assistant with built-in answers.
* Blocked visitors can message the site owner from the page, even while banned. Allow in the new Visitor help tab lifts the ban and lockout and lets the blocked request through.
* Sign-in help bubble on the login page, and an optional help bubble on every page that answers your own questions, with a title, greeting and colour.
* Answers are matched in the browser with no outside service. Scripts, the REST API and tools still get the short text answer.
* Fix: deactivating or removing the plugin now also clears pending ban and help alerts.

= 1.10.0 =
* Critical file fingerprints: wp-config.php, the server config files, drop-ins, must-use plugins, the theme's functions.php and key core files are checked every hour against an accepted SHA-256 and MD5 fingerprint.
* Changes alert you right away, show what changed line by line, and can be accepted or put back, with the replaced version saved as a restore point.
* New drop-ins and must-use plugins are reported the moment they appear.
* Download every fingerprint as JSON to keep a copy off the site.

= 1.9.0 =
* Connections: outside services now connect from a dialog in the dashboard. The service's sign-up page opens in a small window beside it, and the keys or webhook are checked before anything is saved.
* hCaptcha as a second login CAPTCHA, next to Cloudflare Turnstile. CAPTCHA keys are checked with a live test challenge, and connecting switches the CAPTCHA on.
* Alerts in Slack, Discord, Microsoft Teams and Google Chat, with a test button and the last delivery result. Alert text is escaped and mentions are switched off.
* Log forwarding to a Discord webhook now works.
* Secret keys and chat webhooks are stored encrypted and never shown again in full.

= 1.8.0 =
* New Firewall tab. The firewall now scores requests and checks every input, including POST and JSON bodies, cookies and upload names, with decoding that sees through URL, entity and comment tricks.
* New rules for PHP object injection, XXE, server-side request forgery, null bytes and PHP uploads.
* Learning mode, sensitivity levels and per-rule switches.
* Recent hits with references shown to blocked visitors, and one-click exceptions.
* Optional rule that stops PHP running in uploads.
* Fewer false positives on everyday text such as "select one from the menu" or code samples in posts.

= 1.7.0 =
* Multisite: network activate Chaos Shield to protect every site with one set of settings, one log, one ban list and one set of background jobs, managed from Network Admin. Lockouts and bans hold across the network. The log, SIEM search and CSV export name the site of each event. Site administrators can no longer see or change the plugin.
* New Backups tab with restore points taken before plugin and theme updates, file repairs and settings changes, restorable in one click and undoable.
* Download a compressed database backup.
* Export settings and import them on another site.
* Fixed: errors from quarantine and repair actions were not shown on the Scan tab.
* Upgrading a network that ran 1.6 network wide moves each site's log into the network log.

= 1.6.2 =
Security release after a full internal audit. Updating is recommended.

* Fixed: when a password reset was forced or a password had expired, signing in with the old password led straight to the reset form. Now Chaos Shield emails a reset link instead, so a leaked password alone cannot be used to set a new one.
* Fixed: the hub sent the site key with every request. It now signs requests with it, only connects over HTTPS or a private network, and does not follow redirects.
* Fixed: a proxy header with no trusted proxies listed was believed from anyone. It now only counts from private network proxies and Cloudflare's own ranges unless you list others.
* Fixed: "Allow only the listed countries" let in visitors whose country was unknown, for example by going around Cloudflare. They are now kept out, except private network visitors and while the built-in database downloads. Country headers anyone can send now only count from a trusted proxy.
* Fixed: adding a passkey now asks for the current password, so a stolen session cannot add a permanent way in.
* Fixed: another site could make its visitors' browsers load attack URLs here and get those visitors banned. Such requests are still blocked but no longer count toward a ban.
* Fixed: user enumeration blocking missed `/wp/v2/Users` and author lookups sent by POST.
* Fixed: a broken status reply from a connected site could stop the hub tab from loading.
* New integration test suite in the source repository (73 checks).

= 1.6.1 =
* Traffic map on the Live traffic tab: a world heatmap of requests, blocks or logins per country in the last 24 hours, with a top countries table. Click a country to filter the live traffic.
* Built-in country lookup: a free, public domain IP to country database is downloaded weekly (about 25 MB, no account or key) and searched locally. Nothing about your visitors leaves the site.
* Country rules can now use the built-in database instead of a Cloudflare or host header.

= 1.6.0 =
* New SIEM tab: twelve detection rules mapped to MITRE ATT&CK open incidents with evidence, severity and email alerts.
* Incidents work as cases with status, assignee and notes, and offer response actions: ban or block the IP, end sessions, force a password reset.
* IP and user timelines across the log, live traffic and incidents.
* Field search for the log (action:, ip:, user:, sev:, since:).
* Every logged event now carries an action code and a subject.
* The hub lists open incidents across all connected sites.

= 1.5.0 =
* Vulnerability alerts no longer need a Wordfence account or key: they now use the free WPVulnerability.net database and work as soon as the plugin is active. Severity, CVE and CVSS score are shown.
* Plugins and themes closed on WordPress.org or not updated in two years are flagged.
* Plugin and theme files are compared with the official WordPress.org release, and modified files can be repaired.
* The scan finds exposed backups, logs and secret files.
* Threat intelligence blocklist with Spamhaus DROP, and optional Tor exit node blocking.
* Live traffic tab with filters, live updates and one-click IP blocking.
* A stored Wordfence key from earlier versions is deleted on upgrade.

= 1.4.0 =
* Detailed audit trail of content, site settings, profile changes, logouts, failed logins and privacy requests, with a user column.
* Activity log filters by user, text, IP and date, and CSV export.
* Printable security and compliance report with SOC 2 and ISO 27001 references.
* Log forwarding to a webhook or syslog (UDP, TCP or local), with an HMAC signature and retries.
* Password policy, optional expiry, and forced password resets for one user, a selection or all administrators.
* Hub actions: start scans, release bans and push settings to connected sites, with signed one-time requests.
* Uptime and HTTPS certificate monitoring for connected sites, with email alerts.
* Log retention up to 730 days.

= 1.3.0 =
* Passkey login with fingerprint, face or device PIN, counted as two-factor.
* Rate limiting for login, XML-RPC, REST API, AJAX, search and (with an object cache) all pages, with bans for repeat offenders.
* Country blocking or allow-only rules for the login page or the whole site, from Cloudflare or host GeoIP headers.
* One-click repair of modified core files, verified against the official checksums.
* File quarantine with restore and delete.
* Database scan for injected scripts, iframes and eval code.

= 1.2.0 =
* Known vulnerability alerts from the Wordfence Intelligence feed, with one-click updates.
* Custom login address that hides wp-login.php and wp-admin.
* Cloudflare Turnstile CAPTCHA for login, lost password and registration.
* Signed-in administrator sessions with remote sign out.

= 1.1.0 =
* Automatic bans for repeat lockouts, firewall trips and 404 probing bots, with a Banned IPs list.
* File change watch for plugins and themes between scans, aware of updates.
* Breached password check for new passwords, resets and administrator logins.
* Weekly security report email, with a send-now button.

= 1.0.0 =
* REST API with read-only hub keys and administrator write routes.
* Hub tab to watch the security status of several sites.
* WordPress dashboard widget.
* Translation template, PHP 7.4 compatibility check, readme and uninstall cleanup for hub data.

= 0.3.0 =
* Core file integrity check against WordPress.org checksums and a malware scan, manual or scheduled.
* Activity log moved to its own table, with logins, users, plugins, themes and core updates, filtering and paging.
* Email alerts with throttling and a test button.
* Dashboard: Scan and Alerts tabs, file scan check in the security score.

= 0.2.0 =
* Two-factor login with authenticator apps and recovery codes.
* Request firewall, IP allow and block lists, trusted proxy support.
* Password reset no longer reveals which accounts exist.
* Dashboard: Access tab, firewall stats, two-factor coverage check.

= 0.1.0 =
* First release: hardening modules, login limits, security score and activity log.
