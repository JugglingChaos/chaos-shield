=== Chaos Shield ===
Contributors: jugglingchaos
Tags: security, firewall, two-factor, audit log, malware scanner
Requires at least: 6.4
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 1.12.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Lightweight security hub: hardening, passkeys and two-factor login, a firewall with rate limits, malware scanning and cleanup, an activity log, alerts and a hub for all your sites.

== Description ==

Chaos Shield gives you a single dashboard for the security basics, without slowing your site down.

**Hardening, one switch each**

* Disable XML-RPC and pingbacks
* Disable the theme and plugin file editor
* Hide the WordPress version
* Block username enumeration (author URLs, REST API, sitemaps, oEmbed)
* Security headers (nosniff, frame options, referrer and permissions policy, HSTS on HTTPS)
* Limit login attempts with temporary IP lockouts
* Generic login error messages
* Optionally disable application passwords

**Automatic bans**

* IPs that get locked out again and again, or keep tripping the firewall, are banned from the whole site for a day.
* Bots that request lots of missing pages while hunting for vulnerable files are banned too. Missing images, scripts and fonts do not count, so broken links on your own pages never ban a visitor.
* IPs an administrator has logged in from, the allow list, and Google and Bing crawlers (verified by DNS) are never banned.

**Breached password protection**

New and reset passwords that appear in public data breaches are refused, and administrators who still log in with one see a warning. Checks use the Have I Been Pwned range API: only the first five characters of the password's SHA-1 hash leave your site.

**Known vulnerability alerts**

Works out of the box, with no account, key or second plugin. Every day Chaos Shield checks WordPress, every plugin and every theme against WPVulnerability.net, a free and open database built from public sources such as CVE records. Affected items show on the Scan tab with severity, CVE, CVSS score, the fixed version and an Update now button, count against the security score and trigger an email. Plugins and themes that were closed on WordPress.org or not updated in two years are flagged too. Only slugs and your WordPress version are sent, never your site address.

**Threat intelligence blocklist**

Blocks networks run by criminals and spammers using the free Spamhaus DROP list, downloaded once a day. Tor exit nodes can be blocked too. Lookups are a binary search over a few kilobytes, so the check costs next to nothing on each request.

**Visitor help assistant**

Blocked, rate-limited and locked-out visitors get a clear page in place of a bare error: what happened in plain words, what they can try, the block reference, and a small help assistant that answers common questions. Visitors who are still stuck can message you from the page, even while banned, and Allow in the Visitor help tab lifts their ban and lockout and lets the blocked request through. The login page gets a sign-in help bubble, and you can add a help bubble to every page that answers your own questions. Answers are matched in the visitor's browser with no AI service, and block pages never say which rule fired. Scripts and tools still get the one-line text answer.

**Live traffic**

Watch requests as they happen: blocked requests, logins, XML-RPC calls and missing pages, or every visit if you choose. Filter by type, see the IP, country, user, request and browser, and block an IP in one click. The last 24 hours are kept in a small table of their own.

**Login page protection**

* Move the login page to a secret address. wp-login.php and wp-admin then answer 404 to visitors who are not logged in. The address is emailed to you when it changes; `define( 'CSHIELD_DISABLE_LOGIN_SLUG', true );` in wp-config.php switches it off if you lose it.
* Optional CAPTCHA on the login, lost password and registration forms, with Cloudflare Turnstile or hCaptcha. Connecting opens the service's sign-up page in a small window beside the dashboard and checks the keys with a live test challenge before switching it on. If the service cannot be reached during a login, the login is allowed and the outage is logged, so you are never locked out by a third party.
* See every signed-in administrator session, with IP and browser, and sign out any of them remotely.

**Passkey login**

Users add a passkey from their profile and sign in with their fingerprint, face or device PIN, using Windows Hello, Touch ID, Android, iCloud Keychain, Google Password Manager, 1Password or a security key. Passkeys cannot be phished or reused on another site, and because the device checks who you are, a passkey login counts as two-factor and skips the code step. Failed passkey attempts count toward login lockouts, and a passkey whose signature counter goes backwards (a sign of a copied key) is refused. Passkeys need HTTPS.

**Two-factor login**

Each user can add an authenticator app (Google Authenticator, Microsoft Authenticator, Authy, 1Password and others) from their profile. Setup uses a QR code, gives ten one-time recovery codes, and administrators can reset two-factor for a user who lost their phone. Secrets are encrypted with a key derived from your site's security keys.

**Rate limiting**

Each IP gets a per-minute budget for login and XML-RPC requests, REST API and AJAX calls, and searches, with limits you can change. Over the limit it gets 429 Too Many Requests, and an IP that keeps hitting the limit is banned. With a persistent object cache such as Redis, every page view can be limited too. Administrators and the allow list are never limited.

**Country blocking**

Block a list of countries, or allow only the countries you list, for the login page or the whole site. The country comes from Cloudflare's CF-IPCountry header or a GeoIP header set by your host, so no database download is needed. Signed-in users keep using the site, and you cannot save a rule that blocks your own country.

**Firewall and access control**

* A scoring firewall that decodes and checks every part of a request: the address, form and JSON fields, XML bodies, cookies, the referrer, the user agent and uploaded file names.
* Fourteen rules, from SQL and script injection to PHP object injection, XXE and server-side request forgery. Clear attacks block on their own; suspicious signs add up. Relaxed, balanced and strict sensitivity, and any rule can be switched off.
* Learning mode records for 7 days what would have been blocked, so you can allow your own traffic before blocking starts.
* Blocked visitors see a reference you can look up in the Firewall tab, and Allow turns that hit into an exception for that address and field.
* One click blocks PHP from running in the uploads folder (Apache and LiteSpeed; an nginx rule is shown).
* IP allow list (never locked out or blocked) and block list (403 everywhere), with CIDR ranges and IPv6.
* Locked out IPs can be moved to the block list in one click.
* Password reset no longer reveals whether an account exists.

**File and malware scan**

* Checks every core file against the official WordPress.org checksums and reports modified or missing files.
* Compares every plugin and theme from WordPress.org with its official release, reporting modified files and PHP files the release does not contain. Modified files can be repaired from WordPress.org in one click.
* Fingerprints critical files every hour with SHA-256 and MD5: wp-config.php, .htaccess, .user.ini and php.ini, drop-ins such as object-cache.php, must-use plugins, the active theme's functions.php and the core files that run on every request. A change, a deleted file or a new drop-in alerts you at once and stays listed until you accept it. Config files show exactly which lines changed and can be put back in one click; for wp-config.php only line fingerprints are kept, and new lines are shown with passwords, keys and salts hidden. Updates and permalink changes you make are accepted on their own, and the fingerprints can be downloaded to keep off the site.
* Finds backups, logs and secrets that the web server would hand to anyone, such as wp-config.php.bak, .env, .git, debug.log and database dumps.
* Flags PHP files that WordPress did not ship inside wp-admin, wp-includes or the site root, and any PHP file in uploads.
* Searches plugins, themes and uploads for common backdoor and malware patterns, with file, line and the matching code.
* Runs in small steps from the dashboard or in the background every day or week, so it works on shared hosting.
* Reports plugin and theme files that changed, or new PHP files that appeared, since the last scan without going through the WordPress updater. A change keeps showing until you mark it reviewed.
* Findings can be marked as reviewed; they come back if the file changes.

**Cleanup**

* Repair a modified core file in one click. The original is downloaded from WordPress.org for your exact version, checked against the official checksum before anything is written, and the modified file is kept as a backup.
* Quarantine a suspicious plugin, theme or upload file. It moves to a locked folder where it cannot run, and can be restored or deleted for good.
* Scan the database for code injected into posts, pages and settings: scripts loaded from other sites, obfuscated scripts, hidden iframes and eval code, plus tampered site addresses.

**Activity log and alerts**

* Logs logins, lockouts, firewall blocks, user creation, role changes, password resets, plugin and theme changes, core updates, scans and setting changes, in its own database table with filtering and paging.
* Email alerts for administrator logins from a new IP, new or promoted administrators, plugin and theme changes, scan findings and (optionally) lockouts. Each alert is throttled to one email per 15 minutes.
* A weekly report with logins, lockouts, bans, changes, scan results and what to fix.

**Audit trail and compliance**

* Records who changed what: posts and pages published, edited, trashed and deleted, media, categories, menus, widgets and Customizer changes, core settings such as the site address, admin email and registration, profile email and password changes, logouts, failed logins, application passwords, content exports and personal data export and erasure requests.
* Filter the log by type, user, text or IP and date range, and export the result to CSV.
* A printable compliance report (save it as PDF from the browser) with the security score, twelve controls marked in place or gap with evidence and the SOC 2 and ISO/IEC 27001:2022 controls they support, every administrator's second factor and last login, and the notable events of the period. It is evidence for an assessment, not a certification.
* Alerts in Slack, Discord, Microsoft Teams or Google Chat as well as by email. Connect a channel from the Alerts tab: the service opens in a small window, a test message proves the webhook works, and alert text is escaped so it can never ping a whole channel.
* Keep the log up to two years, or forward every event as it happens to a webhook (JSON, signed with HMAC-SHA256 if you set a secret; Slack and Discord hooks work too) or to syslog (local, UDP or TCP, RFC 5424) for your SIEM.

**Traffic map and built-in country lookup**

The Live traffic tab shows a world heatmap of where requests, blocks and logins come from, with a top countries table. Countries come from a public domain IP to country database (ip-location-db, compiled from the regional internet registries, BGP routing data and operator geofeeds) that Chaos Shield downloads once a week into your uploads folder and searches locally in microseconds. No account, no key, and no visitor data is sent anywhere. The same database can drive country blocking, so that no longer needs Cloudflare or a host header. The map uses Natural Earth country shapes (public domain).

**Built-in SIEM**

No ELK stack, Splunk or outside service. Every event carries an action code (such as auth.failed or plugin.activated), and twelve detection rules mapped to MITRE ATT&CK watch them as they are logged:

* Login after brute force, credential stuffing, distributed login attacks, and repeat attackers
* New administrators, risky changes soon after a login from a new IP, and the account takeover pattern (email and password changed together)
* Site address, admin email or registration changes, with open registration as administrator rated critical
* Protections or security plugins switched off, malware found by the scan, mass deletion of content, and suspicious sign-in methods

A match opens an incident with a severity, the evidence events and the ATT&CK technique. Repeats merge into the same incident instead of flooding you, and high and critical incidents are emailed (you choose the threshold).

* Work each incident as a case: status, assignee and notes, with every change recorded.
* Respond from the incident: ban or block the IP, end the user's sessions or force a password reset. Your own IP and account, and IPs administrators logged in from, are protected.
* Timelines for any IP or user join the log, live traffic and incidents in one list.
* Search the log with fields: action:auth.* ip:203.0.113.7 user:admin sev:3 since:24h.
* A 24 hour chart of events by severity, and open incidents by severity at a glance.
* Switch any rule off. Switching rules or protections off is itself logged.
* The hub shows open incidents for every connected site, worst first.

**Password policy and forced resets**

* Minimum length, a mix of character kinds and no username or email inside the password, for administrators, everyone who writes posts, or all users. Optional expiry.
* Force a password reset for one user or many from the Users screen, or for all other administrators in one click. They are signed out everywhere, and at their next login they go straight to the screen for choosing a new password.

**Backups and restore points**

* Before a plugin or theme updates, before a file is repaired from WordPress.org and before Chaos Shield settings change, a restore point saves what is about to be replaced. One click on the Backups tab puts it back, and the state from just before is saved too, so a restore can be undone.
* Make a restore point of wp-config.php, .htaccess and the settings by hand before you try something risky.
* Download the whole database as a compressed SQL file, ready for phpMyAdmin, Adminer or `wp db import`.
* Export the settings and import them on another site. The receiving site keeps its login address and never blocks the importer's own IP.
* Points are kept for 30 days, up to 20 of them, in a locked folder in wp-content. Every stored file starts with a PHP exit line, so a direct request shows nothing even where the folder's deny rules are ignored.

**Edge protection and outside services**

The Edge tab brings the free parts of a CDN's security that a plugin can do itself, and connects to Cloudflare or any other firewall for the rest.

* Under attack mode puts a one-second browser check in front of the site. Browsers solve a small proof-of-work puzzle and keep a signed pass for 12 hours, while bots and scripts that flood the site never reach WordPress. It switches on by itself when more than 100 requests a minute are blocked (you choose the number) and ends an hour after the flood stops. Logged-in users, the allow list, Google, Bing and the REST API are never checked.
* Page script monitor: every day the plugin loads your home page, newest post and page, and a shop's cart and checkout, and lists every script they load. Scripts found on the first look are approved; a new one, one that changes, one loaded from the uploads folder, or one that looks like a card skimmer, miner or hidden code sends an alert. A Content Security Policy built from the approved list can run in report-only mode, so browsers report scripts other scripts load later, or enforce it so browsers refuse scripts from domains you did not approve. Editors only get reports, so page builders keep working.
* HTTPS checks: the certificate's expiry and trust, whether plain http is sent to HTTPS, and mixed content on your pages. "Send every visitor to HTTPS" only switches on once the site answers on HTTPS with a trusted certificate, so it cannot lock you out, and a separate switch upgrades http:// images and scripts in the browser.
* Exposed files and keys: about 40 addresses such as .env, .git, database dumps, backup archives, logs and phpinfo are asked for over the web and only count when the answer looks like the real thing. Backups and logs in public folders are listed even when they cannot be downloaded, pages and scripts are searched for live API keys (shown masked), and one button blocks these files in .htaccess, with a snippet for nginx.
* Cloudflare: paste an API token and banned and blocked IPs are refused at Cloudflare before they reach your server, under attack mode switches Cloudflare's own Under Attack mode with it, and you can purge the cache, turn on Always Use HTTPS and trust Cloudflare's visitor IP header from the same card. Disconnecting removes the plugin's rules from Cloudflare.
* Any other firewall or CDN: a secret ban list address returns every banned and blocked IP as plain text, one per line, for server firewalls, fail2ban, CDN IP lists or a scheduled script.

**Multisite networks**

Network activate Chaos Shield and the whole network shares one set of settings, one activity log, one ban list and one set of background jobs, managed by super admins from Network Admin. A lockout earned on one site holds on all of them, because they share one login. The log, the SIEM search (`site:shop`) and the CSV export show which site each event happened on. Site administrators do not see the plugin screens and cannot change its settings, while two-factor and passkeys keep working on every site's profile page.

**Security score**

A weighted score from 0 to 100 based on HTTPS, pending updates, debug output, the default admin username, PHP version, database prefix and which protections are on, with a plain explanation of what to fix.

**Hub for several sites**

Install Chaos Shield on each site, create a hub key on its Hub tab, and connect it from the site you use as your hub. The Hub tab then shows every site's score, open checks, scan findings and lockouts in one list.

* Uptime checks every five minutes with response time and 24 hour uptime, plus HTTPS certificate expiry and trust, with an email when a site goes down, comes back, or its certificate has less than 14 days left.
* With a key that allows actions, start scans, release lockouts and bans, and push your hardening settings (switches, login and rate limits, password policy) to one site or all of them. Login addresses, IP lists and email settings are never pushed.
* Read keys are stored only as a hash. Actions are never sent with the key: the hub signs the time, a random nonce, the route and the body with HMAC-SHA256, the site refuses requests older than five minutes or seen before, and wrong signatures count toward the lockout.

**WordPress dashboard widget**

A small widget on the main WordPress dashboard shows the score, failed logins and firewall blocks for the last 24 hours, and the top things to fix.

= REST API =

Routes live under `/wp-json/chaos-shield/v1/` (or `?rest_route=/chaos-shield/v1/` without pretty permalinks).

* Read: `GET /status`, `GET /events`, `GET /scan`, `GET /lockouts`. Accepts a logged-in administrator or a request signed with the hub key (`X-Chaos-Time`, `X-Chaos-Nonce`, `X-Chaos-Signature`), so the key itself never travels. The older `X-Chaos-Key` header still works.
* Write: `POST /scan`, `POST /scan/step`, `DELETE /lockouts/{ip}`, `POST /blocklist`, `GET` and `POST /settings`. Needs an administrator, for example with an application password. The hub key can never write.
* A wrong hub key counts as a failed login, so guessing gets the caller locked out.

= Behind a proxy or CDN =

By default Chaos Shield reads the visitor IP from REMOTE_ADDR, because forwarded headers can be faked. Under Access you can choose Cloudflare, X-Forwarded-For or X-Real-IP, and the header is only believed when the connection comes from a trusted proxy: by default a private network address, plus Cloudflare's published ranges for the Cloudflare header. List your proxy IPs if they are public. The dashboard warns you when requests arrive through a proxy that is not configured or not trusted.

= Two-factor and changed security keys =

Two-factor secrets are encrypted with your wp-config.php security keys. If those keys change, users log in with a recovery code and set two-factor up again, or an administrator resets it from their profile.

= Running the tests =

The plugin source (not the release zip) has an integration suite in `tests/` that drives a live test site over HTTP: logins, two-factor, the firewall, bans, the SIEM, the hub API, restore points and the admin screens, plus network checks when the site is a multisite. Run `tests/run.sh /path/to/wordpress` on a throwaway site, never on production.

= Filters =

* `cshield_client_ip` - the client IP used for login limits.
* `cshield_security_headers` - the array of security headers sent.
* `cshield_critical_files` - the files whose fingerprints are watched, by name, with path, group, text (keep a copy to compare and put back) and appear (report the file appearing).
* `cshield_firewall_rules` - the firewall rules, keyed by id. Each has `label`, `info`, `pattern`, `score` (5 blocks, 3 adds up), `targets` (all, path, agent or file) and an optional `staff` flag to keep checking post content from authors and editors.
* `cshield_scan_signatures` - the malware signatures used by the file scan.
* `cshield_check_pages` - the page addresses the daily page check loads (up to 8).
* `cshield_exposure_paths` - the addresses asked for by the exposed files check, by id, with path and kind.
* `cshield_attack_mode` (action) - runs with true or false when under attack mode switches on or off.

== Installation ==

1. Upload the plugin zip from Plugins > Add New > Upload Plugin.
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

Nothing that identifies your site's users, unless you turn on log forwarding, which sends events (including usernames and IPs) to the webhook or syslog server you choose. Repair downloads the original file from core.svn.wordpress.org, plugins.svn.wordpress.org or themes.svn.wordpress.org. The daily vulnerability check asks wpvulnerability.net about each installed slug and your WordPress version, the scan fetches plugin checksums and theme releases from downloads.wordpress.org, and the threat blocklist downloads Spamhaus DROP (and the Tor exit list, if chosen) once a day, the built-in country lookup downloads its database from github.com once a week; all of these can be switched off under Hardening. With a login CAPTCHA on, login tokens are checked with Cloudflare or hCaptcha, and their script loads on the login page; while you connect one, its script also loads in the dialog for the live test. A connected chat receives the text of each alert. The daily page check loads your own pages and downloads the outside scripts they include, so their servers see your server's address. With Cloudflare connected, the plugin sends banned IPs and settings changes to api.cloudflare.com with your token. Help messages from visitors (name, email, message and IP) are stored on your site for 30 days and never sent anywhere except your own alert email or chat. Scans fetch core checksums from api.wordpress.org, the breached password check sends the first five characters of a password's SHA-1 hash to api.pwnedpasswords.com (switch it off under Hardening if you prefer), and the hub contacts only the sites you connect.

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

== Changelog ==

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
