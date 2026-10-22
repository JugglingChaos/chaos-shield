<?php
/**
 * IP block list and request firewall.
 *
 * @package ChaosShield
 */

namespace ChaosShield;

defined( 'ABSPATH' ) || exit;

/**
 * Stops blocked IPs and malicious requests before WordPress does any real work.
 *
 * Every part of a request that an attacker controls is inspected: the path, the
 * query, form and JSON fields, cookies, the referrer, the user agent and the
 * names of uploaded files. Each value is decoded the way an application would
 * read it (URL encoding up to three times, HTML entities, SQL comments, null
 * bytes) before the rules run, so encoding tricks do not slip past them.
 *
 * Rules score instead of deciding alone. A clear attack signature scores 5, a
 * suspicious one 3, and the request is blocked when its total reaches the
 * sensitivity threshold. Learning mode records what would have been blocked
 * without blocking it, and exceptions switch a rule off for one address or field.
 */
final class Firewall {

	const HITS         = 'cshield_fw_hits';
	const EXCEPTIONS   = 'cshield_fw_exceptions';
	const MAX_HITS     = 100;
	const MAX_VALUE    = 16384;
	const MAX_BYTES    = 262144;
	const MAX_FIELDS   = 500;
	const UPLOADS_MARK = '# Chaos Shield: no PHP in uploads';

	/**
	 * Reference of the request being blocked, shown on the block page.
	 *
	 * @var string
	 */
	private static $reference = '';

	/**
	 * Registers hooks.
	 */
	public function register() {
		// The block list needs nothing but the IP, so it runs while the plugin loads.
		$this->enforce_blocklist();

		if ( Settings::enabled( 'firewall' ) ) {
			// Pluggable functions exist from here, which the admin exemption needs.
			add_action( 'plugins_loaded', array( $this, 'inspect' ), 0 );
		}
		add_action( 'admin_post_cshield_firewall', array( __CLASS__, 'handle' ) );
	}

	/**
	 * Whether the client IP is on the allow list.
	 *
	 * @return bool
	 */
	public static function allowlisted() {
		return Request::ip_matches( Request::ip(), (array) Settings::get( 'ip_allowlist' ) );
	}

	/**
	 * Refuses every request from a blocked IP.
	 */
	private function enforce_blocklist() {
		$blocked = (array) Settings::get( 'ip_blocklist' );
		if ( ( defined( 'WP_CLI' ) && WP_CLI ) || ! $blocked || self::allowlisted() || ! Request::ip_matches( Request::ip(), $blocked ) ) {
			return;
		}
		Login_Guard::bump_stat( 'firewall_blocks' );
		self::deny( 'blocklist' );
	}

	// Settings.

	/**
	 * Score that blocks a request, by sensitivity.
	 *
	 * @return array
	 */
	public static function thresholds() {
		return array(
			'relaxed'  => 8,
			'balanced' => 5,
			'strict'   => 3,
		);
	}

	/**
	 * Current blocking threshold.
	 *
	 * @return int
	 */
	public static function threshold() {
		$all = self::thresholds();
		$key = (string) Settings::get( 'fw_sensitivity' );
		return isset( $all[ $key ] ) ? $all[ $key ] : $all['balanced'];
	}

	/**
	 * Whether the firewall only records what it would block.
	 *
	 * @return bool
	 */
	public static function learning() {
		return 'learn' === Settings::get( 'fw_mode' ) && (int) Settings::get( 'fw_learn_until' ) > time();
	}

	// Inspection.

	/**
	 * Checks the request and blocks it, or records it in learning mode.
	 */
	public function inspect() {
		// The site's own page check asks for .env, .git and the like on purpose.
		if ( ( defined( 'WP_CLI' ) && WP_CLI ) || self::allowlisted() || Page_Check::is_self() ) {
			return;
		}
		// Administrators can legitimately send odd looking requests, for example while debugging.
		if ( current_user_can( Network::cap() ) ) {
			return;
		}

		$path   = self::request_path();
		$result = self::evaluate( self::inputs(), $path, current_user_can( 'edit_posts' ) );
		if ( $result['score'] < self::threshold() ) {
			return;
		}

		$learning = self::learning();
		$ip       = Request::ip();
		$ref      = strtoupper( substr( wp_hash( $ip . microtime() . wp_rand() ), 0, 8 ) );
		self::record_hit( $ref, $path, $result, $learning ? 'logged' : 'blocked' );

		$labels = array();
		$rules  = self::rules();
		foreach ( $result['hits'] as $hit ) {
			$labels[] = $rules[ $hit['rule'] ]['label'] . ' in ' . $hit['field'];
		}

		// Log one event per IP and rule set every 10 minutes so a scan cannot flood the log.
		$throttle = 'cshield_fw_' . md5( $ip . '|' . implode( ',', wp_list_pluck( $result['hits'], 'rule' ) ) . '|' . (int) $learning );
		if ( ! Network::get_transient( $throttle ) ) {
			Network::set_transient( $throttle, 1, 10 * MINUTE_IN_SECONDS );
			Events::add(
				'blocked',
				// Plain English: this runs before translations may be loaded.
				sprintf( $learning ? 'Firewall would have blocked a request (learning mode, ref %1$s): %2$s, at %3$s' : 'Firewall blocked a request (ref %1$s): %2$s, at %3$s', $ref, implode( '; ', $labels ), $path ),
				$ip,
				array(
					'action'  => $learning ? 'fw.learned' : 'fw.blocked',
					'subject' => $path,
				)
			);
		}
		if ( $learning ) {
			return;
		}

		Login_Guard::bump_stat( 'firewall_blocks' );
		Bans::strike( $ip, 'firewall' );
		self::$reference = $ref;
		self::deny();
	}

	/**
	 * Firewall rules. Patterns run against decoded, lower-cased values.
	 *
	 * Targets: path, query, body, cookie, header, agent, file (uploaded file names).
	 * Form and JSON fields sent by signed-in authors and editors only go through
	 * rules marked staff: posts legitimately carry HTML, code and SQL examples.
	 * Labels are not translated because rules are evaluated before translations may load.
	 *
	 * @param bool $all Include rules switched off in the settings.
	 * @return array Rule key => [ label, info, pattern, score, targets, staff ].
	 */
	public static function rules( $all = false ) {
		$inputs = array( 'query', 'body', 'cookie', 'header' );
		$rules  = array(
			'sqli'       => array(
				'label'   => 'SQL injection',
				'info'    => 'UNION SELECT, schema lookups, time delays and file reads through SQL.',
				'pattern' => '#(\bunion\s+(all\s+|distinct\s+)?select\b|\binformation_schema\b|\bsleep\s*\(\s*\d|\bbenchmark\s*\(|\bpg_sleep\s*\(|\bwaitfor\s+delay\b|\bload_file\s*\(|\binto\s+(out|dump)file\b|\b(extractvalue|updatexml)\s*\(|\bselect\b.{1,80}\bfrom\b.{1,40}\b\w*users\b.{0,80}\buser_pass\b)#',
				'score'   => 5,
				'targets' => array( 'path', 'query', 'body', 'cookie', 'header' ),
			),
			'sqli_logic' => array(
				'label'   => 'SQL logic trick',
				'info'    => 'Always-true conditions followed by a comment, such as \' or 1=1 --.',
				'pattern' => '#([\'"`)]\s*\b(or|and|xor|\|\||&&)\b\s*[\'"`(]?\s*[\w\'"]+\s*[\'"`)]?\s*(=|<|>|like)\s*[\'"`(]?\s*[\w\'"]*|\b(or|and)\s+\d+\s*=\s*\d+\s*(--|\#|;))#',
				'score'   => 3,
				'targets' => $inputs,
			),
			'xss'        => array(
				'label'   => 'Script injection',
				'info'    => 'Script, frame and object tags, event handlers and javascript: links.',
				'pattern' => '#(<\s*(script|iframe|object|embed|base|applet|meta\s[^>]*http-equiv)\b|<[a-z][^>]*[\s/]on[a-z]{3,}\s*=|(?<![\w-])(javascript|vbscript):(?!\s)|\bdata\s*:\s*text/html|\bsrcdoc\s*=)#',
				'score'   => 5,
				'targets' => array( 'path', 'query', 'body', 'cookie', 'header' ),
			),
			'xss_dom'    => array(
				'label'   => 'Script probe',
				'info'    => 'Cookie theft and alert() probes, scored low because they also appear in normal text.',
				'pattern' => '#(\bdocument\s*\.\s*(cookie|domain|write)\b|\b(alert|prompt|confirm)\(\s*[\w\'"`]*\s*\)|\bstring\s*\.\s*fromcharcode\s*\(|\bwindow\s*\.\s*location\b)#',
				'score'   => 3,
				'targets' => $inputs,
			),
			'traversal'  => array(
				'label'   => 'Path traversal',
				'info'    => 'Climbing out of a folder with ../ to read system or WordPress files.',
				'pattern' => '#((\.\./|\.\.\\\\){2,}|(\.\./|\.\.\\\\)+(etc|proc|windows|boot|var|usr|wp-config|wp-admin|wp-includes)\b|/etc/(passwd|shadow|hosts|group)\b|/proc/self/|(\.\./|/)wp-config\.php\b|\bc:\\\\windows\b)#',
				'score'   => 5,
				'targets' => array( 'path', 'query', 'body', 'cookie' ),
			),
			'code'       => array(
				'label'   => 'Code injection',
				'info'    => 'PHP tags, PHP stream wrappers and calls to eval, system and similar functions.',
				'pattern' => '#(<\?php|<\?=|\b(php|phar|expect|zip|glob|data)://|\bdata:(text|application)/[a-z-]+;base64|\b(system|exec|shell_exec|passthru|proc_open|popen|pcntl_exec|assert|eval|create_function|call_user_func(_array)?)\(\s*[\'"$]|\b(base64_decode|gzinflate|str_rot13)\(|\$\{\s*jndi\s*:|\$\{\s*(env|sys|java|lower|upper)\s*:)#',
				'score'   => 5,
				'targets' => array( 'path', 'query', 'body', 'cookie', 'header' ),
			),
			'command'    => array(
				'label'   => 'Command injection',
				'info'    => 'Shell commands chained after ;, | or `, or inside $( ).',
				'pattern' => '#(;|\|\|?|&&|`|\$\()\s*((cat|head|tail|more|less)\s+/|(wget|curl)\s+(-\S+\s+)*(https?|ftp)://|(bash|sh|zsh|dash)\s+-c\b|(nc|ncat|netcat)\s+(-\S+\s+)*[\w.]+\s+\d+|(python[23]?|perl|ruby|php)\s+-[cer]\b|(whoami|id|uname(\s+-a)?)\s*($|[;|&`)])|chmod\s+[0-7]{3,4}\s|rm\s+-[rf]+\s+/|powershell\b)#',
				'score'   => 5,
				'targets' => $inputs,
			),
			'object'     => array(
				'label'   => 'PHP object injection',
				'info'    => 'Serialized PHP objects, which can run code when a plugin unserializes them.',
				'pattern' => '#(^|[;{:"])\s*[oc]:\+?\d+:"[a-z_\\\\][a-z0-9_\\\\]*":\d+:\{#',
				'score'   => 5,
				'targets' => array( 'query', 'body', 'cookie' ),
				'staff'   => true,
			),
			'xxe'        => array(
				'label'   => 'XML entity attack',
				'info'    => 'XML that declares external entities to read files or reach other servers.',
				'pattern' => '#<!(doctype|entity)[^>]*\b(system|public)\b|<!entity\s#',
				'score'   => 5,
				'targets' => array( 'query', 'body' ),
				'staff'   => true,
			),
			'ssrf'       => array(
				'label'   => 'Cloud metadata request',
				'info'    => 'Addresses of cloud metadata services, used to steal server credentials.',
				'pattern' => '#(169\.254\.169\.254|\bmetadata\.google\.internal\b|\b100\.100\.100\.200\b|\[?fd00:ec2::254\]?|\b0x(a9fea9fe)\b)#',
				'score'   => 5,
				'targets' => array( 'query', 'body' ),
				'staff'   => true,
			),
			'null_byte'  => array(
				'label'   => 'Null byte',
				'info'    => 'A hidden end-of-string character used to cut file names short.',
				'pattern' => '#%00|\\\\0|\\\\x00#',
				'score'   => 3,
				'targets' => array( 'path', 'query', 'body' ),
				'raw'     => true,
			),
			'probe'      => array(
				'label'   => 'Sensitive file probe',
				'info'    => 'Requests for .env, .git, backups and database dumps.',
				'pattern' => '#(/\.env(\.\w+)?$|/\.git/|/\.svn/|/\.hg/|/\.ds_store$|/\.htpasswd$|/\.aws/|\.(sql|sql\.gz|bak|old|swp)$|/phpinfo\.php$|/wp-config\.php\.(bak|old|save|orig|txt|swp)$)#',
				'score'   => 5,
				'targets' => array( 'path' ),
			),
			'php_upload' => array(
				'label'   => 'Script upload',
				'info'    => 'Uploads of files that a web server could run, such as .php or .phtml.',
				'pattern' => '#\.(php\d?|phtml|phar|pht|phps|shtml|cgi|pl|py|asp|aspx|jsp)(\.|$)|^\.(htaccess|user\.ini)$#',
				'score'   => 5,
				'targets' => array( 'file' ),
			),
			'oversize'   => array(
				'label'   => 'Oversized request',
				'info'    => 'More form data than the firewall reads, which could hide an attack past the part it checks.',
				'pattern' => '#^over$#',
				'score'   => 5,
				'targets' => array( 'size' ),
			),
			'scanner'    => array(
				'label'   => 'Attack tool',
				'info'    => 'User agents of vulnerability scanners and attack tools.',
				'pattern' => '#(sqlmap|nikto|acunetix|nessus|netsparker|havij|masscan|zgrab|nuclei|dirbuster|gobuster|wpscan|nmap scripting engine|jorgee|commix|xsser|openvas|arachni|w3af|wfuzz|ffuf|feroxbuster)#',
				'score'   => 5,
				'targets' => array( 'agent' ),
			),
		);

		/**
		 * Filters the firewall rules. Remove a key to switch a rule off.
		 *
		 * @param array $rules Rule key => [ label, info, pattern, score, targets, staff ].
		 */
		$rules = (array) apply_filters( 'cshield_firewall_rules', $rules );
		if ( ! $all ) {
			foreach ( (array) Settings::get( 'fw_rules_off' ) as $off ) {
				unset( $rules[ $off ] );
			}
		}
		return $rules;
	}

	/**
	 * Everything in the request an attacker controls, as field => raw value.
	 *
	 * @return array
	 */
	public static function inputs() {
		// phpcs:disable WordPress.Security.NonceVerification, WordPress.Security.ValidatedSanitizedInput -- Inspected only, never stored or printed as is.
		$fields = array(
			array( 'path', 'path', self::request_path( false ) ),
			array( 'agent', 'user agent', isset( $_SERVER['HTTP_USER_AGENT'] ) ? (string) wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) : '' ),
			array( 'header', 'referrer', isset( $_SERVER['HTTP_REFERER'] ) ? (string) wp_unslash( $_SERVER['HTTP_REFERER'] ) : '' ),
		);
		self::flatten( 'query', 'GET', $_GET ? wp_unslash( $_GET ) : array(), $fields );
		// The whole query string too, for attacks hidden in parameter names.
		$fields[] = array( 'query', 'query string', isset( $_SERVER['QUERY_STRING'] ) ? (string) wp_unslash( $_SERVER['QUERY_STRING'] ) : '' );
		foreach ( $_COOKIE ? wp_unslash( $_COOKIE ) : array() as $name => $value ) {
			// WordPress's own login and settings cookies are signed or harmless.
			if ( preg_match( '/^(wordpress_(logged_in_|sec_)?[a-f0-9]{32}|wp-settings-(time-)?\d+|wordpress_test_cookie)$/', (string) $name ) ) {
				continue;
			}
			self::flatten( 'cookie', 'COOKIE', array( $name => $value ), $fields );
		}
		// Form fields last: they can be large, and the size budget runs out at the end.
		self::flatten( 'body', 'POST', $_POST ? wp_unslash( $_POST ) : array(), $fields );
		$type = isset( $_SERVER['CONTENT_TYPE'] ) ? strtolower( (string) $_SERVER['CONTENT_TYPE'] ) : '';
		$over = false;
		// PHP only fills $_POST for a POST form, but the REST API also reads PUT, PATCH and
		// DELETE bodies, and bodies with no type at all, so read those here.
		if ( ! $_POST && false === strpos( $type, 'multipart/' ) ) {
			$raw  = (string) file_get_contents( 'php://input', false, null, 0, self::MAX_BYTES + 1 ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Reads the request body.
			$over = strlen( $raw ) > self::MAX_BYTES;
			$raw  = substr( $raw, 0, self::MAX_BYTES );
			$doc  = false !== strpos( $type, 'json' ) ? json_decode( $raw, true ) : null;
			$form = array();
			if ( ! is_array( $doc ) && ( '' === $type || false !== strpos( $type, 'x-www-form-urlencoded' ) ) ) {
				parse_str( $raw, $form );
			}
			if ( is_array( $doc ) ) {
				self::flatten( 'body', 'JSON', $doc, $fields );
			} elseif ( $form ) {
				self::flatten( 'body', 'POST', $form, $fields );
			} elseif ( '' !== $raw ) {
				$fields[] = array( 'body', 'body', $raw );
			}
		}
		foreach ( $_FILES as $field => $file ) {
			foreach ( (array) ( isset( $file['name'] ) ? $file['name'] : array() ) as $name ) {
				if ( is_string( $name ) && '' !== $name ) {
					$fields[] = array( 'file', 'upload ' . $field, strtolower( basename( $name ) ) );
				}
			}
		}
		// phpcs:enable
		if ( $over || count( $fields ) >= self::MAX_FIELDS ) {
			// Checked first, so it still counts when the size budget runs out.
			array_unshift( $fields, array( 'size', 'request size', 'over' ) );
		}
		return $fields;
	}

	/**
	 * Adds nested values as flat fields such as POST:comment or JSON:meta.title.
	 *
	 * @param string $target Rule target.
	 * @param string $prefix Field prefix.
	 * @param mixed  $value  Value.
	 * @param array  $fields Fields, added to.
	 * @param int    $depth  Nesting depth.
	 */
	private static function flatten( $target, $prefix, $value, array &$fields, $depth = 0 ) {
		if ( count( $fields ) >= self::MAX_FIELDS || $depth > 8 ) {
			return;
		}
		if ( is_array( $value ) ) {
			foreach ( $value as $key => $child ) {
				$name = $prefix . ( $depth ? '.' : ':' ) . substr( (string) $key, 0, 64 );
				// Field names are input too, for plugins that store or print them. Plain names
				// cannot match a rule, and the query string is already checked whole.
				if ( 'query' !== $target && ! preg_match( '/^[\w\-]*$/', (string) $key ) && count( $fields ) < self::MAX_FIELDS ) {
					$fields[] = array( $target, $name . ' (name)', (string) $key );
				}
				self::flatten( $target, $name, $child, $fields, $depth + 1 );
			}
			return;
		}
		if ( is_scalar( $value ) && '' !== (string) $value ) {
			$fields[] = array( $target, $prefix, (string) $value );
		}
	}

	/**
	 * Decodes a value the way an application would read it, so encoding tricks do not hide an attack.
	 *
	 * @param string $value Raw value.
	 * @return string
	 */
	public static function normalize( $value ) {
		$value = substr( (string) $value, 0, self::MAX_VALUE );
		for ( $i = 0; $i < 3; $i++ ) {
			$decoded = rawurldecode( str_replace( '+', ' ', $value ) );
			$decoded = preg_replace_callback(
				'/%u([0-9a-f]{4})/i',
				static function ( $m ) {
					return mb_convert_encoding( pack( 'H*', $m[1] ), 'UTF-8', 'UCS-2BE' );
				},
				$decoded
			);
			if ( $decoded === $value ) {
				break;
			}
			$value = $decoded;
		}
		$value = html_entity_decode( $value, ENT_QUOTES | ENT_HTML5, 'UTF-8' );
		$value = str_replace( array( "\0", '\\0' ), '', $value );
		// SQL comments stand in for spaces: union/**/select reads as union select.
		$value = preg_replace( '#/\*.*?\*/#s', ' ', $value );
		$value = preg_replace( '/\s+/u', ' ', (string) $value );
		return strtolower( (string) $value );
	}

	/**
	 * Scores a request.
	 *
	 * @param array  $fields Fields from inputs(): [ target, name, value ].
	 * @param string $path   Request path, for exceptions.
	 * @param bool   $staff  Whether a signed-in author or editor sent it.
	 * @return array score, hits ([ rule, field, snippet, score ]).
	 */
	public static function evaluate( array $fields, $path, $staff = false ) {
		$rules      = self::rules();
		$exceptions = self::exceptions();
		$hits       = array();
		$budget     = self::MAX_BYTES;
		$skipped    = false;
		foreach ( $fields as $field ) {
			list( $target, $name, $raw ) = $field;
			if ( '' === $raw ) {
				continue;
			}
			// A long value is read in overlapping pieces, so an attack cannot hide past the first one.
			$pieces = array( $raw );
			if ( 'file' !== $target && strlen( $raw ) > self::MAX_VALUE ) {
				$pieces = array();
				$length = strlen( $raw );
				for ( $at = 0; $at < $length; $at += self::MAX_VALUE - 1024 ) {
					$pieces[] = substr( $raw, $at, self::MAX_VALUE );
				}
			}
			foreach ( $pieces as $piece ) {
				if ( $budget <= 0 ) {
					$skipped = true;
					break;
				}
				$budget -= strlen( $piece );
				self::match( $rules, $exceptions, $path, $staff, $target, $name, $piece, $hits );
			}
		}
		if ( $skipped ) {
			self::match( $rules, $exceptions, $path, $staff, 'size', 'request size', 'over', $hits );
		}
		return array(
			'score' => array_sum( wp_list_pluck( $hits, 'score' ) ),
			'hits'  => array_values( $hits ),
		);
	}

	/**
	 * Runs the rules on one value.
	 *
	 * @param array  $rules      Rules.
	 * @param array  $exceptions Exceptions.
	 * @param string $path       Request path.
	 * @param bool   $staff      Whether a signed-in author or editor sent it.
	 * @param string $target     Rule target.
	 * @param string $name       Field name.
	 * @param string $raw        Raw value.
	 * @param array  $hits       Hits so far, by rule, added to.
	 */
	private static function match( array $rules, array $exceptions, $path, $staff, $target, $name, $raw, array &$hits ) {
		$value = 'file' === $target ? $raw : self::normalize( $raw );
		if ( false !== strpos( $raw, '/*' ) || false !== strpos( $raw, '%2f%2a' ) || false !== strpos( $raw, '%2F%2A' ) ) {
			// Comments can also split a keyword: un/**/ion. Check that reading too.
			$value .= ' ' . preg_replace( '#/\*.*?\*/#s', '', self::normalize( preg_replace( '#/\*.*?\*/#s', '', rawurldecode( $raw ) ) ) );
		}
		foreach ( $rules as $key => $rule ) {
			if ( isset( $hits[ $key ] ) || ! in_array( $target, (array) $rule['targets'], true ) ) {
				continue;
			}
			if ( $staff && in_array( $target, array( 'body', 'size' ), true ) && empty( $rule['staff'] ) ) {
				continue;
			}
			$subject = empty( $rule['raw'] ) ? $value : strtolower( substr( $raw, 0, self::MAX_VALUE ) );
			if ( ! preg_match( $rule['pattern'], $subject, $m, PREG_OFFSET_CAPTURE ) ) {
				continue;
			}
			if ( self::excepted( $exceptions, $key, $path, $name ) ) {
				continue;
			}
			$start        = max( 0, $m[0][1] - 20 );
			$hits[ $key ] = array(
				'rule'    => $key,
				'field'   => $name,
				'snippet' => self::snippet( substr( $subject, $start, 90 ) ),
				'score'   => (int) $rule['score'],
			);
		}
	}

	/**
	 * Short, printable piece of the matched text for the hit list.
	 *
	 * @param string $text Text.
	 * @return string
	 */
	private static function snippet( $text ) {
		$text = preg_replace( '/[^\x20-\x7e]/', '?', (string) $text );
		return trim( (string) $text );
	}

	// Hits and exceptions.

	/**
	 * Saves a hit for the Firewall tab.
	 *
	 * @param string $ref    Reference shown to the visitor.
	 * @param string $path   Request path.
	 * @param array  $result Result of evaluate().
	 * @param string $action blocked or logged.
	 */
	private static function record_hit( $ref, $path, array $result, $action ) {
		$hits = self::hits();
		array_unshift(
			$hits,
			array(
				'ref'    => $ref,
				'time'   => time(),
				'ip'     => Request::ip(),
				'method' => isset( $_SERVER['REQUEST_METHOD'] ) ? substr( sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ), 0, 8 ) : 'get',
				'path'   => $path,
				'score'  => (int) $result['score'],
				'hits'   => $result['hits'],
				'action' => $action,
			)
		);
		Network::update_option( self::HITS, array_slice( $hits, 0, self::MAX_HITS ), false );
	}

	/**
	 * Recent hits, newest first.
	 *
	 * @return array
	 */
	public static function hits() {
		$hits = Network::get_option( self::HITS, array() );
		return is_array( $hits ) ? $hits : array();
	}

	/**
	 * Exceptions: [ rule, path, field, time, user ].
	 *
	 * @return array
	 */
	public static function exceptions() {
		$list = Network::get_option( self::EXCEPTIONS, array() );
		return is_array( $list ) ? $list : array();
	}

	/**
	 * Whether an exception covers a hit.
	 *
	 * @param array  $exceptions Exceptions.
	 * @param string $rule       Rule key.
	 * @param string $path       Request path.
	 * @param string $field      Field name.
	 * @return bool
	 */
	public static function excepted( array $exceptions, $rule, $path, $field ) {
		foreach ( $exceptions as $e ) {
			if ( $e['rule'] !== $rule ) {
				continue;
			}
			$prefix   = empty( $e['exact'] ) && '/' === substr( $e['path'], -1 );
			$path_ok  = '' === $e['path'] || $path === $e['path'] || ( $prefix && 0 === strpos( $path, $e['path'] ) );
			$field_ok = '' === $e['field'] || $field === $e['field'];
			if ( $path_ok && $field_ok ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Adds an exception.
	 *
	 * @param string $rule  Rule key.
	 * @param string $path  Path, exact, or a prefix when it ends with /. Empty for everywhere.
	 * @param string $field Field such as POST:message, or empty for any field.
	 * @param bool   $exact Match the path exactly, even when it ends with /.
	 * @return bool Whether it was added.
	 */
	public static function add_exception( $rule, $path, $field, $exact = false ) {
		$rules = self::rules();
		if ( ! isset( $rules[ $rule ] ) ) {
			return false;
		}
		$list  = self::exceptions();
		$path  = '' === $path ? '' : '/' . ltrim( substr( (string) wp_parse_url( $path, PHP_URL_PATH ), 0, 200 ), '/' );
		$path  = strtolower( $path );
		$field = substr( (string) $field, 0, 120 );
		foreach ( $list as $e ) {
			if ( $e['rule'] === $rule && $e['path'] === $path && $e['field'] === $field && empty( $e['exact'] ) === ! $exact ) {
				return false;
			}
		}
		$list[] = array(
			'rule'  => $rule,
			'path'  => $path,
			'field' => $field,
			'exact' => (bool) $exact,
			'time'  => time(),
			'user'  => get_current_user_id(),
		);
		Network::update_option( self::EXCEPTIONS, array_slice( $list, -200 ), false );
		return true;
	}

	/**
	 * Turns a recorded hit into exceptions, so the same request goes through next time.
	 *
	 * Each exception covers only the rule, the field and the exact path of that
	 * request. The front page is never excepted, because a request made up for
	 * it would otherwise switch a rule off for a field the whole site uses.
	 *
	 * @param string      $ref Block reference.
	 * @param string|null $ip  Only when the hit came from this IP, such as the sender of a help message.
	 * @return bool Whether exceptions were added.
	 */
	public static function allow_reference( $ref, $ip = null ) {
		$hit = self::exceptable( $ref, $ip );
		if ( ! $hit ) {
			return false;
		}
		foreach ( $hit['hits'] as $h ) {
			self::add_exception( $h['rule'], $hit['path'], $h['field'], true );
		}
		Events::add(
			'settings',
			/* translators: 1: request path, 2: reference. */
			sprintf( __( 'Firewall exception added for %1$s (from blocked request %2$s).', 'chaos-shield' ), $hit['path'], $hit['ref'] ),
			Request::ip(),
			array(
				'severity' => Events::NOTICE,
				'action'   => 'fw.exception',
				'subject'  => $hit['path'],
			)
		);
		return true;
	}

	/**
	 * The recorded hit for a reference, when it may become exceptions.
	 *
	 * @param string      $ref Block reference.
	 * @param string|null $ip  Only when the hit came from this IP.
	 * @return array|null
	 */
	public static function exceptable( $ref, $ip = null ) {
		$hit = self::hit( $ref );
		if ( ! $hit || empty( $hit['hits'] ) || ( null !== $ip && ( '' === (string) $ip || (string) $hit['ip'] !== (string) $ip ) ) ) {
			return null;
		}
		$path = '/' . ltrim( (string) wp_parse_url( (string) $hit['path'], PHP_URL_PATH ), '/' );
		$home = '/' . trim( (string) wp_parse_url( home_url( '/' ), PHP_URL_PATH ), '/' );
		if ( '/' === $path || untrailingslashit( $path ) === untrailingslashit( $home ) ) {
			return null;
		}
		return $hit;
	}

	/**
	 * Finds the recorded hit for a reference.
	 *
	 * @param string $ref Block reference.
	 * @return array|null
	 */
	public static function hit( $ref ) {
		foreach ( self::hits() as $hit ) {
			if ( '' !== (string) $ref && strtolower( $hit['ref'] ) === strtolower( (string) $ref ) ) {
				return $hit;
			}
		}
		return null;
	}

	// Admin.

	/**
	 * Handles the Firewall tab forms.
	 */
	public static function handle() {
		if ( ! current_user_can( Network::cap() ) ) {
			wp_die( esc_html__( 'You are not allowed to change Chaos Shield settings.', 'chaos-shield' ), 403 );
		}
		check_admin_referer( 'cshield_firewall' );
		// phpcs:disable WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Each field is validated below.
		$op     = isset( $_POST['op'] ) ? sanitize_key( wp_unslash( $_POST['op'] ) ) : '';
		$notice = 'saved';
		if ( 'settings' === $op ) {
			$off   = isset( $_POST['rules_on'] ) ? array_diff( array_keys( self::rules( true ) ), array_map( 'sanitize_key', (array) wp_unslash( $_POST['rules_on'] ) ) ) : array_keys( self::rules( true ) );
			$mode  = isset( $_POST['mode'] ) && 'learn' === $_POST['mode'] ? 'learn' : 'block';
			$level = isset( $_POST['sensitivity'] ) ? sanitize_key( wp_unslash( $_POST['sensitivity'] ) ) : 'balanced';
			Settings::save_firewall( $mode, $level, array_values( $off ) );
			if ( 'learn' === $mode ) {
				$notice = 'fw_learning';
			}
		} elseif ( 'allow' === $op ) {
			self::allow_reference( isset( $_POST['ref'] ) ? sanitize_key( wp_unslash( $_POST['ref'] ) ) : '' );
			$notice = 'fw_allowed';
		} elseif ( 'remove' === $op ) {
			$index = isset( $_POST['exception'] ) ? absint( $_POST['exception'] ) : -1;
			$list  = self::exceptions();
			if ( isset( $list[ $index ] ) ) {
				unset( $list[ $index ] );
				Network::update_option( self::EXCEPTIONS, array_values( $list ), false );
			}
			$notice = 'fw_removed';
		} elseif ( 'uploads_on' === $op || 'uploads_off' === $op ) {
			$result = self::uploads_rule( 'uploads_on' === $op );
			if ( is_wp_error( $result ) ) {
				Network::set_transient( 'cshield_error_' . get_current_user_id(), $result->get_error_message(), MINUTE_IN_SECONDS );
				$notice = '';
			}
		}
		// phpcs:enable
		wp_safe_redirect( Admin::url( 'firewall', array( 'cshield_notice' => $notice ) ) );
		exit;
	}

	// PHP in uploads.

	/**
	 * Path of the uploads .htaccess.
	 *
	 * @return string
	 */
	private static function uploads_htaccess() {
		$dir = Network::uploads_dir();
		return '' === $dir ? '' : $dir . '/.htaccess';
	}

	/**
	 * Whether the no-PHP rule is in the uploads .htaccess.
	 *
	 * @return bool
	 */
	public static function uploads_protected() {
		$file = self::uploads_htaccess();
		return '' !== $file && is_file( $file ) && false !== strpos( (string) file_get_contents( $file ), self::UPLOADS_MARK ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file.
	}

	/**
	 * Adds or removes the rule that stops PHP from running in uploads (Apache and LiteSpeed).
	 *
	 * @param bool $on Add or remove.
	 * @return true|\WP_Error
	 */
	public static function uploads_rule( $on ) {
		$file = self::uploads_htaccess();
		if ( '' === $file ) {
			return new \WP_Error( 'cshield_up_dir', __( 'The uploads folder could not be found.', 'chaos-shield' ) );
		}
		$body  = is_file( $file ) ? (string) file_get_contents( $file ) : ''; // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file.
		$block = self::UPLOADS_MARK . "\n<FilesMatch \"\\.(php\\d?|phtml|phar|pht|phps)$\">\n\t<IfModule mod_authz_core.c>\n\t\tRequire all denied\n\t</IfModule>\n\t<IfModule !mod_authz_core.c>\n\t\tOrder allow,deny\n\t\tDeny from all\n\t</IfModule>\n</FilesMatch>\n# End Chaos Shield\n";
		$body  = preg_replace( '/' . preg_quote( self::UPLOADS_MARK, '/' ) . '.*?# End Chaos Shield\n?/s', '', $body );
		if ( $on ) {
			$body = rtrim( (string) $body ) . ( '' === trim( (string) $body ) ? '' : "\n\n" ) . $block;
		}
		// Not a change to report: the administrator asked for it.
		Integrity::expect( 'wp-content/uploads/.htaccess' );
		if ( '' === trim( (string) $body ) ) {
			if ( is_file( $file ) ) {
				wp_delete_file( $file );
			}
		} elseif ( false === file_put_contents( $file, $body ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Writes the uploads .htaccess on request.
			return new \WP_Error( 'cshield_up_write', __( 'Could not write the .htaccess file in uploads. Check the folder permissions.', 'chaos-shield' ) );
		}
		Events::add(
			'settings',
			$on ? __( 'PHP is now blocked from running in the uploads folder.', 'chaos-shield' ) : __( 'The rule blocking PHP in the uploads folder was removed.', 'chaos-shield' ),
			Request::ip(),
			array(
				'severity' => $on ? Events::INFO : Events::NOTICE,
				'action'   => 'fw.uploads_rule',
			)
		);
		return true;
	}

	// Output.

	/**
	 * Request path, lower-cased.
	 *
	 * @param bool $clean Strip to printable characters for the log.
	 * @return string
	 */
	private static function request_path( $clean = true ) {
		$uri  = isset( $_SERVER['REQUEST_URI'] ) ? (string) wp_unslash( $_SERVER['REQUEST_URI'] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Cleaned below or only inspected.
		$path = (string) wp_parse_url( $uri, PHP_URL_PATH );
		if ( ! $clean ) {
			return $path;
		}
		return substr( strtolower( sanitize_text_field( rawurldecode( $path ) ) ), 0, 200 );
	}

	/**
	 * Sends the 403 block page and stops.
	 *
	 * @param string $reason firewall, ban, blocklist, country or threat; shown to the visitor in plain words.
	 */
	public static function deny( $reason = 'firewall' ) {
		Traffic::note_block( 'blocked' );
		Attack_Mode::note();
		// The block page explains what happened and lets the visitor ask the owner for access.
		Help::block_page( 403, $reason, self::$reference );
	}
}
