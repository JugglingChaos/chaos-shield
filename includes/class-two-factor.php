<?php
/**
 * Two-factor login with an authenticator app.
 *
 * @package ChaosShield
 */

namespace ChaosShield;

defined( 'ABSPATH' ) || exit;

/**
 * Adds a code step after the password for users who turned two-factor on.
 */
final class Two_Factor {

	const META_SECRET   = '_cshield_2fa_secret';
	const META_PENDING  = '_cshield_2fa_pending';
	const META_RECOVERY = '_cshield_2fa_recovery';
	const META_LAST     = '_cshield_2fa_last_step';
	const META_LOGIN    = '_cshield_2fa_login';
	const MAX_TRIES     = 5;
	const CHALLENGE_TTL = 600;
	const RECOVERY_KEYS = 10;

	/**
	 * Session token created by the password step, destroyed if a code is needed.
	 *
	 * @var string
	 */
	private $token = '';

	/**
	 * Whether the password step asked to be remembered.
	 *
	 * @var bool
	 */
	private $remember = false;

	/**
	 * Set once the code step passed, so the login can finish.
	 *
	 * @var bool
	 */
	private $passed = false;

	/**
	 * Set by a passkey login, which already proved two factors on the device.
	 *
	 * @var bool
	 */
	public static $passkey_login = false;

	/**
	 * Profile error to report through user_profile_update_errors.
	 *
	 * @var string
	 */
	private $profile_error = '';

	/**
	 * Registers hooks.
	 */
	public function register() {
		add_action( 'set_logged_in_cookie', array( $this, 'capture_session' ), 10, 6 );
		add_action( 'wp_login', array( $this, 'interrupt_login' ), 1, 2 );
		add_action( 'login_form_cshield_2fa', array( $this, 'challenge_screen' ) );
		add_filter( 'authenticate', array( $this, 'block_xmlrpc_password' ), PHP_INT_MAX );
		add_filter( 'wp_login_errors', array( $this, 'expired_notice' ) );

		add_action( 'show_user_profile', array( $this, 'profile_section' ) );
		add_action( 'edit_user_profile', array( $this, 'profile_section' ) );
		add_action( 'personal_options_update', array( $this, 'profile_save' ) );
		add_action( 'edit_user_profile_update', array( $this, 'profile_save' ) );
		add_action( 'user_profile_update_errors', array( $this, 'profile_errors' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'profile_assets' ) );
		add_action( 'admin_notices', array( $this, 'admin_nag' ) );
	}

	/**
	 * Whether a user has two-factor turned on.
	 *
	 * @param int $user_id User ID.
	 * @return bool
	 */
	public static function is_enabled( $user_id ) {
		return '' !== (string) get_user_meta( $user_id, self::META_SECRET, true );
	}

	/**
	 * Administrators and how many of them use two-factor.
	 *
	 * @return array 'total' and 'enabled'.
	 */
	public static function admin_coverage() {
		$ids     = get_users(
			array(
				'role'   => 'administrator',
				'fields' => 'ID',
				'number' => 200,
			)
		);
		$enabled = 0;
		foreach ( $ids as $id ) {
			if ( self::is_enabled( (int) $id ) ) {
				++$enabled;
			}
		}
		return array(
			'total'   => count( $ids ),
			'enabled' => $enabled,
		);
	}

	/**
	 * Removes two-factor from a user.
	 *
	 * @param int $user_id User ID.
	 */
	public static function reset( $user_id ) {
		foreach ( array( self::META_SECRET, self::META_PENDING, self::META_RECOVERY, self::META_LAST, self::META_LOGIN ) as $key ) {
			delete_user_meta( $user_id, $key );
		}
	}

	// Login flow.

	/**
	 * Remembers the session the password step created.
	 *
	 * @param string $cookie     Cookie value.
	 * @param int    $expire     Cookie expiry, 0 for a browser session.
	 * @param int    $expiration Session expiry.
	 * @param int    $user_id    User ID.
	 * @param string $scheme     Cookie scheme.
	 * @param string $token      Session token.
	 */
	public function capture_session( $cookie, $expire, $expiration, $user_id, $scheme, $token ) {
		$this->token    = (string) $token;
		$this->remember = 0 !== (int) $expire;
	}

	/**
	 * Swaps a finished password login for the code step.
	 *
	 * @param string   $login Username.
	 * @param \WP_User $user  User.
	 */
	public function interrupt_login( $login, $user ) {
		if ( $this->passed || self::$passkey_login || ! self::active() || ! $user instanceof \WP_User || ! self::is_enabled( $user->ID ) ) {
			return;
		}

		// Undo the session and cookies the password step just created.
		if ( $this->token ) {
			\WP_Session_Tokens::get_instance( $user->ID )->destroy( $this->token );
		}
		wp_clear_auth_cookie();
		wp_set_current_user( 0 );

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Login redirect target, validated below.
		$redirect = isset( $_REQUEST['redirect_to'] ) ? esc_url_raw( wp_unslash( $_REQUEST['redirect_to'] ) ) : '';
		$token    = wp_generate_password( 40, false );

		update_user_meta(
			$user->ID,
			self::META_LOGIN,
			array(
				'hash'     => wp_hash( $token ),
				'expires'  => time() + self::CHALLENGE_TTL,
				'tries'    => 0,
				'remember' => $this->remember,
				'redirect' => wp_validate_redirect( $redirect, admin_url() ),
			)
		);

		wp_safe_redirect( self::challenge_url( $user->ID, $token ) );
		exit;
	}

	/**
	 * XML-RPC cannot show a code step, so accounts with two-factor must use an application password there.
	 *
	 * @param \WP_User|\WP_Error|null $user Authentication result.
	 * @return \WP_User|\WP_Error|null
	 */
	public function block_xmlrpc_password( $user ) {
		if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST && self::active() && $user instanceof \WP_User && self::is_enabled( $user->ID ) ) {
			return new \WP_Error( 'cshield_2fa_required', __( 'This account uses two-factor login. Use an application password instead.', 'chaos-shield' ) );
		}
		return $user;
	}

	/**
	 * Shows and processes the code form on wp-login.php?action=cshield_2fa.
	 */
	public function challenge_screen() {
		// phpcs:disable WordPress.Security.NonceVerification -- The one-time challenge token is the request credential.
		$user_id = isset( $_REQUEST['uid'] ) ? absint( $_REQUEST['uid'] ) : 0;
		$token   = isset( $_REQUEST['token'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['token'] ) ) : '';
		$code    = isset( $_POST['cshield_code'] ) ? sanitize_text_field( wp_unslash( $_POST['cshield_code'] ) ) : '';
		$posted  = isset( $_SERVER['REQUEST_METHOD'] ) && 'POST' === $_SERVER['REQUEST_METHOD'];
		// phpcs:enable

		$user      = $user_id ? get_userdata( $user_id ) : false;
		$challenge = $user ? self::challenge( $user_id, $token ) : false;
		if ( ! $challenge ) {
			wp_safe_redirect( add_query_arg( 'cshield_2fa', 'expired', wp_login_url() ) );
			exit;
		}

		$error = '';
		if ( $posted ) {
			$ip = Request::ip();
			if ( $ip && ! Firewall::allowlisted() && Login_Guard::locked_until( $ip ) ) {
				$error = __( 'Too many failed login attempts. Try again later.', 'chaos-shield' );
			} elseif ( $this->check_code( $user_id, $code ) ) {
				$this->finish_login( $user, $challenge );
			} else {
				++$challenge['tries'];
				do_action( 'wp_login_failed', $user->user_login, new \WP_Error( 'cshield_2fa_invalid' ) ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- WordPress's own hook, fired so other plugins see this sign-in.
				if ( $challenge['tries'] >= self::MAX_TRIES ) {
					delete_user_meta( $user_id, self::META_LOGIN );
					wp_safe_redirect( add_query_arg( 'cshield_2fa', 'expired', wp_login_url() ) );
					exit;
				}
				update_user_meta( $user_id, self::META_LOGIN, $challenge );
				$error = __( 'That code is not right. Check your authenticator app and try again.', 'chaos-shield' );
			}
		}

		$this->render_challenge( $user_id, $token, $error );
		exit;
	}

	/**
	 * Explains why the login screen came back after the code step.
	 *
	 * @param \WP_Error $errors Login screen messages.
	 * @return \WP_Error
	 */
	public function expired_notice( $errors ) {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Display only.
		if ( isset( $_GET['cshield_2fa'] ) && 'expired' === $_GET['cshield_2fa'] ) {
			$errors->add( 'cshield_2fa_expired', __( 'Your login step expired or had too many wrong codes. Please log in again.', 'chaos-shield' ) );
		}
		return $errors;
	}

	/**
	 * Valid, unexpired challenge for a user, or false.
	 *
	 * @param int    $user_id User ID.
	 * @param string $token   Token from the URL.
	 * @return array|false
	 */
	private static function challenge( $user_id, $token ) {
		$challenge = get_user_meta( $user_id, self::META_LOGIN, true );
		if ( ! is_array( $challenge ) || '' === $token || empty( $challenge['hash'] ) ) {
			return false;
		}
		if ( (int) $challenge['expires'] < time() || ! hash_equals( $challenge['hash'], wp_hash( $token ) ) ) {
			return false;
		}
		return $challenge;
	}

	/**
	 * Accepts a current authenticator code or an unused recovery code.
	 *
	 * @param int    $user_id User ID.
	 * @param string $code    Code typed by the user.
	 * @return bool
	 */
	private function check_code( $user_id, $code ) {
		$secret = Totp::open( get_user_meta( $user_id, self::META_SECRET, true ) );
		if ( $secret ) {
			$step = Totp::verify( $secret, $code, (int) get_user_meta( $user_id, self::META_LAST, true ) );
			if ( false !== $step ) {
				update_user_meta( $user_id, self::META_LAST, $step );
				return true;
			}
		}

		$normal = strtolower( preg_replace( '/[^a-z0-9]/i', '', $code ) );
		if ( strlen( $normal ) !== 10 ) {
			return false;
		}
		$hashes = (array) get_user_meta( $user_id, self::META_RECOVERY, true );
		foreach ( $hashes as $i => $hash ) {
			if ( wp_check_password( $normal, $hash ) ) {
				unset( $hashes[ $i ] );
				update_user_meta( $user_id, self::META_RECOVERY, array_values( $hashes ) );
				Events::add( 'twofactor', __( 'A recovery code was used to log in.', 'chaos-shield' ), Request::ip(), array( 'action' => 'auth.recovery_code' ) );
				return true;
			}
		}
		return false;
	}

	/**
	 * Logs the user in after the code step.
	 *
	 * @param \WP_User $user      User.
	 * @param array    $challenge Challenge data.
	 */
	private function finish_login( $user, array $challenge ) {
		delete_user_meta( $user->ID, self::META_LOGIN );
		$this->passed = true;

		wp_set_auth_cookie( $user->ID, ! empty( $challenge['remember'] ), is_ssl() );
		wp_set_current_user( $user->ID );
		do_action( 'wp_login', $user->user_login, $user ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Core hook.

		$redirect = apply_filters( 'login_redirect', $challenge['redirect'], $challenge['redirect'], $user ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Core hook.
		wp_safe_redirect( $redirect ? $redirect : admin_url() );
		exit;
	}

	/**
	 * Prints the code form using the standard login screen.
	 *
	 * @param int    $user_id User ID.
	 * @param string $token   Challenge token.
	 * @param string $error   Error message.
	 */
	private function render_challenge( $user_id, $token, $error ) {
		$errors = new \WP_Error();
		if ( $error ) {
			$errors->add( 'cshield_2fa', $error );
		}
		login_header( __( 'Two-factor login', 'chaos-shield' ), '', $errors );
		?>
		<form name="cshield_2fa" id="loginform" action="<?php echo esc_url( self::challenge_url( $user_id, $token ) ); ?>" method="post" autocomplete="off">
			<p><?php esc_html_e( 'Open your authenticator app and enter the 6-digit code for this site. You can also use one of your recovery codes.', 'chaos-shield' ); ?></p>
			<p style="margin-top:16px">
				<label for="cshield_code"><?php esc_html_e( 'Authentication code', 'chaos-shield' ); ?></label>
				<input type="text" name="cshield_code" id="cshield_code" class="input" value="" size="20" inputmode="numeric" autocomplete="one-time-code" autofocus required>
			</p>
			<p class="submit">
				<input type="submit" class="button button-primary button-large" value="<?php esc_attr_e( 'Verify', 'chaos-shield' ); ?>">
			</p>
		</form>
		<p id="nav"><a href="<?php echo esc_url( wp_login_url() ); ?>"><?php esc_html_e( 'Start over', 'chaos-shield' ); ?></a></p>
		<?php
		login_footer( 'cshield_code' );
	}

	/**
	 * URL of the code step.
	 *
	 * @param int    $user_id User ID.
	 * @param string $token   Token.
	 * @return string
	 */
	private static function challenge_url( $user_id, $token ) {
		return add_query_arg(
			array(
				'action' => 'cshield_2fa',
				'uid'    => $user_id,
				'token'  => $token,
			),
			wp_login_url()
		);
	}

	/**
	 * Whether the module is switched on.
	 *
	 * @return bool
	 */
	private static function active() {
		return Settings::enabled( 'two_factor' );
	}

	// Profile screen.

	/**
	 * Loads the QR code script on profile screens.
	 *
	 * @param string $hook Admin page hook.
	 */
	public function profile_assets( $hook ) {
		if ( ! self::active() || ! in_array( $hook, array( 'profile.php', 'user-edit.php' ), true ) ) {
			return;
		}
		wp_enqueue_script( 'cshield-qrcode', CSHIELD_URL . 'assets/js/vendor/qrcode.js', array(), '1.4.4', true );
		wp_enqueue_script( 'cshield-profile', CSHIELD_URL . 'assets/js/profile.js', array( 'cshield-qrcode' ), CSHIELD_VERSION, true );
		wp_enqueue_style( 'cshield-profile', CSHIELD_URL . 'assets/css/profile.css', array(), CSHIELD_VERSION );
	}

	/**
	 * Prints the two-factor section of a profile.
	 *
	 * @param \WP_User $user User being edited.
	 */
	public function profile_section( $user ) {
		if ( ! self::active() ) {
			return;
		}
		$own     = get_current_user_id() === $user->ID;
		$enabled = self::is_enabled( $user->ID );
		?>
		<div class="cshield-2fa" id="cshield-2fa">
			<h2><?php esc_html_e( 'Two-factor login', 'chaos-shield' ); ?></h2>
			<?php
			if ( ! $own ) {
				$this->profile_other( $user, $enabled );
			} elseif ( $enabled ) {
				$this->profile_enabled( $user );
			} else {
				$this->profile_setup( $user );
			}
			?>
		</div>
		<?php
	}

	/**
	 * Section shown to an admin editing someone else.
	 *
	 * @param \WP_User $user    User.
	 * @param bool     $enabled Whether two-factor is on.
	 */
	private function profile_other( $user, $enabled ) {
		if ( ! $enabled ) {
			echo '<p>' . esc_html__( 'This user has not turned on two-factor login. They can set it up from their own profile.', 'chaos-shield' ) . '</p>';
			return;
		}
		?>
		<p><span class="cshield-2fa__on"><?php esc_html_e( 'On', 'chaos-shield' ); ?></span> <?php esc_html_e( 'This user signs in with an authenticator app.', 'chaos-shield' ); ?></p>
		<?php if ( current_user_can( 'edit_user', $user->ID ) ) : ?>
			<label><input type="checkbox" name="cshield_2fa_reset" value="1"> <?php esc_html_e( 'Turn off two-factor for this user (for a lost phone). They can set it up again afterwards.', 'chaos-shield' ); ?></label>
		<?php endif; ?>
		<?php
	}

	/**
	 * Section for a user who already has two-factor.
	 *
	 * @param \WP_User $user User.
	 */
	private function profile_enabled( $user ) {
		$codes    = Network::get_transient( 'cshield_2fa_codes_' . $user->ID );
		$left     = count( (array) get_user_meta( $user->ID, self::META_RECOVERY, true ) );
		$readable = false !== Totp::open( get_user_meta( $user->ID, self::META_SECRET, true ) );
		if ( $codes ) {
			Network::delete_transient( 'cshield_2fa_codes_' . $user->ID );
			$this->print_codes( $codes );
		}
		?>
		<p><span class="cshield-2fa__on"><?php esc_html_e( 'On', 'chaos-shield' ); ?></span>
			<?php
			printf(
				/* translators: %d: number of unused recovery codes. */
				esc_html( _n( 'You sign in with your authenticator app. %d recovery code left.', 'You sign in with your authenticator app. %d recovery codes left.', $left, 'chaos-shield' ) ),
				(int) $left
			);
			?>
		</p>
		<?php if ( ! $readable ) : ?>
			<p class="cshield-2fa__warn"><?php esc_html_e( 'Your authenticator key can no longer be read, usually because the site security keys in wp-config.php changed. Log in with a recovery code, turn two-factor off and set it up again.', 'chaos-shield' ); ?></p>
		<?php endif; ?>
		<table class="form-table" role="presentation">
			<tr>
				<th scope="row"><?php esc_html_e( 'Recovery codes', 'chaos-shield' ); ?></th>
				<td><label><input type="checkbox" name="cshield_2fa_regen" value="1"> <?php esc_html_e( 'Replace my recovery codes with a new set', 'chaos-shield' ); ?></label></td>
			</tr>
			<tr>
				<th scope="row"><label for="cshield_2fa_off_code"><?php esc_html_e( 'Turn off', 'chaos-shield' ); ?></label></th>
				<td>
					<input type="text" id="cshield_2fa_off_code" name="cshield_2fa_off_code" class="regular-text" inputmode="numeric" autocomplete="one-time-code" placeholder="123456">
					<p class="description"><?php esc_html_e( 'To turn two-factor off, enter a current code from your app or a recovery code, then update your profile.', 'chaos-shield' ); ?></p>
				</td>
			</tr>
		</table>
		<?php
	}

	/**
	 * Setup section with QR code.
	 *
	 * @param \WP_User $user User.
	 */
	private function profile_setup( $user ) {
		$secret = Totp::open( get_user_meta( $user->ID, self::META_PENDING, true ) );
		if ( ! $secret ) {
			$secret = Totp::new_secret();
			update_user_meta( $user->ID, self::META_PENDING, Totp::seal( $secret ) );
		}
		$uri = Totp::uri( $secret, $user->user_login );
		?>
		<p><?php esc_html_e( 'Add a second step to your login: after your password, you enter a code from an authenticator app such as Google Authenticator, Microsoft Authenticator, Authy or 1Password.', 'chaos-shield' ); ?></p>
		<div class="cshield-2fa__setup">
			<div class="cshield-2fa__qr" data-uri="<?php echo esc_attr( $uri ); ?>" role="img" aria-label="<?php esc_attr_e( 'QR code for your authenticator app', 'chaos-shield' ); ?>"></div>
			<ol>
				<li><?php esc_html_e( 'Scan the QR code with your authenticator app.', 'chaos-shield' ); ?>
					<br><span class="description"><?php esc_html_e( 'Cannot scan? Enter this key by hand:', 'chaos-shield' ); ?></span>
					<code class="cshield-2fa__key"><?php echo esc_html( trim( chunk_split( $secret, 4, ' ' ) ) ); ?></code>
				</li>
				<li>
					<label for="cshield_2fa_code"><?php esc_html_e( 'Enter the 6-digit code the app shows:', 'chaos-shield' ); ?></label><br>
					<input type="text" id="cshield_2fa_code" name="cshield_2fa_code" class="regular-text" inputmode="numeric" autocomplete="one-time-code" placeholder="123456" maxlength="7">
				</li>
				<li><?php esc_html_e( 'Click Update Profile. You will then see your recovery codes.', 'chaos-shield' ); ?></li>
			</ol>
		</div>
		<?php
	}

	/**
	 * Prints new recovery codes once.
	 *
	 * @param array $codes Plain codes.
	 */
	private function print_codes( array $codes ) {
		?>
		<div class="cshield-2fa__codes">
			<p><strong><?php esc_html_e( 'Save these recovery codes now.', 'chaos-shield' ); ?></strong>
				<?php esc_html_e( 'Each one logs you in once if you lose your phone. They will not be shown again.', 'chaos-shield' ); ?></p>
			<ul>
				<?php foreach ( $codes as $code ) : ?>
					<li><code><?php echo esc_html( substr( $code, 0, 5 ) . '-' . substr( $code, 5 ) ); ?></code></li>
				<?php endforeach; ?>
			</ul>
		</div>
		<?php
	}

	/**
	 * Handles two-factor fields when a profile is saved. Core has already checked the nonce.
	 *
	 * @param int $user_id User being saved.
	 */
	public function profile_save( $user_id ) {
		if ( ! self::active() || ! current_user_can( 'edit_user', $user_id ) ) {
			return;
		}
		// phpcs:disable WordPress.Security.NonceVerification.Missing -- Verified by core (update-user_{id}) before this hook.
		$own = get_current_user_id() === (int) $user_id;

		if ( ! $own ) {
			if ( ! empty( $_POST['cshield_2fa_reset'] ) && self::is_enabled( $user_id ) ) {
				self::reset( $user_id );
				$target = get_userdata( $user_id );
				Events::add(
					'twofactor',
					/* translators: %s: username. */
					sprintf( __( 'Two-factor turned off for %s by an administrator.', 'chaos-shield' ), $target ? $target->user_login : $user_id ),
					Request::ip(),
					array( 'action' => 'auth.2fa_removed' )
				);
			}
			return;
		}

		if ( ! self::is_enabled( $user_id ) ) {
			$code = isset( $_POST['cshield_2fa_code'] ) ? sanitize_text_field( wp_unslash( $_POST['cshield_2fa_code'] ) ) : '';
			if ( '' === $code ) {
				return;
			}
			$sealed = get_user_meta( $user_id, self::META_PENDING, true );
			$secret = Totp::open( $sealed );
			$step   = $secret ? Totp::verify( $secret, $code ) : false;
			if ( false === $step ) {
				$this->profile_error = __( 'Two-factor was not turned on: the code did not match. Make sure the time on your phone is correct and try again.', 'chaos-shield' );
				return;
			}
			update_user_meta( $user_id, self::META_SECRET, $sealed );
			update_user_meta( $user_id, self::META_LAST, $step );
			delete_user_meta( $user_id, self::META_PENDING );
			$this->issue_codes( $user_id );
			Events::add( 'twofactor', __( 'A user turned on two-factor login.', 'chaos-shield' ), Request::ip() );
			return;
		}

		$off = isset( $_POST['cshield_2fa_off_code'] ) ? sanitize_text_field( wp_unslash( $_POST['cshield_2fa_off_code'] ) ) : '';
		if ( '' !== $off ) {
			if ( $this->check_code( $user_id, $off ) ) {
				self::reset( $user_id );
				Events::add( 'twofactor', __( 'A user turned off two-factor login.', 'chaos-shield' ), Request::ip(), array( 'action' => 'auth.2fa_removed' ) );
			} else {
				$this->profile_error = __( 'Two-factor is still on: the code did not match.', 'chaos-shield' );
			}
			return;
		}

		if ( ! empty( $_POST['cshield_2fa_regen'] ) ) {
			$this->issue_codes( $user_id );
		}
		// phpcs:enable
	}

	/**
	 * Reports a two-factor problem on the profile screen.
	 *
	 * @param \WP_Error $errors Profile errors.
	 */
	public function profile_errors( $errors ) {
		if ( $this->profile_error ) {
			$errors->add( 'cshield_2fa', $this->profile_error );
		}
	}

	/**
	 * Creates new recovery codes, storing only their hashes.
	 *
	 * @param int $user_id User ID.
	 */
	private function issue_codes( $user_id ) {
		$plain  = array();
		$hashes = array();
		for ( $i = 0; $i < self::RECOVERY_KEYS; $i++ ) {
			$code     = strtolower( wp_generate_password( 10, false ) );
			$plain[]  = $code;
			$hashes[] = wp_hash_password( $code );
		}
		update_user_meta( $user_id, self::META_RECOVERY, $hashes );
		Network::set_transient( 'cshield_2fa_codes_' . $user_id, $plain, 10 * MINUTE_IN_SECONDS );
	}

	/**
	 * Reminds administrators without two-factor, on the main dashboard only.
	 */
	public function admin_nag() {
		$screen = get_current_screen();
		if ( ! self::active() || ! $screen || 'dashboard' !== $screen->id || ! current_user_can( 'manage_options' ) || self::is_enabled( get_current_user_id() ) ) {
			return;
		}
		printf(
			'<div class="notice notice-warning"><p>%s <a href="%s">%s</a></p></div>',
			esc_html__( 'Chaos Shield: your administrator account has no second login step.', 'chaos-shield' ),
			esc_url( admin_url( 'profile.php#cshield-2fa' ) ),
			esc_html__( 'Turn on two-factor login', 'chaos-shield' )
		);
	}
}
