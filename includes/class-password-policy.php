<?php
/**
 * Password rules, expiry and forced resets.
 *
 * @package ChaosShield
 */

namespace ChaosShield;

defined( 'ABSPATH' ) || exit;

/**
 * Enforces password length and variety, expires old passwords and lets
 * administrators force a reset.
 *
 * A user who must change their password and enters the right one is sent
 * straight to the screen for choosing a new one; their old sessions end.
 */
final class Password_Policy {

	const CHANGED_META = '_cshield_pw_changed';
	const FORCED_META  = '_cshield_force_reset';
	const SINCE_OPTION = 'cshield_pw_policy_since';

	/**
	 * Registers hooks.
	 */
	public function register() {
		// Forced resets work even with the policy module off.
		// After the CAPTCHA (30) and the lockout (99), so a locked-out guesser learns nothing.
		add_filter( 'authenticate', array( $this, 'login_gate' ), 999 );
		add_action( 'wp_set_password', array( $this, 'password_set' ), 10, 2 );
		add_action( 'profile_update', array( $this, 'profile_password_set' ), 10, 2 );
		add_action( 'user_register', array( $this, 'user_created' ) );
		add_filter( 'user_row_actions', array( $this, 'row_action' ), 10, 2 );
		add_filter( 'bulk_actions-users', array( $this, 'bulk_action' ) );
		add_filter( 'handle_bulk_actions-users', array( $this, 'handle_bulk' ), 10, 3 );
		add_action( 'admin_post_cshield_force_reset', array( $this, 'handle_force' ) );
		add_action( 'admin_notices', array( $this, 'users_notice' ) );
		add_filter( 'login_message', array( $this, 'reset_message' ) );

		if ( ! Settings::enabled( 'password_policy' ) ) {
			return;
		}
		if ( ! Network::get_option( self::SINCE_OPTION ) ) {
			// Passwords set before the policy was on count from today, so nobody expires at once.
			Network::update_option( self::SINCE_OPTION, time(), false );
		}
		add_action( 'user_profile_update_errors', array( $this, 'check_profile' ), 5, 3 );
		add_action( 'validate_password_reset', array( $this, 'check_reset' ), 5, 2 );
		add_action( 'resetpass_form', array( $this, 'reset_hint' ) );
	}

	// Rules.

	/**
	 * Whether the policy applies to a user.
	 *
	 * @param \WP_User|null $user  User, or null for a new account.
	 * @param string        $role  Role of a new or edited account, when known.
	 * @return bool
	 */
	public static function applies( $user, $role = '' ) {
		$scope = (string) Settings::get( 'pw_roles' );
		if ( 'all' === $scope ) {
			return true;
		}
		$cap = 'admins' === $scope ? 'manage_options' : 'edit_posts';
		if ( $role ) {
			$object = get_role( $role );
			if ( $object && $object->has_cap( $cap ) ) {
				return true;
			}
		}
		return $user instanceof \WP_User && $user->exists() && user_can( $user, $cap );
	}

	/**
	 * Problems with a password under the current rules.
	 *
	 * @param string $password Plain password.
	 * @param string $login    Username.
	 * @param string $email    Email.
	 * @return string[] Messages, empty when it passes.
	 */
	public static function problems( $password, $login = '', $email = '' ) {
		$problems = array();
		$min      = (int) Settings::get( 'pw_min_length' );
		if ( mb_strlen( $password ) < $min ) {
			/* translators: %d: minimum length. */
			$problems[] = sprintf( __( 'Use at least %d characters.', 'chaos-shield' ), $min );
		}
		$need = (int) Settings::get( 'pw_classes' );
		if ( self::classes( $password ) < $need ) {
			/* translators: %d: number of character kinds. */
			$problems[] = sprintf( __( 'Mix at least %d of these: lowercase letters, capital letters, numbers and symbols.', 'chaos-shield' ), $need );
		}
		$lower = mb_strtolower( $password );
		foreach ( array( $login, strstr( (string) $email, '@', true ) ) as $part ) {
			$part = mb_strtolower( (string) $part );
			if ( mb_strlen( $part ) >= 4 && false !== strpos( $lower, $part ) ) {
				$problems[] = __( 'Do not use your username or email address in the password.', 'chaos-shield' );
				break;
			}
		}
		return $problems;
	}

	/**
	 * Number of character kinds in a password.
	 *
	 * @param string $password Password.
	 * @return int 0 to 4.
	 */
	private static function classes( $password ) {
		$n = 0;
		foreach ( array( '/\p{Ll}/u', '/\p{Lu}/u', '/\p{N}/u', '/[^\p{L}\p{N}]/u' ) as $pattern ) {
			$n += (int) preg_match( $pattern, $password );
		}
		return $n;
	}

	/**
	 * Plain description of the rules.
	 *
	 * @return string
	 */
	public static function describe() {
		return sprintf(
			/* translators: 1: minimum length, 2: number of character kinds. */
			__( 'Passwords need at least %1$d characters and %2$d of these: lowercase letters, capital letters, numbers and symbols.', 'chaos-shield' ),
			(int) Settings::get( 'pw_min_length' ),
			(int) Settings::get( 'pw_classes' )
		);
	}

	/**
	 * Checks a password set on a profile or the Add User screen.
	 *
	 * @param \WP_Error $errors Errors.
	 * @param bool      $update Whether an existing user is updated.
	 * @param \stdClass $data   User data.
	 */
	public function check_profile( $errors, $update, $data ) {
		if ( empty( $data->user_pass ) ) {
			return;
		}
		$user = ! empty( $data->ID ) ? get_userdata( (int) $data->ID ) : null;
		$role = ! empty( $data->role ) ? (string) $data->role : '';
		if ( ! self::applies( $user, $role ) ) {
			return;
		}
		$problems = self::problems( (string) $data->user_pass, isset( $data->user_login ) ? (string) $data->user_login : ( $user ? $user->user_login : '' ), isset( $data->user_email ) ? (string) $data->user_email : '' );
		if ( $problems ) {
			$errors->add( 'cshield_password_policy', '<strong>' . esc_html__( 'Error:', 'chaos-shield' ) . '</strong> ' . esc_html( implode( ' ', $problems ) ), array( 'form-field' => 'pass1' ) );
		}
	}

	/**
	 * Checks a password chosen on the reset screen.
	 *
	 * @param \WP_Error          $errors Errors.
	 * @param \WP_User|\WP_Error $user   User.
	 */
	public function check_reset( $errors, $user ) {
		$pass = isset( $_POST['pass1'] ) ? (string) wp_unslash( $_POST['pass1'] ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Core checked the reset key; passwords are only hashed.
		if ( '' === $pass || ! $user instanceof \WP_User || ! self::applies( $user ) ) {
			return;
		}
		$problems = self::problems( $pass, $user->user_login, $user->user_email );
		if ( $problems ) {
			$errors->add( 'cshield_password_policy', '<strong>' . esc_html__( 'Error:', 'chaos-shield' ) . '</strong> ' . esc_html( implode( ' ', $problems ) ) );
		}
	}

	/**
	 * Shows the rules on the reset screen.
	 *
	 * @param \WP_User $user User.
	 */
	public function reset_hint( $user ) {
		if ( $user instanceof \WP_User && self::applies( $user ) ) {
			echo '<p class="description indicator-hint">' . esc_html( self::describe() ) . '</p>';
		}
	}

	// Expiry and forced resets.

	/**
	 * Why a user must choose a new password, or ''.
	 *
	 * @param \WP_User $user User.
	 * @return string forced, expired or ''.
	 */
	public static function reset_reason( $user ) {
		if ( get_user_meta( $user->ID, self::FORCED_META, true ) ) {
			return 'forced';
		}
		$days = (int) Settings::get( 'pw_max_age' );
		if ( ! Settings::enabled( 'password_policy' ) || $days <= 0 || ! self::applies( $user ) ) {
			return '';
		}
		$changed = max( (int) get_user_meta( $user->ID, self::CHANGED_META, true ), (int) Network::get_option( self::SINCE_OPTION ) );
		return $changed && time() - $changed > $days * DAY_IN_SECONDS ? 'expired' : '';
	}

	/**
	 * Whether an administrator forced a reset for this user.
	 *
	 * @param int $user_id User ID.
	 * @return bool
	 */
	public static function forced( $user_id ) {
		return (bool) get_user_meta( (int) $user_id, self::FORCED_META, true );
	}

	/**
	 * Stops a user who must change their password and emails them a reset link.
	 *
	 * The link only goes to the account's email address, never into the login
	 * response: a forced reset usually means the password leaked, so knowing it
	 * must not be enough to choose a new one.
	 *
	 * @param \WP_User|\WP_Error|null $user Authentication result so far.
	 * @return \WP_User|\WP_Error|null
	 */
	public function login_gate( $user ) {
		if ( ! $user instanceof \WP_User ) {
			return $user;
		}
		$reason = self::reset_reason( $user );
		if ( '' === $reason ) {
			return $user;
		}
		$message = 'forced' === $reason
			? __( 'An administrator asked you to choose a new password.', 'chaos-shield' )
			: __( 'Your password has expired.', 'chaos-shield' );

		$interactive = ! ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) && ! ( defined( 'REST_REQUEST' ) && REST_REQUEST ) && did_action( 'login_init' );
		if ( ! $interactive ) {
			return new \WP_Error( 'cshield_reset_required', $message . ' ' . __( 'Sign in on the website to choose a new one.', 'chaos-shield' ) );
		}

		// One email per user every 15 minutes, so the form cannot be used to flood an inbox.
		$throttle = 'cshield_rp_sent_' . $user->ID;
		if ( ! Network::get_transient( $throttle ) ) {
			Network::set_transient( $throttle, 1, 15 * MINUTE_IN_SECONDS );
			$sent = retrieve_password( $user->user_login );
			Events::add(
				'password',
				/* translators: 1: username, 2: forced or expired. */
				sprintf( __( '%1$s must choose a new password (%2$s). A reset link was emailed to them.', 'chaos-shield' ), $user->user_login, $reason ),
				Request::ip(),
				array(
					'user_id' => $user->ID,
					'action'  => 'user.reset_emailed',
				)
			);
			if ( is_wp_error( $sent ) ) {
				return new \WP_Error( 'cshield_reset_required', $message . ' ' . __( 'The reset email could not be sent. Ask an administrator for help.', 'chaos-shield' ) );
			}
		}
		return new \WP_Error( 'cshield_reset_required', $message . ' ' . __( 'We emailed you a link to choose a new one. Check your inbox.', 'chaos-shield' ) );
	}

	/**
	 * Explains on the reset screen why a new password is needed.
	 *
	 * @param string $message Login message.
	 * @return string
	 */
	public function reset_message( $message ) {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Display only.
		$reason = isset( $_GET['cshield_reason'] ) ? sanitize_key( wp_unslash( $_GET['cshield_reason'] ) ) : '';
		if ( 'forced' === $reason ) {
			$text = __( 'An administrator asked you to choose a new password before you continue.', 'chaos-shield' );
		} elseif ( 'expired' === $reason ) {
			$text = __( 'Your password has expired. Choose a new one to continue.', 'chaos-shield' );
		} else {
			return $message;
		}
		if ( Settings::enabled( 'password_policy' ) ) {
			$text .= ' ' . self::describe();
		}
		return $message . '<p class="message">' . esc_html( $text ) . '</p>';
	}

	/**
	 * Records a password change and clears a pending reset.
	 *
	 * @param string $password Plain password (unused).
	 * @param int    $user_id  User ID.
	 */
	public function password_set( $password, $user_id ) {
		self::changed( (int) $user_id );
	}

	/**
	 * Same for a password changed on a profile, which does not run wp_set_password.
	 *
	 * @param int      $user_id  User ID.
	 * @param \WP_User $old_user User before the update.
	 */
	public function profile_password_set( $user_id, $old_user ) {
		$user = get_userdata( $user_id );
		if ( $user && $old_user instanceof \WP_User && $user->user_pass !== $old_user->user_pass ) {
			self::changed( (int) $user_id );
		}
	}

	/**
	 * New accounts start their password age now.
	 *
	 * @param int $user_id User ID.
	 */
	public function user_created( $user_id ) {
		update_user_meta( (int) $user_id, self::CHANGED_META, time() );
	}

	/**
	 * Marks a password as changed.
	 *
	 * @param int $user_id User ID.
	 */
	private static function changed( $user_id ) {
		update_user_meta( $user_id, self::CHANGED_META, time() );
		if ( get_user_meta( $user_id, self::FORCED_META, true ) ) {
			delete_user_meta( $user_id, self::FORCED_META );
			$user = get_userdata( $user_id );
			/* translators: %s: username. */
			Events::add( 'password', sprintf( __( '%s chose a new password after a forced reset.', 'chaos-shield' ), $user ? $user->user_login : '#' . $user_id ), Request::ip(), array( 'user_id' => $user_id ) );
		}
	}

	/**
	 * Forces a user to choose a new password at their next login and signs them out everywhere.
	 *
	 * @param int $user_id User ID.
	 * @return bool
	 */
	public static function force( $user_id ) {
		$user = get_userdata( (int) $user_id );
		if ( ! $user ) {
			return false;
		}
		update_user_meta( $user->ID, self::FORCED_META, time() );
		\WP_Session_Tokens::get_instance( $user->ID )->destroy_all();
		Events::add(
			'password',
			/* translators: %s: username. */
			sprintf( __( 'Password reset forced for %s. Their sessions were ended.', 'chaos-shield' ), $user->user_login ),
			Request::ip(),
			array( 'severity' => Events::NOTICE )
		);
		return true;
	}

	/**
	 * Forces a reset for every user in a group, except the current user.
	 *
	 * @param string $group admins or policy (the roles the policy covers).
	 * @return int Users affected.
	 */
	public static function force_group( $group ) {
		$args = array(
			'fields' => 'ID',
			'number' => 2000,
		);
		if ( 'admins' === $group ) {
			$args['role__in'] = array( 'administrator' );
		}
		$count = 0;
		foreach ( get_users( $args ) as $id ) {
			$id = (int) $id;
			if ( get_current_user_id() === $id || ( is_user_logged_in() && ! current_user_can( 'edit_user', $id ) ) ) {
				continue;
			}
			if ( 'admins' !== $group && ! self::applies( get_userdata( $id ) ) ) {
				continue;
			}
			$count += (int) self::force( $id );
		}
		return $count;
	}

	/**
	 * Number of users who still have to choose a new password.
	 *
	 * @return int
	 */
	public static function pending_count() {
		return count(
			get_users(
				array(
					'meta_key' => self::FORCED_META, // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_key -- Small admin count.
					'fields'   => 'ID',
					'number'   => 2000,
				)
			)
		);
	}

	// Users screen.

	/**
	 * Adds "Force password reset" to each row of the Users list.
	 *
	 * @param array    $actions Actions.
	 * @param \WP_User $user    User.
	 * @return array
	 */
	public function row_action( $actions, $user ) {
		if ( ! current_user_can( 'edit_user', $user->ID ) || get_current_user_id() === $user->ID || ! current_user_can( 'manage_options' ) ) {
			return $actions;
		}
		if ( self::forced( $user->ID ) ) {
			$actions['cshield_reset'] = '<span class="description">' . esc_html__( 'Password reset pending', 'chaos-shield' ) . '</span>';
			return $actions;
		}
		$url                      = wp_nonce_url(
			add_query_arg(
				array(
					'action' => 'cshield_force_reset',
					'user'   => $user->ID,
				),
				admin_url( 'admin-post.php' )
			),
			'cshield_force_reset_' . $user->ID
		);
		$actions['cshield_reset'] = '<a href="' . esc_url( $url ) . '">' . esc_html__( 'Force password reset', 'chaos-shield' ) . '</a>';
		return $actions;
	}

	/**
	 * Adds the bulk action.
	 *
	 * @param array $actions Bulk actions.
	 * @return array
	 */
	public function bulk_action( $actions ) {
		if ( current_user_can( 'manage_options' ) ) {
			$actions['cshield_force_reset'] = __( 'Force password reset', 'chaos-shield' );
		}
		return $actions;
	}

	/**
	 * Runs the bulk action.
	 *
	 * @param string $redirect Redirect URL.
	 * @param string $action   Action.
	 * @param int[]  $ids      User IDs.
	 * @return string
	 */
	public function handle_bulk( $redirect, $action, $ids ) {
		if ( 'cshield_force_reset' !== $action || ! current_user_can( 'manage_options' ) ) {
			return $redirect;
		}
		$count = 0;
		foreach ( (array) $ids as $id ) {
			$id = (int) $id;
			if ( get_current_user_id() !== $id && current_user_can( 'edit_user', $id ) ) {
				$count += (int) self::force( $id );
			}
		}
		return add_query_arg( 'cshield_forced', $count, $redirect );
	}

	/**
	 * Row action and Hardening tab buttons.
	 */
	public function handle_force() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You are not allowed to do this.', 'chaos-shield' ), 403 );
		}
		// phpcs:disable WordPress.Security.NonceVerification -- Each branch checks its own nonce.
		$group = isset( $_REQUEST['group'] ) ? sanitize_key( wp_unslash( $_REQUEST['group'] ) ) : '';
		if ( $group ) {
			// Whole groups are a network-wide action, like the rest of the Hardening tab.
			if ( ! current_user_can( Network::cap() ) ) {
				wp_die( esc_html__( 'You are not allowed to do this.', 'chaos-shield' ), 403 );
			}
			check_admin_referer( 'cshield_force_group' );
			$count = self::force_group( 'admins' === $group ? 'admins' : 'policy' );
			wp_safe_redirect(
				Admin::url(
					'hardening',
					array(
						'cshield_notice' => 'forced',
						'forced'         => $count,
					)
				)
			);
			exit;
		}
		$id = isset( $_GET['user'] ) ? absint( $_GET['user'] ) : 0;
		// phpcs:enable
		check_admin_referer( 'cshield_force_reset_' . $id );
		$count = ( $id && get_current_user_id() !== $id && current_user_can( 'edit_user', $id ) ) ? (int) self::force( $id ) : 0;
		wp_safe_redirect( add_query_arg( 'cshield_forced', $count, admin_url( 'users.php' ) ) );
		exit;
	}

	/**
	 * Confirmation on the Users screen.
	 */
	public function users_notice() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Display only.
		if ( ! isset( $_GET['cshield_forced'] ) || 'users' !== get_current_screen()->id ) {
			return;
		}
		$count = absint( $_GET['cshield_forced'] ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Display only.
		printf(
			'<div class="notice notice-success is-dismissible"><p>%s</p></div>',
			esc_html(
				sprintf(
					/* translators: %d: number of users. */
					_n( 'Password reset forced for %d user. They were signed out and will choose a new password at their next login.', 'Password reset forced for %d users. They were signed out and will choose a new password at their next login.', $count, 'chaos-shield' ),
					$count
				)
			)
		);
	}
}
