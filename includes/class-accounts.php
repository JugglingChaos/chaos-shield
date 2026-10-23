<?php
/**
 * Account rules: idle sign out and approval of new sign-ups.
 *
 * @package ChaosShield
 */

namespace ChaosShield;

defined( 'ABSPATH' ) || exit;

/**
 * Signs out idle sessions and holds self-made accounts until an administrator approves them.
 */
final class Accounts {

	const PENDING = '_cshield_pending';
	const SEEN    = 'cshield_seen';

	/**
	 * Registers hooks.
	 */
	public function register() {
		add_action( 'init', array( $this, 'watch_session' ), 1 );
		add_filter( 'wp_login_errors', array( $this, 'login_notice' ) );

		// Held accounts can log in again if approval is switched off; they stay listed until approved.
		add_action( 'user_register', array( $this, 'hold_new_account' ), 5 );
		// After the password check and the lockout (99), so it never tells a guesser that the account exists.
		add_filter( 'authenticate', array( $this, 'refuse_pending' ), 990 );
		add_filter( 'user_row_actions', array( $this, 'row_action' ), 10, 2 );
		add_filter( 'bulk_actions-users', array( $this, 'bulk_action' ) );
		add_filter( 'handle_bulk_actions-users', array( $this, 'handle_bulk' ), 10, 3 );
		add_filter( 'views_users', array( $this, 'pending_view' ) );
		add_action( 'pre_get_users', array( $this, 'filter_pending' ) );
		add_action( 'admin_post_cshield_approve', array( $this, 'handle_approve' ) );
		add_action( 'admin_notices', array( $this, 'pending_notice' ) );
	}

	/**
	 * Whether a rule set for a group of roles covers a user.
	 *
	 * @param \WP_User|null $user  User.
	 * @param string        $scope admins, staff (everyone who can write posts) or all.
	 * @param string        $role  Role of a new or edited account, when known.
	 * @return bool
	 */
	public static function covers( $user, $scope, $role = '' ) {
		if ( 'all' === $scope ) {
			return true;
		}
		if ( ! in_array( $scope, array( 'admins', 'staff' ), true ) ) {
			return false;
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

	// Idle sign out.

	/**
	 * Ends a session that was idle for too long, and notes activity on the others.
	 *
	 * Heartbeat pings from an open tab do not count as activity, so a dashboard left open still signs out.
	 */
	public function watch_session() {
		if ( ! is_user_logged_in() || ( defined( 'WP_CLI' ) && WP_CLI ) || wp_doing_cron() ) {
			return;
		}
		$user = wp_get_current_user();
		if ( Settings::enabled( 'approve_signups' ) && self::pending( $user->ID ) ) {
			// A plugin logged a held account straight in, for example after a shop checkout.
			\WP_Session_Tokens::get_instance( $user->ID )->destroy_all();
			wp_clear_auth_cookie();
			wp_set_current_user( 0 );
			return;
		}
		$minutes = (int) Settings::get( 'idle_minutes' );
		$token   = wp_get_session_token();
		if ( ! $minutes || '' === $token || ! self::covers( $user, (string) Settings::get( 'idle_roles' ) ) ) {
			return;
		}
		$manager = \WP_Session_Tokens::get_instance( $user->ID );
		$session = $manager->get( $token );
		if ( ! is_array( $session ) ) {
			return;
		}
		$now  = time();
		$seen = isset( $session[ self::SEEN ] ) ? (int) $session[ self::SEEN ] : ( isset( $session['login'] ) ? (int) $session['login'] : $now );
		if ( $now - $seen > $minutes * MINUTE_IN_SECONDS ) {
			$manager->destroy( $token );
			wp_clear_auth_cookie();
			wp_set_current_user( 0 );
			Events::add(
				'user',
				/* translators: 1: username, 2: minutes. */
				sprintf( __( '%1$s was signed out after %2$d minutes without activity.', 'chaos-shield' ), $user->user_login, $minutes ),
				Request::ip(),
				array(
					'user_id' => $user->ID,
					'action'  => 'auth.idle_logout',
				)
			);
			if ( ! wp_doing_ajax() && ! self::is_rest() && 'GET' === Request::server( 'REQUEST_METHOD' ) ) {
				$back = is_admin() ? admin_url() : home_url( '/' );
				wp_safe_redirect( add_query_arg( 'cshield_idle', '1', wp_login_url( $back ) ) );
				exit;
			}
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Only reads which AJAX action this is.
		$heartbeat = wp_doing_ajax() && isset( $_POST['action'] ) && 'heartbeat' === $_POST['action'];
		if ( ! $heartbeat && $now - $seen >= MINUTE_IN_SECONDS ) {
			$session[ self::SEEN ] = $now;
			$manager->update( $token, $session );
		}
	}

	/**
	 * Whether this is a REST API request, known before WordPress parses it.
	 *
	 * @return bool
	 */
	private static function is_rest() {
		$path   = (string) wp_parse_url( Request::server( 'REQUEST_URI' ), PHP_URL_PATH );
		$prefix = '/' . trim( rest_get_url_prefix(), '/' ) . '/';
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Only reads which kind of request this is.
		return false !== strpos( $path, $prefix ) || isset( $_GET['rest_route'] );
	}

	/**
	 * Explains on the login screen why the user is there.
	 *
	 * @param \WP_Error $errors Login screen messages.
	 * @return \WP_Error
	 */
	public function login_notice( $errors ) {
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- Display only.
		if ( isset( $_GET['cshield_idle'] ) ) {
			$errors->add( 'cshield_idle', __( 'You were signed out because the session was idle. Please log in again.', 'chaos-shield' ), 'message' );
		}
		if ( isset( $_GET['cshield_keys'] ) ) {
			$errors->add( 'cshield_keys', __( 'The site security keys were replaced, so everyone was signed out. Please log in again.', 'chaos-shield' ), 'message' );
		}
		// phpcs:enable
		return $errors;
	}

	// Approval of new sign-ups.

	/**
	 * Whether an account waits for approval.
	 *
	 * @param int $user_id User ID.
	 * @return bool
	 */
	public static function pending( $user_id ) {
		return (bool) get_user_meta( (int) $user_id, self::PENDING, true );
	}

	/**
	 * Holds an account a visitor made for themselves.
	 *
	 * @param int $user_id New user.
	 */
	public function hold_new_account( $user_id ) {
		if ( ! Settings::enabled( 'approve_signups' ) || ( is_user_logged_in() && ( current_user_can( 'create_users' ) || current_user_can( 'promote_users' ) ) ) || ( defined( 'WP_CLI' ) && WP_CLI ) ) {
			return;
		}
		$user = get_userdata( $user_id );
		if ( ! $user ) {
			return;
		}
		update_user_meta( $user_id, self::PENDING, time() );
		Events::add(
			'user',
			/* translators: %s: username. */
			sprintf( __( 'New account %s is waiting for approval.', 'chaos-shield' ), $user->user_login ),
			Request::ip(),
			array(
				'user_id' => $user_id,
				'action'  => 'user.pending',
				'subject' => $user->user_login,
			)
		);
		wp_mail(
			Settings::alert_email(),
			sprintf( '[%s] %s', wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ), __( 'A new account is waiting for approval', 'chaos-shield' ) ),
			sprintf(
				/* translators: 1: username, 2: email, 3: link. */
				__( "%1\$s (%2\$s) signed up and cannot log in until you approve the account:\n\n%3\$s", 'chaos-shield' ),
				$user->user_login,
				$user->user_email,
				add_query_arg( 'cshield_pending', '1', admin_url( 'users.php' ) )
			)
		);
	}

	/**
	 * Refuses a correct login to an account that waits for approval.
	 *
	 * @param \WP_User|\WP_Error|null $user Authentication result.
	 * @return \WP_User|\WP_Error|null
	 */
	public function refuse_pending( $user ) {
		if ( $user instanceof \WP_User && Settings::enabled( 'approve_signups' ) && self::pending( $user->ID ) ) {
			return new \WP_Error( 'cshield_pending', __( '<strong>Your account is waiting for approval.</strong> You will get an email as soon as the site owner approves it.', 'chaos-shield' ) );
		}
		return $user;
	}

	/**
	 * Approves an account and tells its owner.
	 *
	 * @param int $user_id User ID.
	 * @return bool
	 */
	public static function approve( $user_id ) {
		$user = get_userdata( (int) $user_id );
		if ( ! $user || ! self::pending( $user->ID ) ) {
			return false;
		}
		delete_user_meta( $user->ID, self::PENDING );
		Events::add(
			'user',
			/* translators: %s: username. */
			sprintf( __( 'Account %s was approved.', 'chaos-shield' ), $user->user_login ),
			Request::ip(),
			array(
				'action'  => 'user.approved',
				'subject' => $user->user_login,
			)
		);
		wp_mail(
			$user->user_email,
			sprintf( '[%s] %s', wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ), __( 'Your account was approved', 'chaos-shield' ) ),
			sprintf(
				/* translators: 1: site name, 2: login URL. */
				__( "Your account on %1\$s was approved. You can log in here:\n\n%2\$s", 'chaos-shield' ),
				wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ),
				wp_login_url()
			)
		);
		return true;
	}

	/**
	 * Number of accounts waiting for approval.
	 *
	 * @return int
	 */
	public static function pending_count() {
		return count(
			get_users(
				array(
					'meta_key' => self::PENDING, // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_key -- Small admin count.
					'fields'   => 'ID',
					'number'   => 2000,
				)
			)
		);
	}

	/**
	 * Adds "Approve" to rows that wait for approval.
	 *
	 * @param array    $actions Actions.
	 * @param \WP_User $user    User.
	 * @return array
	 */
	public function row_action( $actions, $user ) {
		if ( ! self::pending( $user->ID ) || ! current_user_can( 'edit_user', $user->ID ) ) {
			return $actions;
		}
		$url                        = wp_nonce_url(
			add_query_arg(
				array(
					'action' => 'cshield_approve',
					'user'   => $user->ID,
				),
				admin_url( 'admin-post.php' )
			),
			'cshield_approve_' . $user->ID
		);
		$actions['cshield_approve'] = '<a href="' . esc_url( $url ) . '"><strong>' . esc_html__( 'Approve', 'chaos-shield' ) . '</strong></a>';
		return $actions;
	}

	/**
	 * Adds the bulk action.
	 *
	 * @param array $actions Bulk actions.
	 * @return array
	 */
	public function bulk_action( $actions ) {
		if ( current_user_can( 'edit_users' ) ) {
			$actions['cshield_approve'] = __( 'Approve', 'chaos-shield' );
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
		if ( 'cshield_approve' !== $action ) {
			return $redirect;
		}
		$count = 0;
		foreach ( (array) $ids as $id ) {
			if ( current_user_can( 'edit_user', (int) $id ) ) {
				$count += (int) self::approve( (int) $id );
			}
		}
		return add_query_arg( 'cshield_approved', $count, remove_query_arg( 'cshield_pending', $redirect ) );
	}

	/**
	 * Row action handler.
	 */
	public function handle_approve() {
		$id = isset( $_GET['user'] ) ? absint( $_GET['user'] ) : 0; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Checked next.
		check_admin_referer( 'cshield_approve_' . $id );
		if ( ! current_user_can( 'edit_user', $id ) ) {
			wp_die( esc_html__( 'You are not allowed to do this.', 'chaos-shield' ), 403 );
		}
		$count = (int) self::approve( $id );
		wp_safe_redirect( add_query_arg( 'cshield_approved', $count, admin_url( 'users.php' ) ) );
		exit;
	}

	/**
	 * Adds "Waiting for approval" above the Users list.
	 *
	 * @param array $views Views.
	 * @return array
	 */
	public function pending_view( $views ) {
		$count = self::pending_count();
		if ( ! $count ) {
			return $views;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Display only.
		$current                  = isset( $_GET['cshield_pending'] );
		$views['cshield_pending'] = sprintf(
			'<a href="%s"%s>%s <span class="count">(%d)</span></a>',
			esc_url( add_query_arg( 'cshield_pending', '1', admin_url( 'users.php' ) ) ),
			$current ? ' class="current" aria-current="page"' : '',
			esc_html__( 'Waiting for approval', 'chaos-shield' ),
			$count
		);
		return $views;
	}

	/**
	 * Shows only held accounts when that view is picked.
	 *
	 * @param \WP_User_Query $query Query.
	 */
	public function filter_pending( $query ) {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Display only.
		if ( ! is_admin() || ! isset( $_GET['cshield_pending'] ) || ! function_exists( 'get_current_screen' ) || ! get_current_screen() || 'users' !== get_current_screen()->base ) {
			return;
		}
		$query->set( 'meta_key', self::PENDING ); // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_key -- Admin list filter.
	}

	/**
	 * Tells administrators that accounts are waiting, and confirms approvals.
	 */
	public function pending_notice() {
		$screen = get_current_screen();
		if ( ! $screen || ! current_user_can( 'edit_users' ) || ! in_array( $screen->base, array( 'users', 'dashboard' ), true ) ) {
			return;
		}
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- Display only.
		if ( isset( $_GET['cshield_approved'] ) ) {
			$done = absint( $_GET['cshield_approved'] );
			printf(
				'<div class="notice notice-success is-dismissible"><p>%s</p></div>',
				/* translators: %d: number of accounts. */
				esc_html( sprintf( _n( '%d account approved. Its owner was emailed.', '%d accounts approved. Their owners were emailed.', $done, 'chaos-shield' ), $done ) )
			);
		}
		$count = Settings::enabled( 'approve_signups' ) && ! isset( $_GET['cshield_pending'] ) ? self::pending_count() : 0;
		// phpcs:enable
		if ( $count ) {
			printf(
				'<div class="notice notice-info"><p>%s <a href="%s">%s</a></p></div>',
				/* translators: %d: number of accounts. */
				esc_html( sprintf( _n( 'Chaos Shield: %d new account is waiting for your approval.', 'Chaos Shield: %d new accounts are waiting for your approval.', $count, 'chaos-shield' ), $count ) ),
				esc_url( add_query_arg( 'cshield_pending', '1', admin_url( 'users.php' ) ) ),
				esc_html__( 'Review them', 'chaos-shield' )
			);
		}
	}

	// Public names.

	/**
	 * Accounts that publish under their login name, which hands attackers half of the login.
	 *
	 * @return string[] Logins, at most 500 accounts checked.
	 */
	public static function public_logins() {
		$found = array();
		$users = get_users(
			array(
				'capability' => 'edit_posts',
				'fields'     => array( 'ID', 'user_login', 'display_name' ),
				'number'     => 500,
			)
		);
		foreach ( $users as $user ) {
			if ( '' !== (string) $user->user_login && strtolower( trim( (string) $user->display_name ) ) === strtolower( (string) $user->user_login ) ) {
				$found[] = (string) $user->user_login;
			}
		}
		return $found;
	}
}
