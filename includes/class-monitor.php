<?php
/**
 * Activity monitoring: logins, users, plugins, themes and core.
 *
 * @package ChaosShield
 */

namespace ChaosShield;

defined( 'ABSPATH' ) || exit;

/**
 * Logs important changes to the site and raises alerts for the risky ones.
 */
final class Monitor {

	const KNOWN_IPS_META = '_cshield_known_ips';

	/**
	 * Registers hooks.
	 */
	public function register() {
		// After the two-factor step, which runs at priority 1 and stops unfinished logins.
		add_action( 'wp_login', array( $this, 'login' ), 20, 2 );
		add_action( 'after_password_reset', array( $this, 'password_reset' ) );
		add_action( 'user_register', array( $this, 'user_created' ) );
		add_action( 'set_user_role', array( $this, 'role_changed' ), 10, 3 );
		add_action( 'delete_user', array( $this, 'user_deleted' ) );
		add_action( 'activated_plugin', array( $this, 'plugin_activated' ) );
		add_action( 'deactivated_plugin', array( $this, 'plugin_deactivated' ) );
		add_action( 'deleted_plugin', array( $this, 'plugin_deleted' ), 10, 2 );
		add_action( 'upgrader_process_complete', array( $this, 'upgraded' ), 10, 2 );
		add_action( 'switch_theme', array( $this, 'theme_switched' ) );
		add_action( '_core_updated_successfully', array( $this, 'core_updated' ) );
	}

	/**
	 * Successful login.
	 *
	 * @param string   $login Username.
	 * @param \WP_User $user  User.
	 */
	public function login( $login, $user ) {
		if ( ! $user instanceof \WP_User ) {
			return;
		}
		$ip    = Request::ip();
		$admin = user_can( $user, 'manage_options' );

		Events::add(
			'login',
			/* translators: %s: username. */
			sprintf( __( '%s logged in.', 'chaos-shield' ), $login ),
			$ip,
			array(
				'user_id' => $user->ID,
				'action'  => 'auth.login',
				'subject' => $login,
			)
		);

		if ( ! $admin || ! $ip ) {
			return;
		}

		$known = array_values( array_filter( (array) get_user_meta( $user->ID, self::KNOWN_IPS_META, true ) ) );
		if ( in_array( $ip, $known, true ) ) {
			return;
		}
		$first = ! $known;
		array_unshift( $known, $ip );
		update_user_meta( $user->ID, self::KNOWN_IPS_META, array_slice( $known, 0, 10 ) );

		// The very first login we see is the baseline, not a surprise.
		if ( $first ) {
			return;
		}
		Events::add(
			'login',
			/* translators: 1: username, 2: IP address. */
			sprintf( __( 'Administrator %1$s logged in from a new IP address (%2$s).', 'chaos-shield' ), $login, $ip ),
			$ip,
			array(
				'user_id'  => $user->ID,
				'severity' => Events::NOTICE,
				'action'   => 'auth.new_ip',
				'subject'  => $login,
			)
		);
		Alerts::send(
			'alert_admin_login',
			__( 'Administrator login from a new IP address', 'chaos-shield' ),
			sprintf(
				/* translators: 1: username, 2: IP address, 3: date and time. */
				__( "The administrator account \"%1\$s\" logged in from %2\$s, an address not seen for this account before, at %3\$s.\n\nIf this was not you, change the password, check Users for accounts you do not recognise, and block the IP under Chaos Shield > Access.", 'chaos-shield' ),
				$login,
				$ip,
				wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ) )
			),
			$user->ID . '|' . $ip
		);
	}

	/**
	 * Password reset by email link.
	 *
	 * @param \WP_User $user User.
	 */
	public function password_reset( $user ) {
		Events::add(
			'user',
			/* translators: %s: username. */
			sprintf( __( 'Password reset for %s.', 'chaos-shield' ), $user->user_login ),
			Request::ip(),
			array(
				'user_id'  => $user->ID,
				'severity' => Events::NOTICE,
				'action'   => 'user.password_reset',
				'subject'  => $user->user_login,
			)
		);
	}

	/**
	 * New user account.
	 *
	 * @param int $user_id New user ID.
	 */
	public function user_created( $user_id ) {
		$user = get_userdata( $user_id );
		if ( ! $user ) {
			return;
		}
		$roles = implode( ', ', $user->roles );
		$admin = in_array( 'administrator', $user->roles, true );
		Events::add(
			'user',
			/* translators: 1: username, 2: roles. */
			sprintf( __( 'User %1$s created with role %2$s.', 'chaos-shield' ), $user->user_login, $roles ? $roles : '-' ),
			Request::ip(),
			array(
				'severity' => $admin ? Events::CRITICAL : Events::INFO,
				'action'   => 'user.created',
				'subject'  => $user->user_login,
			)
		);
		if ( $admin ) {
			$this->alert_new_admin( $user->user_login, $user_id );
		}
	}

	/**
	 * Role change.
	 *
	 * @param int    $user_id   User ID.
	 * @param string $role      New role.
	 * @param array  $old_roles Previous roles.
	 */
	public function role_changed( $user_id, $role, $old_roles ) {
		// user_register already covered brand new accounts.
		if ( ! $old_roles || doing_action( 'user_register' ) ) {
			return;
		}
		$user = get_userdata( $user_id );
		if ( ! $user ) {
			return;
		}
		$promoted = 'administrator' === $role && ! in_array( 'administrator', (array) $old_roles, true );
		Events::add(
			'user',
			/* translators: 1: username, 2: old roles, 3: new role. */
			sprintf( __( 'Role of %1$s changed from %2$s to %3$s.', 'chaos-shield' ), $user->user_login, implode( ', ', (array) $old_roles ), $role ? $role : '-' ),
			Request::ip(),
			array(
				'severity' => $promoted ? Events::CRITICAL : Events::NOTICE,
				'action'   => 'user.role',
				'subject'  => $user->user_login,
			)
		);
		if ( $promoted ) {
			$this->alert_new_admin( $user->user_login, $user_id );
		}
	}

	/**
	 * Deleted user.
	 *
	 * @param int $user_id User ID.
	 */
	public function user_deleted( $user_id ) {
		$user = get_userdata( $user_id );
		Events::add(
			'user',
			/* translators: %s: username. */
			sprintf( __( 'User %s deleted.', 'chaos-shield' ), $user ? $user->user_login : '#' . $user_id ),
			Request::ip(),
			array(
				'severity' => Events::NOTICE,
				'action'   => 'user.deleted',
			)
		);
	}

	/**
	 * Plugin activated.
	 *
	 * @param string $plugin Plugin file.
	 */
	public function plugin_activated( $plugin ) {
		/* translators: %s: plugin name. */
		$this->plugin_event( $plugin, __( 'Plugin activated: %s', 'chaos-shield' ), true, 'plugin.activated' );
	}

	/**
	 * Plugin deactivated.
	 *
	 * @param string $plugin Plugin file.
	 */
	public function plugin_deactivated( $plugin ) {
		/* translators: %s: plugin name. */
		$this->plugin_event( $plugin, __( 'Plugin deactivated: %s', 'chaos-shield' ), false, 'plugin.deactivated' );
	}

	/**
	 * Plugin deleted.
	 *
	 * @param string $plugin  Plugin file.
	 * @param bool   $deleted Whether deletion worked.
	 */
	public function plugin_deleted( $plugin, $deleted ) {
		if ( $deleted ) {
			/* translators: %s: plugin name. */
			$this->plugin_event( $plugin, __( 'Plugin deleted: %s', 'chaos-shield' ), true, 'plugin.deleted' );
		}
	}

	/**
	 * Plugin, theme or core installed or updated through the upgrader.
	 *
	 * @param \WP_Upgrader $upgrader Upgrader.
	 * @param array        $extra    Details: action, type, plugins, themes.
	 */
	public function upgraded( $upgrader, $extra ) {
		$action = isset( $extra['action'] ) ? $extra['action'] : '';
		$type   = isset( $extra['type'] ) ? $extra['type'] : '';
		if ( ! in_array( $type, array( 'plugin', 'theme' ), true ) ) {
			return;
		}

		$names = array();
		if ( 'install' === $action && ! empty( $upgrader->new_plugin_data['Name'] ) ) {
			$names[] = $upgrader->new_plugin_data['Name'];
		} elseif ( 'install' === $action && ! empty( $upgrader->new_theme_data['Name'] ) ) {
			$names[] = $upgrader->new_theme_data['Name'];
		} elseif ( ! empty( $extra['plugins'] ) ) {
			$names = (array) $extra['plugins'];
		} elseif ( ! empty( $extra['themes'] ) ) {
			$names = (array) $extra['themes'];
		} elseif ( ! empty( $extra['plugin'] ) ) {
			$names[] = $extra['plugin'];
		} elseif ( ! empty( $extra['theme'] ) ) {
			$names[] = $extra['theme'];
		}
		$list = $names ? implode( ', ', array_map( 'strval', $names ) ) : '-';
		$this->expect_changes( $upgrader, $type, $extra );

		if ( 'install' === $action ) {
			$message = 'plugin' === $type
				/* translators: %s: plugin name. */
				? sprintf( __( 'Plugin installed: %s', 'chaos-shield' ), $list )
				/* translators: %s: theme name. */
				: sprintf( __( 'Theme installed: %s', 'chaos-shield' ), $list );
			Events::add(
				$type,
				$message,
				Request::ip(),
				array(
					'severity' => Events::NOTICE,
					'action'   => $type . '.installed',
					'subject'  => $list,
				)
			);
			Alerts::send( 'alert_plugin_changes', $message, $message, $message );
			return;
		}

		$message = 'plugin' === $type
			/* translators: %s: plugin names. */
			? sprintf( __( 'Plugins updated: %s', 'chaos-shield' ), $list )
			/* translators: %s: theme names. */
			: sprintf( __( 'Themes updated: %s', 'chaos-shield' ), $list );
		Events::add( $type, $message, Request::ip(), array( 'action' => $type . '.updated' ) );
	}

	/**
	 * Tells the scanner which folders the updater just changed.
	 *
	 * @param \WP_Upgrader $upgrader Upgrader.
	 * @param string       $type     plugin or theme.
	 * @param array        $extra    Upgrader details.
	 */
	private function expect_changes( $upgrader, $type, $extra ) {
		$base    = 'plugin' === $type ? '@content/plugins/' : '@content/themes/';
		$folders = array();
		if ( ! empty( $upgrader->result['destination_name'] ) ) {
			$folders[] = $upgrader->result['destination_name'];
		}
		$items = 'plugin' === $type
			? array_merge( (array) ( isset( $extra['plugins'] ) ? $extra['plugins'] : array() ), (array) ( isset( $extra['plugin'] ) ? $extra['plugin'] : array() ) )
			: array_merge( (array) ( isset( $extra['themes'] ) ? $extra['themes'] : array() ), (array) ( isset( $extra['theme'] ) ? $extra['theme'] : array() ) );
		foreach ( $items as $item ) {
			$dir       = dirname( (string) $item );
			$folders[] = '.' === $dir ? (string) $item : $dir;
		}
		foreach ( array_unique( array_filter( $folders ) ) as $folder ) {
			$folder = trim( $folder, '/' );
			// A single-file plugin is matched by its file name, a folder by its trailing slash.
			Scanner::expect_changes( $base . $folder . ( preg_match( '/\.php$/', $folder ) ? '' : '/' ) );
		}
	}

	/**
	 * Theme switched.
	 *
	 * @param string $name New theme name.
	 */
	public function theme_switched( $name ) {
		/* translators: %s: theme name. */
		$message = sprintf( __( 'Theme switched to %s.', 'chaos-shield' ), $name );
		Events::add(
			'theme',
			$message,
			Request::ip(),
			array(
				'severity' => Events::NOTICE,
				'action'   => 'theme.switched',
				'subject'  => $name,
			)
		);
		Alerts::send( 'alert_plugin_changes', $message, $message, $message );
	}

	/**
	 * Core updated.
	 *
	 * @param string $version New version.
	 */
	public function core_updated( $version ) {
		/* translators: %s: WordPress version. */
		Events::add( 'system', sprintf( __( 'WordPress updated to %s.', 'chaos-shield' ), $version ), '', array( 'action' => 'core.updated' ) );
	}

	/**
	 * Logs a plugin event and optionally alerts.
	 *
	 * @param string $plugin Plugin file.
	 * @param string $format Message with %s for the plugin name.
	 * @param bool   $alert  Whether to send an alert.
	 * @param string $action Action code for the log.
	 */
	private function plugin_event( $plugin, $format, $alert, $action ) {
		$name    = $this->plugin_name( $plugin );
		$message = sprintf( $format, $name );
		Events::add(
			'plugin',
			$message,
			Request::ip(),
			array(
				'severity' => $alert ? Events::NOTICE : Events::INFO,
				'action'   => $action,
				'subject'  => $plugin,
			)
		);
		if ( $alert ) {
			Alerts::send( 'alert_plugin_changes', $message, $message, $message );
		}
	}

	/**
	 * Human name of a plugin.
	 *
	 * @param string $plugin Plugin file.
	 * @return string
	 */
	private function plugin_name( $plugin ) {
		$file = WP_PLUGIN_DIR . '/' . $plugin;
		if ( is_readable( $file ) && function_exists( 'get_plugin_data' ) ) {
			$data = get_plugin_data( $file, false, false );
			if ( ! empty( $data['Name'] ) ) {
				return $data['Name'];
			}
		}
		return $plugin;
	}

	/**
	 * Logs and alerts about a new administrator.
	 *
	 * @param string $login   Username.
	 * @param int    $user_id User ID.
	 */
	private function alert_new_admin( $login, $user_id ) {
		$actor = wp_get_current_user();
		Alerts::send(
			'alert_new_admin',
			__( 'New administrator account', 'chaos-shield' ),
			sprintf(
				/* translators: 1: new admin username, 2: acting username, 3: IP address. */
				__( "\"%1\$s\" now has administrator rights. The change was made by %2\$s from %3\$s.\n\nIf you did not expect this, remove the account under Users right away: creating a hidden admin is a common step after a break-in.", 'chaos-shield' ),
				$login,
				$actor && $actor->exists() ? $actor->user_login : __( 'an unknown user or process', 'chaos-shield' ),
				Request::ip() ? Request::ip() : '-'
			),
			(string) $user_id
		);
	}
}
