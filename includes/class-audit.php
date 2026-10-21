<?php
/**
 * Detailed audit trail: content, site settings, user profiles and privacy requests.
 *
 * @package ChaosShield
 */

namespace ChaosShield;

defined( 'ABSPATH' ) || exit;

/**
 * Adds who-changed-what events on top of the security events Monitor records.
 */
final class Audit {

	/**
	 * Failed logins logged per IP per hour before the rest are summarised.
	 */
	const FAILED_LOGIN_CAP = 20;

	/**
	 * Registers hooks.
	 */
	public function register() {
		if ( ! Settings::enabled( 'audit_trail' ) ) {
			return;
		}
		// Content.
		add_action( 'transition_post_status', array( $this, 'post_status' ), 10, 3 );
		add_action( 'post_updated', array( $this, 'post_updated' ), 10, 3 );
		add_action( 'before_delete_post', array( $this, 'post_deleted' ), 10, 2 );
		add_action( 'add_attachment', array( $this, 'media_added' ) );
		add_action( 'delete_attachment', array( $this, 'media_deleted' ) );
		add_action( 'created_term', array( $this, 'term_created' ), 10, 3 );
		add_action( 'pre_delete_term', array( $this, 'term_deleted' ), 10, 2 );
		add_action( 'wp_update_nav_menu', array( $this, 'menu_updated' ) );
		add_action( 'customize_save_after', array( $this, 'customizer_saved' ) );
		add_action( 'update_option_sidebars_widgets', array( $this, 'widgets_changed' ), 10, 0 );
		add_action( 'export_wp', array( $this, 'exported' ) );

		// Site settings.
		add_action( 'updated_option', array( $this, 'option_updated' ), 10, 3 );

		// Users.
		add_action( 'profile_update', array( $this, 'profile_updated' ), 10, 2 );
		add_action( 'wp_logout', array( $this, 'logout' ) );
		add_action( 'wp_login_failed', array( $this, 'login_failed' ), 5, 2 );
		add_action( 'wp_create_application_password', array( $this, 'app_password_created' ), 10, 2 );
		add_action( 'wp_delete_application_password', array( $this, 'app_password_deleted' ), 10, 2 );

		// Privacy requests.
		add_action( 'wp_privacy_personal_data_export_file_created', array( $this, 'privacy_exported' ), 10, 4 );
		add_action( 'wp_privacy_personal_data_erased', array( $this, 'privacy_erased' ) );
	}

	/**
	 * Core settings worth an audit entry, with labels.
	 *
	 * @return array Option => label.
	 */
	public static function watched_options() {
		$options = array(
			'blogname'                   => __( 'Site title', 'chaos-shield' ),
			'blogdescription'            => __( 'Tagline', 'chaos-shield' ),
			'siteurl'                    => __( 'WordPress address', 'chaos-shield' ),
			'home'                       => __( 'Site address', 'chaos-shield' ),
			'admin_email'                => __( 'Administration email', 'chaos-shield' ),
			'new_admin_email'            => __( 'Pending administration email', 'chaos-shield' ),
			'users_can_register'         => __( 'Anyone can register', 'chaos-shield' ),
			'default_role'               => __( 'New user default role', 'chaos-shield' ),
			'permalink_structure'        => __( 'Permalink structure', 'chaos-shield' ),
			'blog_public'                => __( 'Search engine visibility', 'chaos-shield' ),
			'show_on_front'              => __( 'Homepage displays', 'chaos-shield' ),
			'page_on_front'              => __( 'Homepage', 'chaos-shield' ),
			'default_comment_status'     => __( 'Allow comments on new posts', 'chaos-shield' ),
			'comment_registration'       => __( 'Users must be registered to comment', 'chaos-shield' ),
			'comment_moderation'         => __( 'Comments must be manually approved', 'chaos-shield' ),
			'timezone_string'            => __( 'Timezone', 'chaos-shield' ),
			'WPLANG'                     => __( 'Site language', 'chaos-shield' ),
			'upload_path'                => __( 'Uploads folder', 'chaos-shield' ),
			'wp_page_for_privacy_policy' => __( 'Privacy policy page', 'chaos-shield' ),
		);
		/**
		 * Filters the core options the audit trail records changes to.
		 *
		 * @param array $options Option name => label.
		 */
		return (array) apply_filters( 'cshield_audit_options', $options );
	}

	// Content.

	/**
	 * Post types that are audited.
	 *
	 * @param string $type Post type.
	 * @return bool
	 */
	private static function audited_type( $type ) {
		if ( in_array( $type, array( 'revision', 'nav_menu_item', 'customize_changeset', 'oembed_cache', 'user_request', 'wp_global_styles', 'custom_css', 'attachment' ), true ) ) {
			return false;
		}
		$object = get_post_type_object( $type );
		return $object && ( $object->public || $object->show_ui );
	}

	/**
	 * Type label and title of a post for messages.
	 *
	 * @param \WP_Post $post Post.
	 * @return array [ label, title ].
	 */
	private static function describe( $post ) {
		$object = get_post_type_object( $post->post_type );
		$label  = $object ? $object->labels->singular_name : $post->post_type;
		$title  = '' !== $post->post_title ? $post->post_title : __( '(no title)', 'chaos-shield' );
		return array( $label, wp_html_excerpt( $title, 80, '…' ) . ' (#' . $post->ID . ')' );
	}

	/**
	 * Publish, unpublish, trash and restore.
	 *
	 * @param string   $new_status New status.
	 * @param string   $old  Old status.
	 * @param \WP_Post $post Post.
	 */
	public function post_status( $new_status, $old, $post ) {
		if ( $new_status === $old || 'auto-draft' === $new_status || 'inherit' === $new_status || ! self::audited_type( $post->post_type ) || wp_is_post_autosave( $post ) ) {
			return;
		}
		list( $label, $title ) = self::describe( $post );
		if ( 'publish' === $new_status ) {
			/* translators: 1: post type, 2: title. */
			$message = __( '%1$s published: %2$s.', 'chaos-shield' );
		} elseif ( 'trash' === $new_status ) {
			/* translators: 1: post type, 2: title. */
			$message = __( '%1$s moved to the trash: %2$s.', 'chaos-shield' );
		} elseif ( 'trash' === $old ) {
			/* translators: 1: post type, 2: title. */
			$message = __( '%1$s restored from the trash: %2$s.', 'chaos-shield' );
		} elseif ( 'publish' === $old ) {
			/* translators: 1: post type, 2: title. */
			$message = __( '%1$s unpublished: %2$s.', 'chaos-shield' );
		} elseif ( 'future' === $new_status ) {
			/* translators: 1: post type, 2: title. */
			$message = __( '%1$s scheduled: %2$s.', 'chaos-shield' );
		} elseif ( 'new' === $old || 'auto-draft' === $old ) {
			/* translators: 1: post type, 2: title. */
			$message = __( '%1$s drafted: %2$s.', 'chaos-shield' );
		} else {
			return;
		}
		Events::add( 'content', sprintf( $message, $label, $title ), Request::ip() );
	}

	/**
	 * Edits to published content. Repeated saves by one user within ten minutes count once.
	 *
	 * @param int      $post_id Post ID.
	 * @param \WP_Post $after   Post after.
	 * @param \WP_Post $before  Post before.
	 */
	public function post_updated( $post_id, $after, $before ) {
		if ( 'publish' !== $after->post_status || 'publish' !== $before->post_status || ! self::audited_type( $after->post_type ) ) {
			return;
		}
		$changed = array();
		if ( $after->post_title !== $before->post_title ) {
			$changed[] = __( 'title', 'chaos-shield' );
		}
		if ( $after->post_content !== $before->post_content ) {
			$changed[] = __( 'content', 'chaos-shield' );
		}
		if ( $after->post_name !== $before->post_name ) {
			$changed[] = __( 'address', 'chaos-shield' );
		}
		if ( (int) $after->post_author !== (int) $before->post_author ) {
			$changed[] = __( 'author', 'chaos-shield' );
		}
		if ( $after->post_password !== $before->post_password ) {
			$changed[] = __( 'password', 'chaos-shield' );
		}
		if ( ! $changed ) {
			return;
		}
		$throttle = 'cshield_aud_' . md5( $post_id . '|' . get_current_user_id() );
		if ( Network::get_transient( $throttle ) ) {
			return;
		}
		Network::set_transient( $throttle, 1, 10 * MINUTE_IN_SECONDS );
		list( $label, $title ) = self::describe( $after );
		/* translators: 1: post type, 2: title, 3: list of changed fields. */
		Events::add( 'content', sprintf( __( '%1$s updated: %2$s. Changed: %3$s.', 'chaos-shield' ), $label, $title, implode( ', ', $changed ) ), Request::ip() );
	}

	/**
	 * Permanent deletion.
	 *
	 * @param int      $post_id Post ID.
	 * @param \WP_Post $post    Post.
	 */
	public function post_deleted( $post_id, $post = null ) {
		$post = $post instanceof \WP_Post ? $post : get_post( $post_id );
		if ( ! $post || 'auto-draft' === $post->post_status || ! self::audited_type( $post->post_type ) ) {
			return;
		}
		list( $label, $title ) = self::describe( $post );
		Events::add(
			'content',
			/* translators: 1: post type, 2: title. */
			sprintf( __( '%1$s permanently deleted: %2$s.', 'chaos-shield' ), $label, $title ),
			Request::ip(),
			array(
				'severity' => Events::NOTICE,
				'action'   => 'content.deleted',
			)
		);
	}

	/**
	 * Media uploaded.
	 *
	 * @param int $post_id Attachment ID.
	 */
	public function media_added( $post_id ) {
		/* translators: %s: file name. */
		Events::add( 'content', sprintf( __( 'Media uploaded: %s.', 'chaos-shield' ), wp_basename( (string) get_attached_file( $post_id ) ) ), Request::ip() );
	}

	/**
	 * Media deleted.
	 *
	 * @param int $post_id Attachment ID.
	 */
	public function media_deleted( $post_id ) {
		/* translators: %s: file name. */
		Events::add( 'content', sprintf( __( 'Media deleted: %s.', 'chaos-shield' ), wp_basename( (string) get_attached_file( $post_id ) ) ), Request::ip(), array( 'action' => 'content.deleted' ) );
	}

	/**
	 * Category, tag or other term created.
	 *
	 * @param int    $term_id  Term ID.
	 * @param int    $tt_id    Term taxonomy ID.
	 * @param string $taxonomy Taxonomy.
	 */
	public function term_created( $term_id, $tt_id, $taxonomy ) {
		$term = get_term( $term_id, $taxonomy );
		$tax  = get_taxonomy( $taxonomy );
		if ( ! $term || is_wp_error( $term ) || ! $tax || ! $tax->public || 'nav_menu' === $taxonomy ) {
			return;
		}
		/* translators: 1: taxonomy name, 2: term name. */
		Events::add( 'content', sprintf( __( '%1$s created: %2$s.', 'chaos-shield' ), $tax->labels->singular_name, $term->name ), Request::ip() );
	}

	/**
	 * Term about to be deleted.
	 *
	 * @param int    $term_id  Term ID.
	 * @param string $taxonomy Taxonomy.
	 */
	public function term_deleted( $term_id, $taxonomy ) {
		$term = get_term( $term_id, $taxonomy );
		$tax  = get_taxonomy( $taxonomy );
		if ( ! $term || is_wp_error( $term ) || ! $tax || ! $tax->public || 'nav_menu' === $taxonomy ) {
			return;
		}
		/* translators: 1: taxonomy name, 2: term name. */
		Events::add( 'content', sprintf( __( '%1$s deleted: %2$s.', 'chaos-shield' ), $tax->labels->singular_name, $term->name ), Request::ip() );
	}

	/**
	 * Navigation menu saved.
	 *
	 * @param int $menu_id Menu ID.
	 */
	public function menu_updated( $menu_id ) {
		$throttle = 'cshield_aud_menu_' . (int) $menu_id;
		if ( Network::get_transient( $throttle ) ) {
			return;
		}
		Network::set_transient( $throttle, 1, 5 * MINUTE_IN_SECONDS );
		$menu = wp_get_nav_menu_object( $menu_id );
		/* translators: %s: menu name. */
		Events::add( 'content', sprintf( __( 'Menu updated: %s.', 'chaos-shield' ), $menu ? $menu->name : '#' . (int) $menu_id ), Request::ip() );
	}

	/**
	 * Customizer changes published.
	 */
	public function customizer_saved() {
		Events::add( 'content', __( 'Customizer changes published.', 'chaos-shield' ), Request::ip() );
	}

	/**
	 * Widgets moved, added or removed.
	 */
	public function widgets_changed() {
		if ( Network::get_transient( 'cshield_aud_widgets' ) ) {
			return;
		}
		Network::set_transient( 'cshield_aud_widgets', 1, 5 * MINUTE_IN_SECONDS );
		Events::add( 'content', __( 'Widgets changed.', 'chaos-shield' ), Request::ip() );
	}

	/**
	 * Tools > Export download.
	 */
	public function exported() {
		Events::add(
			'content',
			__( 'Site content exported from Tools > Export.', 'chaos-shield' ),
			Request::ip(),
			array(
				'severity' => Events::NOTICE,
				'action'   => 'data.export',
			)
		);
	}

	// Site settings.

	/**
	 * Core setting changed.
	 *
	 * @param string $option Option name.
	 * @param mixed  $old    Old value.
	 * @param mixed  $value  New value.
	 */
	public function option_updated( $option, $old, $value ) {
		// Options change before init too (cron, transients), when labels cannot be translated yet.
		$names = array( 'blogname', 'blogdescription', 'siteurl', 'home', 'admin_email', 'new_admin_email', 'users_can_register', 'default_role', 'permalink_structure', 'blog_public', 'show_on_front', 'page_on_front', 'default_comment_status', 'comment_registration', 'comment_moderation', 'timezone_string', 'WPLANG', 'upload_path', 'wp_page_for_privacy_policy' );
		if ( ( ! in_array( $option, $names, true ) && ! has_filter( 'cshield_audit_options' ) ) || maybe_serialize( $old ) === maybe_serialize( $value ) ) {
			return;
		}
		$watched = did_action( 'init' ) ? self::watched_options() : array_combine( $names, $names );
		if ( ! isset( $watched[ $option ] ) ) {
			return;
		}
		$sensitive = in_array( $option, array( 'siteurl', 'home', 'admin_email', 'users_can_register', 'default_role' ), true );
		Events::add(
			'option',
			/* translators: 1: setting label, 2: old value, 3: new value. */
			sprintf( __( 'Site setting "%1$s" changed from "%2$s" to "%3$s".', 'chaos-shield' ), $watched[ $option ], self::short( $old ), self::short( $value ) ),
			Request::ip(),
			array(
				'severity' => $sensitive ? Events::NOTICE : Events::INFO,
				'action'   => 'option.changed',
				'subject'  => $option,
			)
		);
	}

	/**
	 * Short printable form of an option value.
	 *
	 * @param mixed $value Value.
	 * @return string
	 */
	private static function short( $value ) {
		if ( is_bool( $value ) ) {
			return $value ? '1' : '0';
		}
		if ( ! is_scalar( $value ) ) {
			$value = wp_json_encode( $value );
		}
		return wp_html_excerpt( (string) $value, 120, '…' );
	}

	// Users.

	/**
	 * Email and password changes made on a profile or by an administrator.
	 *
	 * @param int      $user_id  User ID.
	 * @param \WP_User $old_user User before the update.
	 */
	public function profile_updated( $user_id, $old_user ) {
		$user = get_userdata( $user_id );
		if ( ! $user || ! $old_user instanceof \WP_User ) {
			return;
		}
		$actor = wp_get_current_user();
		$by    = $actor->exists() && $actor->ID !== $user->ID
			/* translators: %s: username of the administrator. */
			? ' ' . sprintf( __( '(by %s)', 'chaos-shield' ), $actor->user_login )
			: '';
		if ( $user->user_email !== $old_user->user_email ) {
			Events::add(
				'user',
				/* translators: 1: username, 2: old email, 3: new email, 4: "(by admin)" or nothing. */
				sprintf( __( 'Email of %1$s changed from %2$s to %3$s.%4$s', 'chaos-shield' ), $user->user_login, $old_user->user_email, $user->user_email, $by ),
				Request::ip(),
				array(
					'severity' => Events::NOTICE,
					'action'   => 'user.email_changed',
					'subject'  => $user->user_login,
				)
			);
		}
		if ( $user->user_pass !== $old_user->user_pass ) {
			Events::add(
				'user',
				/* translators: 1: username, 2: "(by admin)" or nothing. */
				sprintf( __( 'Password of %1$s changed.%2$s', 'chaos-shield' ), $user->user_login, $by ),
				Request::ip(),
				array(
					'severity' => Events::NOTICE,
					'action'   => 'user.password_changed',
					'subject'  => $user->user_login,
				)
			);
		}
		if ( $user->display_name !== $old_user->display_name ) {
			Events::add(
				'user',
				/* translators: 1: username, 2: old name, 3: new name. */
				sprintf( __( 'Display name of %1$s changed from "%2$s" to "%3$s".', 'chaos-shield' ), $user->user_login, $old_user->display_name, $user->display_name ),
				Request::ip()
			);
		}
	}

	/**
	 * Logout.
	 *
	 * @param int $user_id User ID.
	 */
	public function logout( $user_id = 0 ) {
		$user = get_userdata( (int) $user_id );
		if ( $user ) {
			Events::add(
				'login',
				/* translators: %s: username. */
				sprintf( __( '%s logged out.', 'chaos-shield' ), $user->user_login ),
				Request::ip(),
				array(
					'user_id' => $user->ID,
					'action'  => 'auth.logout',
					'subject' => $user->user_login,
				)
			);
		}
	}

	/**
	 * Failed login, capped per IP so a brute force attack cannot flood the log.
	 *
	 * @param string         $username Attempted username.
	 * @param \WP_Error|null $error    Why the login failed.
	 */
	public function login_failed( $username, $error = null ) {
		if ( $error instanceof \WP_Error && 'cshield_reset_required' === $error->get_error_code() ) {
			return; // Right password, but a new one is due: not a failure.
		}
		$ip  = Request::ip();
		$key = 'cshield_aud_fail_' . md5( (string) $ip );
		$n   = (int) Network::get_transient( $key ) + 1;
		Network::set_transient( $key, $n, HOUR_IN_SECONDS );
		if ( $n > self::FAILED_LOGIN_CAP + 1 ) {
			return;
		}
		if ( self::FAILED_LOGIN_CAP + 1 === $n ) {
			/* translators: %d: number of failed logins. */
			Events::add( 'login', sprintf( __( 'More than %d failed logins from this IP in an hour. Further failures are counted but not logged until the hour is over.', 'chaos-shield' ), self::FAILED_LOGIN_CAP ), $ip, array( 'severity' => Events::NOTICE ) );
			return;
		}
		$name = sanitize_user( (string) $username );
		Events::add(
			'login',
			/* translators: %s: attempted username. */
			sprintf( __( 'Failed login for "%s".', 'chaos-shield' ), '' !== $name ? $name : '-' ),
			$ip,
			array(
				'user_id' => 0,
				'action'  => 'auth.failed',
				'subject' => $name,
			)
		);
	}

	/**
	 * Application password created.
	 *
	 * @param int   $user_id User ID.
	 * @param array $item    Password details.
	 */
	public function app_password_created( $user_id, $item ) {
		$user = get_userdata( $user_id );
		Events::add(
			'user',
			/* translators: 1: application name, 2: username. */
			sprintf( __( 'Application password "%1$s" created for %2$s.', 'chaos-shield' ), isset( $item['name'] ) ? $item['name'] : '', $user ? $user->user_login : '#' . (int) $user_id ),
			Request::ip(),
			array(
				'severity' => Events::NOTICE,
				'action'   => 'user.app_password',
			)
		);
	}

	/**
	 * Application password revoked.
	 *
	 * @param int   $user_id User ID.
	 * @param array $item    Password details.
	 */
	public function app_password_deleted( $user_id, $item ) {
		$user = get_userdata( $user_id );
		/* translators: 1: application name, 2: username. */
		Events::add( 'user', sprintf( __( 'Application password "%1$s" revoked for %2$s.', 'chaos-shield' ), isset( $item['name'] ) ? $item['name'] : '', $user ? $user->user_login : '#' . (int) $user_id ), Request::ip() );
	}

	// Privacy.

	/**
	 * Personal data export file created.
	 *
	 * @param string $archive_path Path.
	 * @param string $archive_url  URL.
	 * @param string $html_path    Path.
	 * @param int    $request_id   Request ID.
	 */
	public function privacy_exported( $archive_path, $archive_url, $html_path, $request_id ) {
		$request = wp_get_user_request( $request_id );
		Events::add(
			'privacy',
			/* translators: %s: email address. */
			sprintf( __( 'Personal data export created for %s.', 'chaos-shield' ), $request ? $request->email : '#' . (int) $request_id ),
			Request::ip(),
			array(
				'severity' => Events::NOTICE,
				'action'   => 'data.export',
			)
		);
	}

	/**
	 * Personal data erased.
	 *
	 * @param int $request_id Request ID.
	 */
	public function privacy_erased( $request_id ) {
		$request = wp_get_user_request( $request_id );
		Events::add(
			'privacy',
			/* translators: %s: email address. */
			sprintf( __( 'Personal data erased for %s.', 'chaos-shield' ), $request ? $request->email : '#' . (int) $request_id ),
			Request::ip(),
			array(
				'severity' => Events::NOTICE,
				'action'   => 'data.erase',
			)
		);
	}
}
