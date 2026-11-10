<?php
/**
 * Removes all plugin data on uninstall.
 *
 * @package ChaosShield
 */

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

global $wpdb;


/**
 * Removes the plugin's options, transients, jobs and tables from the current site.
 */
function cshield_uninstall_site() {
	global $wpdb;
	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- One-off cleanup of this plugin's options and transients.
	$wpdb->query(
		$wpdb->prepare(
			"DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s OR option_name LIKE %s",
			$wpdb->esc_like( 'cshield_' ) . '%',
			$wpdb->esc_like( '_transient_cshield_' ) . '%',
			$wpdb->esc_like( '_transient_timeout_cshield_' ) . '%'
		)
	);
	foreach ( array( 'cshield_daily', 'cshield_scan_continue', 'cshield_ban_alert', 'cshield_vuln_refresh', 'cshield_forward', 'cshield_uptime_check', 'cshield_threat_refresh', 'cshield_geo_refresh', 'cshield_integrity_check', 'cshield_help_notify', 'cshield_page_check', 'cshield_attack_changed', 'cshield_cf_sync' ) as $hook ) {
		wp_unschedule_hook( $hook );
	}
	foreach ( array( 'cshield_log', 'cshield_traffic', 'cshield_incidents' ) as $table ) {
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.SchemaChange, PluginCheck.Security.DirectDB.UnescapedDBParameter -- Drops this plugin's own tables.
		$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}{$table}" );
	}
	wp_cache_flush();
}

if ( is_multisite() ) {
	// Network activated, the data lives in the network options and the main tables;
	// activated per site before 1.7, each site has its own copy. Remove both.
	foreach ( get_sites(
		array(
			'number' => 0,
			'fields' => 'ids',
		)
	) as $cshield_blog_id ) {
		switch_to_blog( $cshield_blog_id );
		cshield_uninstall_site();
		restore_current_blog();
	}
	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- One-off cleanup of this plugin's network options.
	$wpdb->query(
		$wpdb->prepare(
			"DELETE FROM {$wpdb->sitemeta} WHERE meta_key LIKE %s OR meta_key LIKE %s OR meta_key LIKE %s",
			$wpdb->esc_like( 'cshield_' ) . '%',
			$wpdb->esc_like( '_site_transient_cshield_' ) . '%',
			$wpdb->esc_like( '_site_transient_timeout_cshield_' ) . '%'
		)
	);
	switch_to_blog( get_main_site_id() );
	$cshield_uploads = wp_upload_dir( null, false );
	restore_current_blog();
} else {
	cshield_uninstall_site();
	$cshield_uploads = wp_upload_dir( null, false );
}

// The built-in country database lives in the (main site's) uploads folder.
$cshield_geo_dir = trailingslashit( $cshield_uploads['basedir'] ) . 'chaos-shield-geo';
if ( is_dir( $cshield_geo_dir ) ) {
	foreach ( (array) glob( $cshield_geo_dir . '/{,.}*', GLOB_BRACE ) as $cshield_file ) {
		if ( is_file( $cshield_file ) ) {
			wp_delete_file( $cshield_file );
		}
	}
	@rmdir( $cshield_geo_dir ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_rmdir -- Best effort.
}

// Take out the no-PHP-in-uploads block, leaving any other rules in the file.
$cshield_htaccess = trailingslashit( $cshield_uploads['basedir'] ) . '.htaccess';
if ( is_file( $cshield_htaccess ) && is_writable( $cshield_htaccess ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- Local file.
	$cshield_body = (string) file_get_contents( $cshield_htaccess ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file.
	if ( false !== strpos( $cshield_body, '# Chaos Shield: no PHP in uploads' ) ) {
		$cshield_body = trim( (string) preg_replace( '/# Chaos Shield: no PHP in uploads.*?# End Chaos Shield\n?/s', '', $cshield_body ) );
		if ( '' === $cshield_body ) {
			wp_delete_file( $cshield_htaccess );
		} else {
			file_put_contents( $cshield_htaccess, $cshield_body . "\n" ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Local file.
		}
	}
}

// Take out the blocks on sensitive files and image hotlinks from the root .htaccess.
$cshield_root_ht = ABSPATH . '.htaccess';
if ( is_file( $cshield_root_ht ) && is_writable( $cshield_root_ht ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- Local file.
	$cshield_body = (string) file_get_contents( $cshield_root_ht ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file.
	if ( false !== strpos( $cshield_body, '# BEGIN Chaos Shield ' ) ) {
		$cshield_body = (string) preg_replace( '/\n?# BEGIN (Chaos Shield (?:sensitive files|hotlinks)).*?# END \1\n?/s', "\n", $cshield_body );
		file_put_contents( $cshield_root_ht, ltrim( $cshield_body ) ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents, PluginCheck.CodeAnalysis.WriteFile.ABSPATHDetected -- Takes this plugin's own rules back out of the site's .htaccess.
	}
}

foreach ( array( '_cshield_known_ips', '_cshield_2fa_secret', '_cshield_2fa_pending', '_cshield_2fa_recovery', '_cshield_2fa_last_step', '_cshield_2fa_login', '_cshield_pw_breached', '_cshield_pw_checked', '_cshield_passkeys', '_cshield_pw_changed', '_cshield_force_reset', '_cshield_2fa_due', '_cshield_2fa_trusted', '_cshield_pending' ) as $cshield_meta_key ) {
	delete_metadata( 'user', 0, $cshield_meta_key, '', true );
}

// Quarantined files are suspected malware, and restore points hold copies of
// wp-config.php: remove both with the plugin.
foreach ( array( WP_CONTENT_DIR . '/cshield-quarantine', WP_CONTENT_DIR . '/cshield-restore' ) as $cshield_dir ) {
	if ( ! is_dir( $cshield_dir ) ) {
		continue;
	}
	$cshield_it = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $cshield_dir, FilesystemIterator::SKIP_DOTS ), RecursiveIteratorIterator::CHILD_FIRST );
	foreach ( $cshield_it as $cshield_file ) {
		if ( $cshield_file->isDir() && ! $cshield_file->isLink() ) {
			@rmdir( $cshield_file->getPathname() ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_rmdir -- Best effort.
		} else {
			wp_delete_file( $cshield_file->getPathname() );
		}
	}
	@rmdir( $cshield_dir ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_rmdir -- Best effort.
}
