<?php
/**
 * Removes all plugin data on uninstall.
 *
 * @package SentinelShield
 */

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

global $wpdb;


/**
 * Removes the plugin's options, transients, jobs and tables from the current site.
 */
function sshield_uninstall_site() {
	global $wpdb;
	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- One-off cleanup of this plugin's options and transients.
	$wpdb->query(
		$wpdb->prepare(
			"DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s OR option_name LIKE %s",
			$wpdb->esc_like( 'sshield_' ) . '%',
			$wpdb->esc_like( '_transient_sshield_' ) . '%',
			$wpdb->esc_like( '_transient_timeout_sshield_' ) . '%'
		)
	);
	foreach ( array( 'sshield_daily', 'sshield_scan_continue', 'sshield_ban_alert', 'sshield_vuln_refresh', 'sshield_forward', 'sshield_uptime_check', 'sshield_threat_refresh', 'sshield_geo_refresh', 'sshield_integrity_check', 'sshield_help_notify', 'sshield_page_check', 'sshield_attack_changed', 'sshield_cf_sync' ) as $hook ) {
		wp_unschedule_hook( $hook );
	}
	foreach ( array( 'sshield_log', 'sshield_traffic', 'sshield_incidents' ) as $table ) {
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.SchemaChange -- Drops this plugin's own tables.
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
	) as $sshield_blog_id ) {
		switch_to_blog( $sshield_blog_id );
		sshield_uninstall_site();
		restore_current_blog();
	}
	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- One-off cleanup of this plugin's network options.
	$wpdb->query(
		$wpdb->prepare(
			"DELETE FROM {$wpdb->sitemeta} WHERE meta_key LIKE %s OR meta_key LIKE %s OR meta_key LIKE %s",
			$wpdb->esc_like( 'sshield_' ) . '%',
			$wpdb->esc_like( '_site_transient_sshield_' ) . '%',
			$wpdb->esc_like( '_site_transient_timeout_sshield_' ) . '%'
		)
	);
	switch_to_blog( get_main_site_id() );
	$sshield_uploads = wp_upload_dir( null, false );
	restore_current_blog();
} else {
	sshield_uninstall_site();
	$sshield_uploads = wp_upload_dir( null, false );
}

// The built-in country database lives in the (main site's) uploads folder.
$sshield_geo_dir = trailingslashit( $sshield_uploads['basedir'] ) . 'sentinel-shield-geo';
if ( is_dir( $sshield_geo_dir ) ) {
	foreach ( (array) glob( $sshield_geo_dir . '/{,.}*', GLOB_BRACE ) as $sshield_file ) {
		if ( is_file( $sshield_file ) ) {
			wp_delete_file( $sshield_file );
		}
	}
	@rmdir( $sshield_geo_dir ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_rmdir -- Best effort.
}

// Take out the no-PHP-in-uploads block, leaving any other rules in the file.
$sshield_htaccess = trailingslashit( $sshield_uploads['basedir'] ) . '.htaccess';
if ( is_file( $sshield_htaccess ) && is_writable( $sshield_htaccess ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- Local file.
	$sshield_body = (string) file_get_contents( $sshield_htaccess ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file.
	if ( false !== strpos( $sshield_body, '# Sentinel Shield: no PHP in uploads' ) ) {
		$sshield_body = trim( (string) preg_replace( '/# Sentinel Shield: no PHP in uploads.*?# End Sentinel Shield\n?/s', '', $sshield_body ) );
		if ( '' === $sshield_body ) {
			wp_delete_file( $sshield_htaccess );
		} else {
			file_put_contents( $sshield_htaccess, $sshield_body . "\n" ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Local file.
		}
	}
}

// Take out the block on backups, logs and hidden files from the root .htaccess.
$sshield_root_ht = ABSPATH . '.htaccess';
if ( is_file( $sshield_root_ht ) && is_writable( $sshield_root_ht ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- Local file.
	$sshield_body = (string) file_get_contents( $sshield_root_ht ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file.
	if ( false !== strpos( $sshield_body, '# BEGIN Sentinel Shield sensitive files' ) ) {
		$sshield_body = (string) preg_replace( '/\n?# BEGIN Sentinel Shield sensitive files.*?# END Sentinel Shield sensitive files\n?/s', "\n", $sshield_body );
		file_put_contents( $sshield_root_ht, ltrim( $sshield_body ) ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Local file.
	}
}

foreach ( array( '_sshield_known_ips', '_sshield_2fa_secret', '_sshield_2fa_pending', '_sshield_2fa_recovery', '_sshield_2fa_last_step', '_sshield_2fa_login', '_sshield_pw_breached', '_sshield_pw_checked', '_sshield_passkeys', '_sshield_pw_changed', '_sshield_force_reset' ) as $sshield_meta_key ) {
	delete_metadata( 'user', 0, $sshield_meta_key, '', true );
}

// Quarantined files are suspected malware, and restore points hold copies of
// wp-config.php: remove both with the plugin.
foreach ( array( WP_CONTENT_DIR . '/sshield-quarantine', WP_CONTENT_DIR . '/sshield-restore' ) as $sshield_dir ) {
	if ( ! is_dir( $sshield_dir ) ) {
		continue;
	}
	$sshield_it = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $sshield_dir, FilesystemIterator::SKIP_DOTS ), RecursiveIteratorIterator::CHILD_FIRST );
	foreach ( $sshield_it as $sshield_file ) {
		if ( $sshield_file->isDir() && ! $sshield_file->isLink() ) {
			@rmdir( $sshield_file->getPathname() ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_rmdir -- Best effort.
		} else {
			wp_delete_file( $sshield_file->getPathname() );
		}
	}
	@rmdir( $sshield_dir ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_rmdir -- Best effort.
}
