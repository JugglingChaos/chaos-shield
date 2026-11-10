<?php
/**
 * Comment spam blocking without a CAPTCHA.
 *
 * @package ChaosShield
 */

namespace ChaosShield;

defined( 'ABSPATH' ) || exit;

/**
 * Adds a hidden field and a signed time stamp to the comment form. Bots that
 * fill every field, post faster than a person types or forge the stamp are
 * refused and banned when they keep at it; comments sent without the form at
 * all go to the spam folder, so a theme with its own form loses nothing.
 */
final class Comments {

	const TRAP     = 'cshield_hp';
	const STAMP    = 'cshield_ct';
	const MIN_AGE  = 3;
	const MAX_AGE  = 30 * DAY_IN_SECONDS;
	const BAN_HITS = 3;

	/**
	 * What the check decided for the comment being saved: spam, hold or ''.
	 *
	 * @var string
	 */
	private $verdict = '';

	/**
	 * Registers hooks.
	 */
	public function register() {
		if ( ! Settings::enabled( 'comment_spam' ) ) {
			return;
		}
		add_action( 'comment_form', array( $this, 'fields' ) );
		add_filter( 'preprocess_comment', array( $this, 'check' ), 1 );
		add_filter( 'pre_comment_approved', array( $this, 'approved' ), 99 );
	}

	/**
	 * Signed time stamp for a form on a post.
	 *
	 * @param int $post_id Post.
	 * @param int $time    Time the form was made.
	 * @return string
	 */
	public static function stamp( $post_id, $time ) {
		return (int) $time . '.' . substr( hash_hmac( 'sha256', 'comment|' . (int) $time . '|' . (int) $post_id, wp_salt( 'nonce' ) ), 0, 24 );
	}

	/**
	 * Prints the hidden field and the stamp inside the comment form.
	 *
	 * @param int $post_id Post.
	 */
	public function fields( $post_id ) {
		if ( is_user_logged_in() ) {
			return;
		}
		printf(
			'<p class="cshield-hp" aria-hidden="true" style="position:absolute;left:-10000px;top:auto;width:1px;height:1px;overflow:hidden"><label>%s <input type="text" name="%s" value="" tabindex="-1" autocomplete="off"></label></p><input type="hidden" name="%s" value="%s">',
			esc_html__( 'Leave this field empty', 'chaos-shield' ),
			esc_attr( self::TRAP ),
			esc_attr( self::STAMP ),
			esc_attr( self::stamp( (int) $post_id, time() ) )
		);
	}

	/**
	 * Judges a comment from a visitor who is not logged in.
	 *
	 * @param array $data Comment data.
	 * @return array
	 */
	public function check( $data ) {
		$this->verdict = '';
		$type          = isset( $data['comment_type'] ) ? (string) $data['comment_type'] : '';
		if ( is_user_logged_in() || ! did_action( 'pre_comment_on_post' ) || ! in_array( $type, array( '', 'comment' ), true ) ) {
			return $data;
		}
		$verdict = self::judge( $_POST, isset( $data['comment_post_ID'] ) ? (int) $data['comment_post_ID'] : 0 ); // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Core's comment form has no nonce; the signed stamp is checked instead.
		if ( 'block' === $verdict ) {
			$ip = Request::ip();
			Events::add(
				'spam',
				__( 'A comment from a bot was refused.', 'chaos-shield' ),
				$ip,
				array(
					'action'  => 'spam.comment_blocked',
					'subject' => isset( $data['comment_post_ID'] ) ? (string) (int) $data['comment_post_ID'] : '',
				)
			);
			Bans::strike( $ip, 'spam' );
			wp_die(
				esc_html__( 'Your comment looks automated, so it was not saved. If you are a person, go back, wait a few seconds and send it again.', 'chaos-shield' ),
				esc_html__( 'Comment not sent', 'chaos-shield' ),
				array(
					'response'  => 403,
					'back_link' => true,
				)
			);
		}
		$this->verdict = $verdict;
		return $data;
	}

	/**
	 * What to do with a comment, from the fields the form sent.
	 *
	 * @param array $post    Posted fields.
	 * @param int   $post_id Post.
	 * @return string block, spam (no form fields), hold (stamp too old) or ''.
	 */
	public static function judge( array $post, $post_id ) {
		if ( isset( $post[ self::TRAP ] ) && '' !== trim( (string) $post[ self::TRAP ] ) ) {
			return 'block';
		}
		if ( ! isset( $post[ self::STAMP ] ) ) {
			return 'spam';
		}
		$stamp = (string) $post[ self::STAMP ];
		$parts = explode( '.', $stamp, 2 );
		if ( 2 !== count( $parts ) || ! ctype_digit( $parts[0] ) || ! hash_equals( self::stamp( $post_id, (int) $parts[0] ), $stamp ) ) {
			return 'block';
		}
		$age = time() - (int) $parts[0];
		if ( $age < self::MIN_AGE ) {
			return 'block';
		}
		// A page cache can serve an old form; a person may still be behind it.
		return $age > self::MAX_AGE ? 'hold' : '';
	}

	/**
	 * Files the comment the way the check decided.
	 *
	 * @param int|string|\WP_Error $approved Status so far.
	 * @return int|string|\WP_Error
	 */
	public function approved( $approved ) {
		if ( is_wp_error( $approved ) || 'trash' === $approved || 'spam' === $approved ) {
			return $approved;
		}
		if ( 'spam' === $this->verdict ) {
			return 'spam';
		}
		return 'hold' === $this->verdict ? 0 : $approved;
	}
}
