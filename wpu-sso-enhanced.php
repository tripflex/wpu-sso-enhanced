<?php
/*
  Plugin Name: WP Ultimo SSO - Mercator Enhanced
  Plugin URI: https://github.com/tripflex/wpu-sso-enhanced
  Description: WP Ultimo 1.x SSO handling for newer versions of Chrome
  Version: 1.0
  Author: Myles McNamara
  Author URI: https://smyles.dev
*/

defined( 'ABSPATH' ) or die( 'No script kiddies please!' );

/**
 * Class WP_Ultimo_SSO_Enhanced
 */
class WP_Ultimo_SSO_Enhanced {
	/**
	 * @var int Number of seconds before SSO expires
	 */
	private $lifespan = 60;
	/**
	 * @var string Cookie name to store data to trigger SSO redirect (STYXKEY_ is used for Pantheon support)
	 */
	private $cookie_name = 'STYXKEY_wpu_sso_me';
	/**
	 * @var string Meta key to store SSO information in user meta
	 */
	private $user_meta_key = 'wpu_sso_me';
	/**
	 * @var array Local object storage of SSO meta
	 */
	private $sso_meta = array();
	/**
	 * @var integer User ID of user attempting to SSO
	 */
	private $user_id;
	/**
	 * @var integer Site ID where the SSO meta is stored at
	 */
	private $meta_site_id;
	/**
	 * @var string Nonce value to validate requests
	 */
	private $nonce;

	/**
	 * SSO constructor.
	 */
	public function __construct() {
		add_action( 'set_logged_in_cookie', array( $this, 'set_logged_in_cookie' ), 10, 6 );
		add_action( 'muplugins_loaded', array( $this, 'maybe_process_sso' ) );
		add_action( 'plugins_loaded', array( $this, 'plugins_loaded' ) );
	}

	/**
	 * Maybe Process SSO Flow
	 *
	 * This method is triggered before the COOKIE_DOMAIN is set, to check if we are in the SSO flow process.
	 * If we are, it sets the COOKIE_DOMAIN to the SSO domain, and then adds an action to be triggered after
	 * plugins are loaded, to then set the authentication cookie.  This is required because the other constants
	 * are not defined until AFTER this method is called (after muplugins_loaded)
	 *
	 * @return false
	 * @since @@version
	 *
	 */
	public function maybe_process_sso() {
		if( ! isset( $_GET['wpu_sso_me'], $_GET['meta_site_id'], $_GET['user_id'], $_GET['nonce'] ) ){
			return false;
		}

		/**
		 * Sanitize and set values for the SSO
		 */
		$this->user_id = absint( $_GET['user_id'] );
		$this->meta_site_id = absint( $_GET['meta_site_id'] );
		$this->nonce = sanitize_text_field( $_GET['nonce'] );

		if( empty( $this->meta_site_id ) || empty( $this->user_id ) || empty( $this->nonce ) ){
			return false;
		}

		if( ! $this->get_sso_meta() ){
			return false;
		}

		$current_site_id = get_current_blog_id();
		$cur_site_meta = isset( $this->sso_meta[ $current_site_id ] ) ? $this->sso_meta[ $current_site_id ] : false;

		if( ! $cur_site_meta || ! isset( $cur_site_meta['expires'], $cur_site_meta['cookie_domain'] ) ){
			return false;
		}

		if( time() > absint( $cur_site_meta['expires'] ) ){
			wp_die( __( 'SSO has expired, please try logging in again.' ) );
		}

		/**
		 * Set COOKIE_DOMAIN to the domain we're doing SSO on, this is required for when
		 * set_user_auth_cookie() is called.
		 */
		define( 'COOKIE_DOMAIN', $cur_site_meta['cookie_domain'] );

		/**
		 * Prevent infinite loop when we call wp_set_auth_cookie() in set_user_auth_cookie()
		 */
		remove_action( 'set_logged_in_cookie', array( $this, 'set_logged_in_cookie' ) );

		/**
		 * Trigger setting the auth cookie after plugins are loaded. This is required because at this point the other required
		 * functions and constants have not been defined yet.
		 */
		add_action( 'plugins_loaded', array( $this, 'set_user_auth_cookie' ) );
	}

	/**
	 * Set User Authentication Cookie
	 *
	 * This method is only triggered after we have successfully validated expiration, and nonce.
	 * At this point, the local class object values have already been set (and only set for this page load).
	 *
	 * @since @@version
	 *
	 */
	public function set_user_auth_cookie() {

		if( ! empty( $this->user_id ) ){
			wp_set_auth_cookie( $this->user_id, true );

			/**
			 * Make sure we remove this from SSO meta
			 */
			$current_site_id = get_current_blog_id();
			unset( $this->sso_meta[ $current_site_id ] );
			$this->set_sso_meta();

			$this->redirect_end_or_next();
		}
	}

	/**
	 * Redirect to SSO or End (if no more sites to SSO)
	 *
	 * @since @@version
	 *
	 */
	public function redirect_end_or_next() {

		if( empty( $this->sso_meta ) ){
			/**
			 * This is just a quick one-liner to easily remove all query arguments from a URL,
			 * and return only the main URL itself.
			 */
			$domain_homepage = explode( '?', esc_url_raw( add_query_arg( array() ) ) );
			wp_redirect( $domain_homepage[0] );
			exit;
		}

		$next_site_id = key( $this->sso_meta );
		$domain = $this->sso_meta[ $next_site_id ]['domain'];
		$protocol = is_ssl() ? 'https://' : 'http://';

		$site_url = add_query_arg( array( 'wpu_sso_me' => 'true', 'meta_site_id' => $this->meta_site_id, 'user_id' => $this->user_id, 'nonce' => $this->nonce ), "{$protocol}{$domain}" );

		if ( ! function_exists( 'wp_redirect' ) ) {
			require_once ABSPATH . '/wp-includes/pluggable.php';
		}

		wp_redirect( $site_url );
		exit;
	}

	/**
	 * Check if Cookie Exists to Start SSO
	 *
	 * @since @@version
	 *
	 */
	public function plugins_loaded() {

		if ( ! isset( $_COOKIE[ $this->cookie_name ] ) || empty( $_COOKIE[ $this->cookie_name ] ) ) {
			return;
		}

		$raw_data = json_decode( $_COOKIE[ $this->cookie_name ], true );
		if( empty( $raw_data ) || ! is_array( $raw_data ) ){
			return;
		}

		if( ! isset( $raw_data['meta_site_id'], $raw_data['user_id'], $raw_data['nonce'] ) ){
			return;
		}

		$this->meta_site_id = sanitize_text_field( $raw_data['meta_site_id'] );
		$this->user_id = sanitize_text_field( $raw_data['user_id'] );
		$this->nonce = sanitize_text_field( $raw_data['nonce'] );

		if( empty( $this->meta_site_id ) || empty( $this->user_id ) || empty( $this->nonce ) ){
			return;
		}

		//undefined wp_nonce_tick
		if( ! $this->verify_shared_nonce( $this->nonce, "{$this->user_id}_wpu_sso_me" ) ){
			return;
		}

		if( ! $this->get_sso_meta() ){
			return;
		}

		$this->redirect_end_or_next();
	}

	/**
	 * Set SSO Cookie
	 *
	 * @return bool
	 * @since @@version
	 *
	 */
	public function set_sso_cookie() {

		$data = array(
			'meta_site_id' => get_current_blog_id(),
			'user_id' => $this->user_id,
			'nonce' => $this->create_shared_nonce( "{$this->user_id}_wpu_sso_me" )
		);

		// HTTPS
		setcookie( $this->cookie_name, json_encode( $data ), time() + $this->lifespan, COOKIEPATH, COOKIE_DOMAIN, true, true );
		// HTTP
		return setcookie( $this->cookie_name, json_encode( $data ), time() + $this->lifespan, COOKIEPATH, COOKIE_DOMAIN, false, true );
	}

	/**
	 * Create shared nonce token
	 *
	 * WP's tokens are linked to the current user. Due to the nature of what we're
	 * doing here, we need to make a user-independent nonce. The user we're working
	 * on can instead be part of the action.
	 *
	 * @param string $action Scalar value to add context to the nonce.
	 *
	 * @return string Nonce token.
	 */
	private function create_shared_nonce( $action ) {
		$i = $this->nonce_tick();
		return substr( wp_hash( $i . '|' . $action, 'nonce' ), - 12, 10 );
	}

	/**
	 * Verify that correct shared nonce was used with time limit.
	 *
	 * Uses nonces not linked to the current user. See {@see create_shared_nonce()}
	 * for more about why this exists.
	 *
	 * @param string     $nonce  Nonce that was used in the form to verify
	 * @param string|int $action Should give context to what is taking place and be the same when nonce was created.
	 *
	 * @return bool Whether the nonce check passed or failed.
	 */
	private function verify_shared_nonce( $nonce, $action ) {

		if ( empty( $nonce ) ) {
			return false;
		}

		$i = $this->nonce_tick();

		// Nonce generated 0-12 hours ago
		$expected = substr( wp_hash( $i . '|' . $action, 'nonce' ), - 12, 10 );
		if ( hash_equals( $expected, $nonce ) ) {
			return 1;
		}

		// Invalid nonce
		return false;
	}

	/**
	 * Returns the time-dependent variable for nonce creation.
	 *
	 * Same as wp_nonce_tick() except the lifespan is the lifespan configured specifically for SSO
	 *
	 * @return false|float
	 * @since @@version
	 *
	 */
	private function nonce_tick(){
		return ceil( time() / ( $this->lifespan / 2 ) );
	}

	/**
	 * Store SSO Meta
	 *
	 * @since @@version
	 *
	 */
	private function set_sso_meta(){
		switch_to_blog( $this->meta_site_id );
		update_user_meta( $this->user_id, $this->user_meta_key, $this->sso_meta );
		restore_current_blog();
	}

	/**
	 * Get SSO Meta
	 *
	 * @return false|mixed
	 * @since @@version
	 *
	 */
	private function get_sso_meta(){
		switch_to_blog( $this->meta_site_id );
		$this->sso_meta = get_user_meta( $this->user_id, $this->user_meta_key, true );
		restore_current_blog();
		return empty( $this->sso_meta ) ? false : $this->sso_meta;
	}

	/**
	 * Fires immediately before the logged-in authentication cookie is set.
	 *
	 * @param string $logged_in_cookie The logged-in cookie value.
	 * @param int    $expire           The time the login grace period expires as a UNIX timestamp.
	 *                                 Default is 12 hours past the cookie's expiration time.
	 * @param int    $expiration       The time when the logged-in authentication cookie expires as a UNIX timestamp.
	 *                                 Default is 14 days from now.
	 * @param int    $user_id          User ID.
	 * @param string $scheme           Authentication scheme. Default 'logged_in'.
	 * @param string $token            User's session token to use for this cookie.
	 *
	 * @since 2.6.0
	 * @since 4.9.0 The `$token` parameter was added.
	 *
	 */
	public function set_logged_in_cookie( $logged_in_cookie, $expire, $expiration, $user_id, $scheme, $token ) {

		/**
		 * No need to do anything if unable to get subscription for user
		 */
		if ( ! $sub = wu_get_subscription( $user_id ) ) {
			return;
		}

		$this->user_id      = $user_id;
		$this->meta_site_id = get_current_blog_id();

		$site_ids = $sub->get_sites_ids();

		if ( empty( $site_ids ) ) {
			return;
		}

		if ( ! $this->build_sso_meta( $site_ids ) ) {
			return;
		}

		$this->set_sso_meta();
		$this->set_sso_cookie();
	}

	/**
	 * Build SSO Meta to Store
	 *
	 * @param array $site_ids
	 *
	 * @return array
	 * @since @@version
	 *
	 */
	private function build_sso_meta( $site_ids = array() ) {

		$this->sso_meta = array();

		foreach ( (array) $site_ids as $site_id ) {

			$current_mappings = \Mercator\Mapping::get_by_site( $site_id );

			foreach ( (array) $current_mappings as $current_mapping ) {

				$domain        = $current_mapping->get_domain();
				$cookie_domain = substr( $domain, 0, 4 ) === 'www.' ? substr( $domain, 4 ) : $domain;

				$this->sso_meta[ $site_id ] = array(
					'site_id'       => $site_id,
					'domain'        => $domain,
					'cookie_domain' => $cookie_domain,
					'expires'       => time() + $this->lifespan,
				);

			}

		}

		return $this->sso_meta;
	}
}

new WP_Ultimo_SSO_Enhanced();
