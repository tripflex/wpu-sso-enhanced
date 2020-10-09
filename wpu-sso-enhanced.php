<?php
/*
  Plugin Name: WP Ultimo SSO - Mercator Enhanced
  Plugin URI: https://smyl.es
  Description: WP Ultimo SSO handling for newer versions of Chrome
  Version: 1.0.0
  Author: Myles McNamara
  Author URI: https://smyles.dev
*/

defined( 'ABSPATH' ) or die( 'No script kiddies please!' );

/**
 * This file MUST be placed in the wp-content/mu-plugins/ directory to work correctly.
 *
 * Functionality is handled in a few different ways.  If $trigger_on_auth_cookie_set is enabled below, when a user's authentication cookie is set (outside of this code),
 * SSO meta will be generated for that user, stored in the network site user meta including the user's custom domains, site IDs, and SSO expiration (@see $this->build_sso_meta()).
 *
 * This is done so that data can not be modified by bad actors in any way.
 *
 * When the next page is loaded (which normally always happens right after auth cookie is set due to redirect after login), and the cookie is detected (@see $this->check_cookie_start_sso())
 * the nonce will be validated and the SSO meta set above will be pulled to start the SSO flow process.
 *
 * The user is then redirected to the custom domain to start the SSO, passing the nonce and user id in query params (ie domain.com/?wpu_sso_me=1234&nonce=XXX), which is then detected in
 * $this->maybe_process_sso(), where the COOKIE_DOMAIN is configured, and then auth cookie is set, redirecting to next site to do SSO on or if no more sites, redirecting to the main page
 * of the last site SSO processed on.
 *
 * Alternatively if you set $trigger_on_auth_cookie_set to false below, you will need to trigger this yourself using the "wpu_sso_me_next_page_load" or "wpu_sso_me_now" actions, passing the
 * user ID as the only argument.
 */

/**
 * Class WP_Ultimo_SSO_Enhanced
 */
class WP_Ultimo_SSO_Enhanced {

	// User defined values (you can customize handling by setting values below)

	/**
	 * @var bool Whether or not to trigger SSO on setting of user auth cookie.
	 *           If this is set to false, you MUST trigger the SSO your self using wpu_sso_me_next_page_load or wpu_sso_me_now actions
	 */
	private $trigger_on_auth_cookie_set = true;
	/**
	 * @var bool Whether or not to use remote IP in generating nonce action (for extra sanity check).
	 *           If users have issues with logging in due to dynamic IP addresses, set this to false.
	 */
	private $use_remote_ip = true;
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

	// Class object storage (do not modify values below here)

	/**
	 * @var array Local object storage of SSO meta
	 */
	private $sso_meta = array();
	/**
	 * @var array Current site meta (from SSO meta) only set when starting SSO processing (@see $this->maybe_process_sso())
	 */
	private $current_site_meta = array();
	/**
	 * @var integer User ID of user attempting to SSO
	 */
	private $user_id;
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
		add_action( 'plugins_loaded', array( $this, 'check_cookie_start_sso' ) );

		/**
		 * This action is for triggering SSO on the next page load, can be used by themes or plugins
		 */
		add_action( 'wpu_sso_me_next_page_load', array( $this, 'trigger_sso_next_page_load' ) );
		/**
		 * This action is for triggering SSO immediately
		 */
		add_action( 'wpu_sso_me_now', array( $this, 'trigger_sso_now' ) );
	}

	/**
	 * Check if Cookie Exists to Start SSO
	 *
	 * @since @@version
	 *
	 */
	public function check_cookie_start_sso() {

		if ( ! isset( $_COOKIE[ $this->cookie_name ] ) || empty( $_COOKIE[ $this->cookie_name ] ) ) {
			return;
		}

		$raw_data = json_decode( $_COOKIE[ $this->cookie_name ], true );
		if ( empty( $raw_data ) || ! is_array( $raw_data ) ) {
			return;
		}

		if ( ! isset( $raw_data['user_id'], $raw_data['nonce'] ) ) {
			return;
		}

		$this->user_id = absint( $raw_data['user_id'] );
		$this->nonce   = sanitize_text_field( $raw_data['nonce'] );

		if ( empty( $this->user_id ) || empty( $this->nonce ) ) {
			return;
		}

		if ( ! $this->verify_shared_nonce() ) {
			return;
		}

		if ( ! $this->get_sso_meta() ) {
			return;
		}

		/**
		 * Remove SSO cookie before triggering redirect
		 */
		$this->set_sso_cookie( true );
		$this->redirect_end_or_next();
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
		if( ! isset( $_GET['wpu_sso_me'], $_GET['nonce'] ) ){
			return false;
		}

		/**
		 * Sanitize and set values for the SSO
		 */
		$this->user_id = absint( $_GET['wpu_sso_me'] );
		$this->nonce = sanitize_text_field( $_GET['nonce'] );

		if( empty( $this->user_id ) || empty( $this->nonce ) ){
			return false;
		}

		if( ! $this->get_sso_meta() ){
			return false;
		}

		$current_site_id = get_current_blog_id();
		$this->current_site_meta = isset( $this->sso_meta[ $current_site_id ] ) ? $this->sso_meta[ $current_site_id ] : false;

		if( ! $this->current_site_meta || ! isset( $this->current_site_meta['cookie_domain'] ) ){
			return false;
		}

		/**
		 * Set COOKIE_DOMAIN to the domain we're doing SSO on, this is required for when
		 * set_user_auth_cookie() is called.
		 */
		define( 'COOKIE_DOMAIN', $this->current_site_meta['cookie_domain'] );
		/**
		 * Define constant WPU_DOING_SSO so other plugins or code know that on this page load/execution,
		 * we are doing SSO processing
		 */
		define( 'WPU_DOING_SSO', true );

		/**
		 * Trigger setting the auth cookie after plugins are loaded. This is required because at this point the other required
		 * functions and constants have not been defined yet.
		 */
		add_action( 'plugins_loaded', array( $this, 'set_user_auth_cookie' ), -1 );
	}

	/**
	 * Set User Authentication Cookie
	 *
	 * This method is only triggered after we have successfully set the cookie domain, BEFORE validating nonce and expiration.
	 * At this point, the local class object values have already been set (and only set for this page load).
	 *
	 * @since @@version
	 *
	 */
	public function set_user_auth_cookie() {

		if ( ! $this->verify_shared_nonce() ) {
			wp_die( __( 'SSO failed, unable to validate nonce.' ) );
		}

		if ( time() > absint( $this->current_site_meta['expires'] ) ) {
			wp_die( __( 'SSO has expired, please try logout, and try again.' ) );
		}

		if ( ! user_can( $this->user_id, 'read' ) ) {
			wp_die( __( 'Single Sign On is trying to log you in, but your user account is not authorized for this site. Please contact a network admin and ask them to add you to this site.' ) );
		}

		/**
		 * Remove this site from SSO meta (before setting auth cookie)
		 */
		unset( $this->sso_meta[ $this->current_site_meta['site_id'] ] );
		$this->set_sso_meta();

		/**
		 * Prevent infinite loop when we call wp_set_auth_cookie() in set_user_auth_cookie()
		 */
		remove_action( 'set_logged_in_cookie', array( $this, 'set_logged_in_cookie' ) );
		wp_set_auth_cookie( $this->user_id, true );

		$this->redirect_end_or_next();
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

		$site_url = add_query_arg( array( 'wpu_sso_me' => $this->user_id, 'nonce' => $this->nonce ), "{$protocol}{$domain}" );
		wp_redirect( $site_url );
		exit;
	}

	/**
	 * Get Nonce Action
	 *
	 * @return string
	 * @since @@version
	 *
	 */
	private function get_nonce_action(){
		$default = "{$this->user_id}_wpu_sso_me";

		if( ! $this->use_remote_ip ){
			return $default;
		}

		/**
		 * This value can't be spoofed (only if have control over ISP or via BGP which would be almost impossible)
		 *
		 * In theory this could also be the IP of a proxy as well, but for our situation we're really only using it to validate
		 * the request is coming from the same IP address, just as an additional sanity check, and not in the terms of security
		 * which is handled by the local WordPress salt/hashing.
		 */
		$remote_ip = $_SERVER['REMOTE_ADDR'];
		// IPv4 modify 127.0.0.1 to 127_0_0_1
		$remote_ip_slug = str_replace( '.', '_', $remote_ip );
		// IPv6 modify 2001:db8::1 to 2001_db8__1
		$remote_ip_slug = str_replace( ':', '_', $remote_ip_slug );

		return "{$default}_{$remote_ip_slug}";
	}

	/**
	 * Set SSO Cookie
	 *
	 * @param bool $remove
	 *
	 * @return bool
	 * @since @@version
	 */
	public function set_sso_cookie( $remove = false ) {

		$data = $remove ? array() : array(
			'user_id' => $this->user_id,
			'nonce' => $this->create_shared_nonce()
		);

		$lifespan = $remove ? time() - 1 : time() + $this->lifespan;

		// HTTPS
		setcookie( $this->cookie_name, json_encode( $data ), $lifespan, COOKIEPATH, COOKIE_DOMAIN, true, true );
		// HTTP
		return setcookie( $this->cookie_name, json_encode( $data ), $lifespan, COOKIEPATH, COOKIE_DOMAIN, false, true );
	}

	/**
	 * Create shared nonce token
	 *
	 * WP's tokens are linked to the current user. Due to the nature of what we're
	 * doing here, we need to make a user-independent nonce. The user we're working
	 * on can instead be part of the action.
	 *
	 * @return string Nonce token.
	 */
	private function create_shared_nonce() {
		$action = $this->get_nonce_action();
		$i = $this->nonce_tick();
		return substr( wp_hash( $i . '|' . $action, 'nonce' ), - 12, 10 );
	}

	/**
	 * Verify that correct shared nonce was used with time limit.
	 *
	 * Uses nonces not linked to the current user. See {@see create_shared_nonce()}
	 * for more about why this exists.
	 *
	 * @return bool Whether the nonce check passed or failed.
	 */
	private function verify_shared_nonce() {

		if ( empty( $this->nonce ) ) {
			return false;
		}

		$action = $this->get_nonce_action();
		$i = $this->nonce_tick();

		$expected = substr( wp_hash( $i . '|' . $action, 'nonce' ), - 12, 10 );
		if ( hash_equals( $expected, $this->nonce ) ) {
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
		/**
		 * SSO metadata is stored on network user meta, to prevent modification by bad actors
		 */
		switch_to_blog( 1 );
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
		/**
		 * SSO metadata is stored on network user meta, to prevent modification by bad actors
		 */
		switch_to_blog( 1 );
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
		if( ! $this->trigger_on_auth_cookie_set ){
			return;
		}

		$this->trigger_sso_next_page_load( $user_id );
	}

	/**
	 * Setup SSO Handling
	 *
	 * @param $user_id
	 *
	 * @return bool
	 * @since @@version
	 *
	 */
	private function setup_sso( $user_id ){

		/**
		 * No need to do anything if unable to get subscription for user
		 */
		if ( ! $sub = wu_get_subscription( $user_id ) ) {
			return false;
		}

		$this->user_id = $user_id;
		$site_ids      = $sub->get_sites_ids();

		if ( empty( $site_ids ) ) {
			return false;
		}

		if ( ! $this->build_sso_meta( $site_ids ) ) {
			return false;
		}

		$this->set_sso_meta();
		return true;
	}

	/**
	 * Trigger SSO handling immediately
	 *
	 * @param $user_id
	 *
	 * @since @@version
	 *
	 */
	public function trigger_sso_now( $user_id ) {
		if ( $this->setup_sso( $user_id ) ) {
			$this->nonce = $this->create_shared_nonce();
			$this->redirect_end_or_next();
		}
	}

	/**
	 * Trigger SSO handling on next page load
	 *
	 * This method can be called via other plugins or themes by using the wpu_sso_me_next_page_load action,
	 * passing the user ID as the only parameter.
	 *
	 * @param $user_id
	 *
	 * @since @@version
	 *
	 */
	public function trigger_sso_next_page_load( $user_id ){
		if( $this->setup_sso( $user_id ) ){
			$this->set_sso_cookie();
		}
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
