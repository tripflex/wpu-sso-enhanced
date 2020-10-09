# wpu-sso-enhanced
WP Ultimo 1.x enhancement for Mercator SSO to support custom domains with recent SameSite=Lax change in Chrome, etc.

This file MUST be placed in the wp-content/mu-plugins/ directory to work correctly.

Functionality is handled in a few different ways.  If $trigger_on_auth_cookie_set is enabled below, when a user's authentication cookie is set (outside of this code), SSO meta will be generated for that user, stored in the network site user meta including the user's custom domains, site IDs, and SSO expiration (@see $this->build_sso_meta()).

This is done so that data can not be modified by bad actors in any way.

 When the next page is loaded (which normally always happens right after auth cookie is set due to redirect after login), and the cookie is detected (@see $this->check_cookie_start_sso()) the nonce will be validated and the SSO meta set above will be pulled to start the SSO flow process.
 
The user is then redirected to the custom domain to start the SSO, passing the nonce and user id in query params (ie domain.com/?wpu_sso_me=1234&nonce=XXX), which is then detected in $this->maybe_process_sso(), where the COOKIE_DOMAIN is configured, and then auth cookie is set, redirecting to next site to do SSO on or if no more sites, redirecting to the main page of the last site SSO processed on.
 
 Alternatively if you set $trigger_on_auth_cookie_set to false below, you will need to trigger this yourself using the "wpu_sso_me_next_page_load" or "wpu_sso_me_now" actions, passing the user ID as the only argument.
