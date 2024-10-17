<?php
namespace WPSAMLIDP;
use WP_Error;

// for retrieve_saml_request()
use \Symfony\Component\HttpFoundation\Request as Symfony_Request;
use \LightSaml\Binding\BindingFactory;
use \LightSaml\Context\Profile\MessageContext;

/**
 * Plugin Name: WP SAML IDP
 * Description: Bare basics SAML Identity Provider for WordPress
 * Version: 0.1
 */

include __DIR__ . '/vendor/autoload.php';

add_action( 'admin_menu', function() {
	include __DIR__ . '/admin.php';
}, 1 );

add_action( 'login_form_idp_confirm', __NAMESPACE__ . '\login_form_idp_confirm' );
function login_form_idp_confirm() {
	include __DIR__ . '/login-idp-confirm.php';
	exit;
}

add_action( 'login_form_idp', __NAMESPACE__ . '\login_form_idp' );
function login_form_idp() {

	// If this is a nonce'd confirmation, just go straight to confirmation instead of presenting the authorization screen.
	if (
		is_user_logged_in() &&
		isset( $_REQUEST['service'] ) &&
		isset( $_REQUEST['_wpnonce'] ) &&
		empty( $_REQUEST['SAMLRequest'] ) &&
		wp_verify_nonce( $_REQUEST['_wpnonce'], 'saml_confirm_' . wp_unslash( $_REQUEST['service'] ) )
	) {
		return login_form_idp_confirm();
	}

	include __DIR__ . '/login-idp.php';
	exit;
}

/**
 * Retrieve the URL for the IDP.
 *
 * @param string $endpoint
 * @return string
 */
function get_idp_url( $endpoint = '' ) {
	return add_query_arg(
		'action',
		'idp' . ( $endpoint ? "_{$endpoint}" : '' ),
		wp_login_url()
	);
}

/**
 * Retrieve the URL to login to a specific service.
 *
 * This URL can be used to initiate a idp-initiated login to a SP service.
 *
 * @param string $service    The registered service to login to.
 * @param bool   $auto_login Whether to automatically login to the service, or to present an authorization screen.
 * @return string|false URL to login, false if unknown service.
 */
function get_login_to_service_url( $service, $auto_login = false ) {
	if ( is_wp_error( validate_saml_client( $service ) ) ) {
		return false;
	}

	$url = add_query_arg( 'service', urlencode( $service ), get_idp_url() );
	if ( $auto_login ) {
		$url = wp_nonce_url( $url, "saml_confirm_{$service}" );
	}

	return $url;
}

/**
 * Retrieve the public and private keys for the IDP.
 *
 * @return object {
 *  @var \LightSaml\Credential\X509Certificate $public
 *  @var \RobRichards\XMLSecLibs\XMLSecurityKey $private
 * }
 */
function get_idp_keys() {
	static $keys = null;
	if ( $keys ) {
		return $keys;
	}

	$public_key  = defined( 'IDP_CERT_PUB' )  ? IDP_CERT_PUB  : get_option( 'idp_cert.pub' );
	$private_key = defined( 'IDP_CERT_PRIV' ) ? IDP_CERT_PRIV : get_option( 'idp_cert.priv' );

	$public = new \LightSaml\Credential\X509Certificate();
	$public->loadPem( $public_key );

	$private = \LightSaml\Credential\KeyHelper::createPrivateKey( $private_key, '' );

	$keys = (object)compact( 'public', 'private' );
	return $keys;
}

/**
 * Retrieve the IDP issuer name, which by default is the home URL.
 *
 * Changing this value may invalidate existing SAML assertions.
 * This can be customized via the IDP_ISSUER_NAME constant.
 *
 * @return string
 */
function get_idp_issuer() {
	return defined( 'IDP_ISSUER_NAME' ) ? IDP_ISSUER_NAME : home_url();
}

/**
 * Parse and return the incoming SAML request.
 *
 * @return false|\LightSaml\Context\Profile\MessageContext
 */
function retrieve_saml_request() {
	if ( empty( $_REQUEST['SAMLRequest'] ) ) {
		return false;
	}

	static $message = null;
	if ( $message ) {
		return $message;
	}

	// TODO: This is the only place that uses Symfony.
	$symfony_request = Symfony_Request::createFromGlobals();
	$binding         = (new BindingFactory)->getBindingByRequest( $symfony_request );
	$message         = new MessageContext();

	$binding->receive( $symfony_request, $message );

	return $message;
}

/**
 * Validate the SAML client can be used with this site, and return the client details.
 *
 * @param string $client
 * @param string $acs_url
 * @return array|WP_Error
 */
function validate_saml_client( $client, $acs_url = false ) {
	$clients = get_saml_clients();

	if ( ! isset( $clients[ $client ] ) ) {
		return new WP_Error( 'invalid_client', 'Invalid Authentication Client' );
	}

	if (
		! empty( $clients[ $client ]['assertionConsumerService'] ) &&
		$acs_url &&
		$acs_url !== $clients[ $client ]['assertionConsumerService']
	) {
		return new WP_Error( 'invalid_acs', 'Invalid Authentication Client Service URL' );
	}

	$return = $clients[ $client ];
	$return['clientName']     = $client;
	$return['friendlyName'] ??= $client;

	return $return;
}

function get_saml_clients() {
	$clients = [];
	if ( defined( 'IDP_TRUSTED_SP_CALLBACK' ) && is_callable( IDP_TRUSTED_SP_CALLBACK ) ) {
		$clients = call_user_func( IDP_TRUSTED_SP_CALLBACK );
	} else {
		foreach ( (array) get_option( 'idp_trusted_sps', [] ) as $client => $url ) {
			$clients[ $client ] = [];
			if ( $url ) {
				$clients[ $client ]['assertionConsumerService'] = $url;
			}
		}
	}

	/**
	 * Filter the list of trusted service providers.
	 *
	 * @param array $clients
	 * @return array
	 */
	$clients = apply_filters( 'idp_trusted_service_providers', $clients );

	return $clients;
}
