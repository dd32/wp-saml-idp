<?php
/**
 * This file is the template and processor for the ?action=idp endpoint, this is the landing page for a user who is undergoing a SAML login.
 */
namespace WPSAMLIDP;
use WP_Error;

$service = $_GET['service'] ?? '';

$saml = retrieve_saml_request();
if ( ! $saml && ! $service ) {
	wp_die( 'Invalid request', 400 );
}

// Current url, used by the auth redirect and the not-you link.
$current_url = add_query_arg(
	array_filter( [
		'SAMLRequest' => urlencode( $_REQUEST['SAMLRequest'] ?? '' ),
		'RelayState'  => urlencode( $_REQUEST['RelayState'] ?? '' ),
		'service'     => urlencode( $service ),
	] ),
	get_idp_url()
);

// Check if logged in, bounce through the login back here if not.
if ( ! is_user_logged_in() ) {
	wp_safe_redirect( wp_login_url( $current_url ) );
	exit;
}

// Check the service is valid.
$issuer      = $saml ? $saml->getMessage()->getIssuer()->getValue() : $service;
$saml_client = validate_saml_client(
	$issuer,
	$saml ? $saml->getMessage()->getAssertionConsumerServiceURL() : null
);

$errors = new WP_Error();
if ( is_wp_error( $saml_client ) && $saml_client->has_errors() ) {
	$errors->merge_from( $saml_client );
}

$saml_destination = '';
if ( ! is_wp_error( $saml_client ) && isset( $saml_client['friendlyName'] ) ) {
	$saml_destination = $saml_client['friendlyName'];
}
if ( $saml ) {
	$saml_destination ??= $saml->getMessage()->getProviderName() ?: $saml->getMessage()->getIssuer()->getValue();
} elseif ( $service ) {
	$saml_destination ??= $service;
}
$saml_destination = preg_replace( '#^https?://#', '', $saml_destination );

login_header( sprintf( __( 'Login to %s', 'wp-saml-idp' ), esc_html( $saml_destination ) ), '', $errors );

// Exit early if there are errors.
if ( $errors->has_errors() ) {
	login_footer();
	exit;
}

/*
 * NOTE: This is a GET request, despite being a confirmation form.
 * This ensures that it's a HTTPRedirect binding in the SAML library, as GET and POST have different encodings.
 * We want to pass the provided SAMLRequest and RelayState through to the sign-and-return without having to re-create it for the different type.
 * A nonce is included to limit CSRF type attacks.
 */
echo '<form action="' . esc_url( get_idp_url('confirm') ) . '" method="GET" class="idp-login-confirm">';
foreach ( [ 'SAMLRequest', 'RelayState', 'service' ] as $key ) {
	if ( ! empty( $_REQUEST[ $key ] ) ) {
		echo '<input type="hidden" name="' . esc_attr( $key ) . '" value="' . esc_attr( wp_unslash( $_REQUEST[ $key ] ) ) . '">';
	}
}
foreach ( wp_parse_args( wp_parse_url( get_idp_url('confirm'), PHP_URL_QUERY ) ) as $key => $value ) {
	echo '<input type="hidden" name="' . esc_attr( $key ) . '" value="' . esc_attr( $value ) . '">';
}
wp_nonce_field( 'saml_confirm_' . $issuer );

/**
 * Some users don't have a display name.
 * If they don't, we'll use their username.
 */
function get_user_display_info() {
	$user = wp_get_current_user();

	if ( empty( $user->display_name ) ) {
		return '<h2>' . esc_html( $user->user_login ) . '</h2>';
	}

	return '<h2>' . esc_html( $user->display_name ) . '</h2>' .
	'<h3>' . esc_html( $user->user_login ) . '</h3>';
}

echo '<style>
	.avatar-wrapper {
		text-align: center;
		margin-bottom: 24px;
	}

	img.avatar {
		margin: 8px auto;
		border-radius: 50%;
	}

	.avatar-wrapper h2 {
		font-weight: 500;
		font-size: 18px;
	}

	.avatar-wrapper h3 {
		font-size: 14px;
		font-weight: normal;
		color: #656a71;
	}

	.continue input {
		width: 100%;
	}

	.idp-login-confirm {
		text-align: center;
	}

	.idp-login-confirm p {
		margin: 1em 0 !important;
	}

	.idp-login-confirm .button-primary {
		float: none;
	}

	.idp-login-confirm .continue + * {
		font-size: 13px;
	}

</style>';

echo '<div class="avatar-wrapper">';
echo get_avatar( wp_get_current_user() );
echo get_user_display_info();
echo '</div>';

printf(
	'<p class="continue"><input type="submit" name="idp_confirm" class="button-primary" value="%s"></p>',
	/* translators: %s is the SAML destination */
	esc_attr( sprintf( __( 'Log in to %s', 'wp-saml-idp' ), $saml_destination ) )
);

echo '<a href="' . esc_url( network_home_url('/') ) . '">' . __( 'No, take me home', 'wp-saml-idp' ) . '</a>';

echo '</form>'; // .idp-login-confirm
echo '<p id="nav">';
printf(
	'<a href="%s">%s</a>',
	esc_url( wp_logout_url( $current_url ) ),
	/* translators: %s is the user's display name */
	sprintf( __( 'Not %s? Switch user.', 'wp-saml-idp' ), esc_html( wp_get_current_user()->user_login ) )
);
echo '</p>';

login_footer();

exit;