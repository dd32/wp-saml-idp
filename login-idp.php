<?php
/**
 * This file is the template and processor for the ?action=idp endpoint, this is the landing page for a user who is undergoing a SAML login.
 */
namespace WPSAMLIDP;
use WP_Error;

$saml = retrieve_saml_request();
if ( ! $saml ) {
	wp_die( 'Invalid request', 400 );
}

// Current url, used by the auth redirect and the not-you link.
$current_url = add_query_arg(
	[
		'SAMLRequest' => urlencode( $_REQUEST['SAMLRequest'] ?? '' ),
		'RelayState'  => urlencode( $_REQUEST['RelayState'] ?? '' ),
	],
	get_idp_url()
);

// Check if logged in, bounce through the login back here if not.
if ( ! is_user_logged_in() ) {
	wp_safe_redirect( wp_login_url( $current_url ) );
	exit;
}

$saml_client = validate_saml_client(
	$saml->getMessage()->getIssuer()->getValue(),
	$saml->getMessage()->getAssertionConsumerServiceURL()
);

$saml_destination = $saml->getMessage()->getProviderName() ?: $saml->getMessage()->getIssuer()->getValue();
$saml_destination = preg_replace( '#^https?://#', '', $saml_destination );

$errors = new WP_Error();
if ( is_wp_error( $saml_client ) && $saml_client->has_errors() ) {
	$errors->merge_from( $saml_client );
}

login_header( sprintf( __( 'Login to %s', 'wp-saml-idp' ), esc_html( $saml_destination ) ), '', $errors );

/*
 * NOTE: This is a GET request, despite being a confirmation form.
 * This ensures that it's a HTTPRedirect binding in the SAML library, as GET and POST have different encodings.
 * We want to pass the provided SAMLRequest and RelayState through to the sign-and-return without having to re-create it for the different type.
 * A nonce is included to limit CSRF type attacks.
 */
echo '<form action="' . esc_url( get_idp_url('confirm') ) . '" method="GET" class="idp-login-confirm">';
echo '<input type="hidden" name="SAMLRequest" value="' . esc_attr( wp_unslash( $_REQUEST['SAMLRequest'] ) ) . '">';
echo '<input type="hidden" name="RelayState" value="' . esc_attr( wp_unslash( $_REQUEST['RelayState'] ?? '' ) ) . '">';
echo '<input type="hidden" name="action" value="idp_confirm">'; // TODO: This duplicates the get args in the form action.
wp_nonce_field( 'saml_confirm' );

echo '<style>
	.avatar-wrapper {
		text-align: center;
		margin-bottom: 1em;
	}
	img.avatar {
		border-radius: 50%;
	}
	.continue input {
		width: 100%;
	}
	.idp-login-confirm p {
		margin: 1em 0;
	}
	.idp-login-confirm .button-primary {
		float: none;
	}
</style>';

echo '<div class="avatar-wrapper">', get_avatar( wp_get_current_user() ), '</div>';

printf(
	'<p>' . __( 'Do you wish to proceed to %1$s as %2$s?', 'wp-saml-idp' ) . '</p>',
	'<code>' . esc_html( $saml_destination ) . '</code>',
	'<code>' . esc_html( wp_get_current_user()->user_login ) . '</code>'
);

printf(
	'<p class="continue"><input type="submit" name="idp_confirm" class="button-primary" value="%s"></p>',
	esc_attr( sprintf( __( 'Log in to %s', 'wp-saml-idp' ), $saml_destination ) )
);

echo '<p><a href="' . esc_url( wp_logout_url( $current_url ) ) . '">' . __( 'Not you? Switch user.', 'wp-saml-idp' ) . '</a></p>';

echo '<p><a href="' . esc_url( network_home_url('/') ) . '">' . __( 'No, take me home', 'wp-saml-idp' ) . '</a></p>';

echo '</form>'; // .idp-login-confirm
login_footer();

exit;