<?php
namespace WPSAMLIDP;

add_action( 'admin_menu', __NAMESPACE__ . '\admin_menu' );
function admin_menu() {
	add_options_page( __( 'WP SAML IDP', 'wp-saml-idp' ), __( 'WP SAML IDP', 'wp-saml-idp' ), 'manage_options', 'saml-idp', __NAMESPACE__ . '\admin_page' );
}

function admin_page() {
	$public_key  = defined( 'IDP_CERT_PUB' )  ? IDP_CERT_PUB  : get_option( 'idp_cert.pub' );
	$private_key = defined( 'IDP_CERT_PRIV' ) ? IDP_CERT_PRIV : get_option( 'idp_cert.priv' );

	if ( $_POST && wp_verify_nonce( $_POST['_wpnonce'], 'idp_save' ) ) {
		$public_key  = trim( wp_unslash( $_POST['public_certificate'] ) );
		$private_key = trim( wp_unslash( $_POST['private_key'] ) );
		$posted_sps  = array_filter( array_map( 'trim', explode( "\n", wp_unslash( $_POST['trusted_sps'] ) ) ) );
		$trusted_sps = [];
		foreach ( $posted_sps as $value ) {
			$parts = array_map( 'trim', explode( '|', $value ) );
			if ( 1 === count( $parts ) ) {
				$trusted_sps[ $parts[0] ] = '';
			} else {
				$trusted_sps[ $parts[0] ] = $parts[1];
			}
		}

		if ( $private_key && str_contains( $private_key, 'Private Key not shown.' ) ) {
			$private_key = get_option( 'idp_cert.priv' );
		}

		defined( 'IDP_CERT_PUB' ) || update_option( 'idp_cert.pub', $public_key );
		defined( 'IDP_CERT_PRIV' ) || update_option( 'idp_cert.priv', $private_key );

		defined( 'IDP_TRUSTED_SP_CALLBACK' ) || update_option( 'idp_trusted_sps', $trusted_sps );
	}

	$trusted_providers = [];
	foreach ( get_saml_clients() as $client_name => $client_details ) {
		$acs_url = $client_details['assertionConsumerService'] ?? '';
		$trusted_providers[] = $client_name . ( $acs_url ? "|{$acs_url}" : '' );
	}

	?>
	<div class="wrap">
		<h1>SAML IDP</h1>
		<p>Configure the SAML Identity Provider.</p>
		<h2>Client Settings</h2>
		<pre>Callback URL / SAML Endpoint: <?php echo esc_html( get_idp_url() ); ?></pre>
		<pre>IDP Entity ID: <?php echo esc_html( get_idp_issuer() ); ?></pre>
		<form method="post">
			<h2>Accepted Service Providers</h2>
			<p>Enter one Entity ID per line, with the accepted ACS URL separated by a Pipe.<br>These can be configured via the <code>IDP_TRUSTED_SP_CALLBACK</code> constant or <code>idp_trusted_service_providers</code> filter.</p>
			<textarea name="trusted_sps" rows="10" cols="80" <?php wp_readonly( defined('IDP_TRUSTED_SP_CALLBACK') ); ?>><?php echo esc_textarea( implode( "\n", $trusted_providers ) ); ?></textarea>
			<?php submit_button(); ?>

			<h2>Keys</h2>
			<p>These keys can be generated using <code>openssl req -new -x509 -days 3652 -nodes -out saml.crt -keyout saml.pem</code>.<br>
			See <a href="https://github.com/lightSAML/lightSAML/blob/02eb2bdfc42023465ce1bbb165b5b83168b334c1/doc/signing_and_certificates.md">this</a> for more information.<br>
			These can also be defined via the <code>IDP_CERT_PUB</code> and <code>IDP_CERT_PRIV</code> constants.</p>
			<h3>Public Certificate</h3>
			<textarea name="public_certificate" rows="10" cols="80" <?php wp_readonly( defined( 'IDP_CERT_PUB' ) ); ?>><?php echo esc_textarea( $public_key ); ?></textarea>
			<h3>Private Key</h3>
			<textarea name="private_key" rows="10" cols="80" <?php wp_readonly( defined( 'IDP_CERT_PRIV' ) ); ?>><?php
				if ( $private_key ) {
					echo "-----BEGIN PRIVATE KEY-----\nPrivate Key not shown. To replace enter new key here, to remove empty field.\n-----END PRIVATE KEY-----";
				}
			?></textarea>
			<?php wp_nonce_field( 'idp_save' ); ?>
			<?php submit_button(); ?>
	</div>
	<?php
}
