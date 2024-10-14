<?php
/**
 * This file is the processor for the ?action=idp_confirm endpoint.
 * All requests to this endpoint are a confirmation of the wish for a user to proceed with login.
 * The user will be redirected back to the ServiceProvider with a SAMLResponse containing the user's details.
 */
namespace WPSAMLIDP;
use DateTime;
use \LightSaml\Binding\BindingFactory;
use \LightSaml\Context\Profile\MessageContext;
use \LightSaml\Helper as LightSamlHelper;
use \LightSaml\Model\Assertion\{
	Assertion,
	Attribute,
	AttributeStatement,
	AudienceRestriction,
	AuthnContext,
	AuthnStatement,
	Conditions,
	Issuer,
	NameID,
	Subject,
	SubjectConfirmation,
	SubjectConfirmationData
};
use \LightSaml\Model\Context\SerializationContext;
use \LightSaml\Model\Protocol\{
	Response,
	Status,
	StatusCode
};
use \LightSaml\Model\XmlDSig\SignatureWriter;
use \LightSaml\{
	SamlConstants,
	ClaimTypes
};

$saml = retrieve_saml_request();
if (
	! $saml ||
	! isset( $_REQUEST['_wpnonce'] ) ||
	! isset( $_REQUEST['idp_confirm'] ) ||
	! is_user_logged_in() ||
	! wp_verify_nonce( $_REQUEST['_wpnonce'], 'saml_confirm' )
) {
	wp_die( 'Invalid request', 400 );
}

// User has confirmed, we can proceed with the redirect.
$issuer  = $saml->getMessage()->getIssuer()->getValue();
$acs_url = $saml->getMessage()->getAssertionConsumerServiceURL(); // NOTE: This will be validated by validate_saml_client()

// Validate the SAML client is acceptable.
$saml_client = validate_saml_client( $issuer, $acs_url );
if ( is_wp_error( $saml_client ) && $saml_client->has_errors() ) {
	wp_die( $saml_client->get_error_message(), 500 );
}

// We now start constructing the SAML Response using LightSAML.
$user         = wp_get_current_user();
$user_details = [];
if ( ! $user ) {
	wp_die( 'Invalid request', 400 );
}
if ( ! empty( $saml_client['userInfo'] ) ) {
	$user_details = $saml_client['userInfo'];
	if ( is_callable( $user_details ) ) {
		$user_details = $user_details( $user );
	}
}

// The bare basics.
$user_details['username'] ??= $user->user_login;
$user_details['email']    ??= $user->user_email;

// We now start constructing the SAML Response using LightSAML.
$response = new Response();
$response
	->addAssertion($assertion = new Assertion())
	->setStatus( new Status( new StatusCode( SamlConstants::STATUS_SUCCESS ) ) )
	->setID( LightSamlHelper::generateID() )
	->setIssueInstant( new DateTime() )
	->setDestination( $acs_url )
	->setIssuer( new Issuer( get_idp_issuer() ) )
;

$assertion
	->setId( LightSamlHelper::generateID() )
	->setIssueInstant( new DateTime() )
	->setIssuer( new Issuer( get_idp_issuer() ) )
	->setSubject(
		( new Subject() )
			// The subject is the user's login, in response to a specific SAMLRequest.
			->setNameID( new NameID( $user_details['username'], SamlConstants::NAME_ID_FORMAT_UNSPECIFIED ) )
			->addSubjectConfirmation(
				( new SubjectConfirmation() )
					->setMethod( SamlConstants::CONFIRMATION_METHOD_BEARER )
					->setSubjectConfirmationData(
						( new SubjectConfirmationData() )
							->setInResponseTo( $saml->getMessage()->getID() )
							->setNotOnOrAfter( new DateTime( '+1 MINUTE' ) )
							->setRecipient( $acs_url )
					)
			)
	)
	// Ensure that this can't be replayed in the future.
	->setConditions(
		( new Conditions() )
			->setNotBefore( new DateTime() )
			->setNotOnOrAfter( new DateTime( '+1 MINUTE' ) )
			->addItem( new AudienceRestriction( [
				$saml->getMessage()->getIssuer()->getValue()
			] ) )
	)
	// And claim the user just Auth'd.
	->addItem(
		( new AuthnStatement() )
			->setAuthnInstant( new DateTime( '-1 MINUTE' ) )
			->setSessionIndex( $assertion->getId() )
			->setAuthnContext(
				( new AuthnContext() )->setAuthnContextClassRef( SamlConstants::AUTHN_CONTEXT_PASSWORD_PROTECTED_TRANSPORT )
			)
	)
	// Add the user's email address & name at a minimum.
	->addItem(
		( new AttributeStatement() )
			->addAttribute( new Attribute( ClaimTypes::EMAIL_ADDRESS, $user_details['email'] ) )
	)
	->addItem(
		(new AttributeStatement())
			->addAttribute( new Attribute( ClaimTypes::NAME, $user_details['username'] ) )
	)
;

// Add any additional attributes.
$claim_types = [ 'COMMON_NAME', 'GIVEN_NAME', 'SURNAME', 'UPN', 'ROLE', 'PPID', 'NAME_ID', 'AUTHENTICATION_TIMESTAMP', 'AUTHENTICATION_METHOD' ];
foreach ( $user_details as $key => $value ) {
	if ( in_array( strtoupper( $key ), $claim_types, true ) ) {
		$key = constant( ClaimTypes::class . '::' . strtoupper( $key ) );
	}
	$assertion->addItem(
		( new AttributeStatement() )
			->addAttribute( new Attribute( $key, $value ) )
	);
}

// Sign the response.
$response->setSignature(
	new SignatureWriter( get_idp_keys()->public, get_idp_keys()->private )
);

// Convert to XML
$serializationContext = new SerializationContext();
$response->serialize( $serializationContext->getDocument(), $serializationContext );
$response->setDestination( $acs_url) ;

// Create a new auto-submitting form to send the response via the users browser.
$auto_submitting_post_form = ( new BindingFactory() )->create( SamlConstants::BINDING_SAML2_HTTP_POST );
$messageContext            = new MessageContext();
$messageContext->setMessage( $response );

// Ensure we include the RelayState.
if ( isset( $_REQUEST['RelayState'] ) ) {
	$message = $messageContext->getMessage();
	$message->setRelayState( wp_unslash( $_REQUEST['RelayState'] ) );
	$messageContext->setMessage( $message );
}

// Print the response, which is an anto submitting form to login.
echo $auto_submitting_post_form->send( $messageContext )->getContent();
exit;