use std::collections::HashMap;
use std::time::Duration;
use std::fs::File;

use libsecret::{SchemaAttributeType, Schema, SchemaFlags};
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{EcdsaSigningAlgorithm, ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair};
use zbus::zvariant::{DeserializeDict, Type};

const ECDSA_ALGORITHM: EcdsaSigningAlgorithm = ECDSA_P256_SHA256_ASN1_SIGNING;
const RNG: dyn SecureRandom = SystemRandom::new();
const SCHEMA: Schema = {
   let mut attributes = HashMap::new();
    attributes.insert("number", SchemaAttributeType::Integer);
    attributes.insert("string", SchemaAttributeType::String);
    attributes.insert("even", SchemaAttributeType::Boolean);

    let schema = Schema::new("some.app.Id", SchemaFlags::NONE, attributes); 
    schema
};

pub enum Error {
    UnknownError,
    NotSupportedError,
    InvalidStateError,
    NotAllowedError,
    ConstraintError,
}
pub(crate) fn make_credential(client_data_hash: Vec<u8>, rp_entity: RelyingParty, user_entity: User, require_resident_key: bool, require_user_presence: bool, require_user_verification: bool, cred_pub_key_algs: Vec<PublicKeyCredentialParameters>, exclude_credential_descriptor_list: Vec<CredentialDescriptor>, enterprise_attestation_possible: bool, extensions: Option<()>) -> Result<(), Error> {

    // Before performing this operation, all other operations in progress in the authenticator session MUST be aborted by running the authenticatorCancel operation.
    // TODO: 
    
    // When this operation is invoked, the authenticator MUST perform the following procedure:
    // Check if all the supplied parameters are syntactically well-formed and of the correct length. If not, return an error code equivalent to "UnknownError" and terminate the operation.
    if client_data_hash.len() != 32 { return Err(Error::UnknownError); }
    if rp_entity.id.is_empty() || rp_entity.name.is_empty() { return Err(Error::UnknownError); }
    if user_entity.id.is_empty() || user_entity.name.is_empty() { return Err(Error::UnknownError); }

    // Check if at least one of the specified combinations of PublicKeyCredentialType and cryptographic parameters in credTypesAndPubKeyAlgs is supported. If not, return an error code equivalent to "NotSupportedError" and terminate the operation.
    let cred_pub_key_parameters = match cred_pub_key_algs.iter().find(|p| p.cred_type == "public-key" && p.alg == -7) {
        Some(cred_pub_key_parameters) => { cred_pub_key_parameters },
        None => { return Err(Error::NotSupportedError )},
    };

    // For each descriptor of excludeCredentialDescriptorList:
    for cd in exclude_credential_descriptor_list.iter() {

        // If looking up descriptor.id in this authenticator returns non-null,
        // and the returned item's RP ID and type match rpEntity.id and
        // excludeCredentialDescriptorList.type respectively, then collect an
        // authorization gesture confirming user consent for creating a new
        // credential. The authorization gesture MUST include a test of user
        // presence.
        if let Some((found, rp)) = lookup_stored_credentials(cd.id) {
            if rp.id == rp_entity.id && found.cred_type == cd.cred_type {
                let has_consent: bool = ask_disclosure_consent();
                // If the user confirms consent to create a new credential
                if has_consent {
                    // return an error code equivalent to "InvalidStateError" and terminate the operation.
                    return Err(Error::InvalidStateError);
                }
                // does not consent to create a new credential
                else {
                    // return an error code equivalent to "NotAllowedError" and terminate the operation.
                    return Err(Error::NotAllowedError);
                }
            // Note: The purpose of this authorization gesture is not to proceed with creating a credential, but for privacy reasons to authorize disclosure of the fact that descriptor.id is bound to this authenticator. If the user consents, the client and Relying Party can detect this and guide the user to use a different authenticator. If the user does not consent, the authenticator does not reveal that descriptor.id is bound to it, and responds as if the user simply declined consent to create a credential.
            }
        }
    }

    // If requireResidentKey is true and the authenticator cannot store a client-side discoverable public key credential source, return an error code equivalent to "ConstraintError" and terminate the operation.
    const can_create_discoverable_credential: bool = true;
    if require_resident_key && !can_create_discoverable_credential {
        return Err(Error::ConstraintError);
    }

    // If requireUserVerification is true and the authenticator cannot perform user verification, return an error code equivalent to "ConstraintError" and terminate the operation.
    if require_user_verification && !is_user_verification_available() {
        return Err(Error::ConstraintError);
    }
    // Collect an authorization gesture confirming user consent for creating a
    // new credential. The prompt for the authorization gesture is shown by the
    // authenticator if it has its own output capability, or by the user agent
    // otherwise. The prompt SHOULD display rpEntity.id, rpEntity.name,
    // userEntity.name and userEntity.displayName, if possible.
    // If requireUserVerification is true, the authorization gesture MUST include user verification.

    // If requireUserPresence is true, the authorization gesture MUST include a test of user presence.
    if let Err(_) = collect_authorization_gesture(require_user_verification, require_user_presence) {
        // If the user does not consent or if user verification fails, return an error code equivalent to "NotAllowedError" and terminate the operation.
        return Err(Error::NotAllowedError);
    }

    // Once the authorization gesture has been completed and user consent has been obtained, generate a new credential object:
    // Let (publicKey, privateKey) be a new pair of cryptographic keys using the combination of PublicKeyCredentialType and cryptographic parameters represented by the first item in credTypesAndPubKeyAlgs that is supported by this authenticator.
    let key_pair = create_key_pair(cred_pub_key_parameters.alg)?;
        // Let userHandle be userEntity.id.
    let user_handle = user_entity.id;
        // Let credentialSource be a new public key credential source with the fields:
    let credential_source = CredentialSource {
        // type
            // public-key.
        cred_type: "public-key",
        // privateKey
            // privateKey
        private_key: key_pair.private_key,
        public_key: key_pair.public_key,
        // rpId
            // rpEntity.id
        rpId: rp_entity.id,
        // userHandle
            // userHandle
        user_handle,
        // otherUI
            // Any other information the authenticator chooses to include.
        other_ui: None,
    };

    // If requireResidentKey is true or the authenticator chooses to create a client-side discoverable public key credential source:
    let credential_id: Vec<u8> = if require_resident_key {
        // Let credentialId be a new credential id.
        let credential_id = ring::rand::generate(&RNG)?;

        // Set credentialSource.id to credentialId.
        let credential_source.id = credential_id;

        // Let credentials be this authenticator’s credentials map.
        // Set credentials[(rpEntity.id, userHandle)] to credentialSource.
        let credential_id = set_discoverable_credential(rp_entity.id, user_handle, credential_source)?;
        credential_id
    }
    // Otherwise:
    else {
        // Let credentialId be the result of serializing and encrypting credentialSource so that only this authenticator can decrypt it.
        let  credential_id = make_credential_id(credential_source.private_key)?;
    }?;

    // If any error occurred while creating the new credential object, return an error code equivalent to "UnknownError" and terminate the operation.

    // Let processedExtensions be the result of authenticator extension processing for each supported extension identifier → authenticator extension input in extensions.
    let processed_extensions = if let Some(extensions) = extensions {
        let processed_extensions = process_authenticator_extensions(extensions)?;
    };

    // If the authenticator:

    let signature_counter = match authenticator.counter_type() {
        // is a U2F device
            // let the signature counter value for the new credential be zero. (U2F devices may support signature counters but do not return a counter when making a credential. See [FIDO-U2F-Message-Formats].)
        WebAuthnDeviceCounterType::U2F => 0,
        // supports a global signature counter
            // Use the global signature counter's actual value when generating authenticator data.
        WebAuthnDeviceCounterType::Global => authenticator.sign_count,
        // supports a per credential signature counter

            // allocate the counter, associate it with the new credential, and initialize the counter value as zero.
        WebAuthnDeviceCounterType::PerCredential => 0,
        // does not support a signature counter

            // let the signature counter value for the new credential be constant at zero.
        WebAuthnDeviceCounterType::Unsupported => 0,
    };


    // Let attestedCredentialData be the attested credential data byte array including the credentialId and publicKey.
    /*
    let attested_credential_data = AttestedCredentialData {
        credential_id,
        credential_public_key: key_pair.public_key,
    };
    */
    let aaguid = None;
    let mut attested_credential_data: Vec<u8> = Vec::new();
    attested_credential_data.push(aaguid.to_bytes());
    attested_credential_data.append((credential_id.len() as u16).to_be_bytes().to_vec().as_mut());
    attested_credential_data.append(credential_id.clone().as_mut());
    attested_credential_data.append(key_pair.public_key.to_bytes());

    // Let authenticatorData be the byte array specified in § 6.1 Authenticator Data, including attestedCredentialData as the attestedCredentialData and processedExtensions, if any, as the extensions.
    let mut authenticator_data: Vec<u8> = Vec::new();
    authenticator_data.append(sha_256_hash(credential_source.rp_id.hash));
    authenticator_data.append(flags);
    authenticator_data.append(signature_counter);
    authenticator_data.append(attested_credential_data.as_mut());
    authenticator_data.append(processed_extensions.to_bytes());

    // Create an attestation object for the new credential using the procedure specified in § 6.5.4 Generating an Attestation Object, using an authenticator-chosen attestation statement format, authenticatorData, and hash, as well as taking into account the value of enterpriseAttestationPossible. For more details on attestation, see § 6.5 Attestation.
    let attestation_format = AttestationStatementFormat::Packed;
    let attestation_object = create_attestation_object(attestation_format, authenticator_data, client_data_hash)?;

    // On successful completion of this operation, the authenticator returns the attestation object to the client.
    Ok(attestation_object)


    /*
    The hash of the serialized client data, provided by the client.
rpEntity

    The Relying Party's PublicKeyCredentialRpEntity.
userEntity

    The user account’s PublicKeyCredentialUserEntity, containing the user handle given by the Relying Party.
requireResidentKey

    The effective resident key requirement for credential creation, a Boolean value determined by the client.
requireUserPresence

    The constant Boolean value true. It is included here as a pseudo-parameter to simplify applying this abstract authenticator model to implementations that may wish to make a test of user presence optional although WebAuthn does not.
requireUserVerification

    The effective user verification requirement for credential creation, a Boolean value determined by the client.
credTypesAndPubKeyAlgs

    A sequence of pairs of PublicKeyCredentialType and public key algorithms (COSEAlgorithmIdentifier) requested by the Relying Party. This sequence is ordered from most preferred to least preferred. The authenticator makes a best-effort to create the most preferred credential that it can.
excludeCredentialDescriptorList

    An OPTIONAL list of PublicKeyCredentialDescriptor objects provided by the Relying Party with the intention that, if any of these are known to the authenticator, it SHOULD NOT create a new credential. excludeCredentialDescriptorList contains a list of known credentials.
enterpriseAttestationPossible

    A Boolean value that indicates that individually-identifying attestation MAY be returned by the authenticator.
extensions 
    A CBOR map from extension identifiers to their authenticator extension inputs, created by the client based on the extensions requested by the Relying Party, if any.
*/
}

async fn create_key_pair(alg: i64) -> Result<ring::pkcs8::Document, ring::error::Unspecified> {
    // TODO: `alg` is just COSE parameters: do we want COSE to leak here , or should we define our own?
    let key_pair = match alg {
        -7 => EcdsaKeyPair::generate_pkcs8(&ECDSA_ALGORITHM, &RNG)?,
        _ => todo!("Unknown signature algorithm given pair generated"),
    };

    let service = oo7::dbus::Service::new(oo7::dbus::Algorithm::Encrypted).await?;
    let collection = service.with_label("WEBAUTHN").await?.unwrap();
    collection.create_item(
        "Item Label",
        HashMap::from([(
            "cred_id", id,
        )]),
        key_pair,
        true,
        "application/octet-stream"
    ).await?;
}

fn lookup_stored_credentials(id: Vec<u8>) -> Option<(CredentialDescriptor, RelyingParty)> {
    todo!();
}

fn ask_disclosure_consent() -> bool {
    todo!();
}

fn is_user_verification_available() -> bool {
    todo!();
}

fn collect_authorization_gesture(require_user_presence: bool, require_user_verification: bool) -> Result<> {
    todo!();
}
#[derive(DeserializeDict, Type)]
pub(crate) struct RelyingParty {
    name: String,
    id: String,
}

#[derive(DeserializeDict, Type)]
/// https://www.w3.org/TR/webauthn-3/#dictionary-user-credential-params
pub(crate) struct User {
    id: Vec<u8>,
    name: String,
    display_name: String,
}

struct Assertion {}

#[derive(DeserializeDict, Type)]
#[zvariant(signature = "dict")]
pub(crate) struct ClientData {
    client_data_type: String,
    challenge: String,
    origin: String,
    cross_origin: bool,
    token_binding: Option<TokenBinding>,
}

#[derive(DeserializeDict, Type)]
#[zvariant(signature = "dict")]
pub(crate) struct TokenBinding {
    status: String,
    id: Option<String>,
}

#[derive(DeserializeDict, Type)]
#[zvariant(signature = "dict")]
pub(crate) struct AssertionOptions {
    user_verification: Option<bool>, //
    user_presence: Option<bool>,
}

#[derive(DeserializeDict, Type)]
#[zvariant(signature = "dict")]
pub(crate) struct MakeCredentialOptions {
    timeout: Duration,
    excluded_credentials: Vec<CredentialDescriptor>,
    authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    attestation: Option<String>, // https://www.w3.org/TR/webauthn-3/#enum-attestation-convey
                                 // extensions: Option<HashMap<String, Box<dyn Any>>>, don't support extensions for no
}

pub(crate) struct CredentialList(Vec<CredentialDescriptor>);

#[derive(DeserializeDict, Type)]
#[zvariant(signature = "dict")]
/// https://www.w3.org/TR/webauthn-3/#dictionary-credential-descriptor
pub(crate) struct CredentialDescriptor {
    /// Type of the public key credential the caller is referring to.
    ///
    /// The value SHOULD be a member of PublicKeyCredentialType but client
    /// platforms MUST ignore any PublicKeyCredentialDescriptor with an unknown
    /// type.
    cred_type: String,
    /// Credential ID of the public key credential the caller is referring to.
    id: Vec<u8>,
    transports: Vec<String>,
}

#[derive(DeserializeDict, Type)]
#[zvariant(signature = "dict")]
/// https://www.w3.org/TR/webauthn-3/#dictionary-authenticatorSelection
pub(crate) struct AuthenticatorSelectionCriteria {
    /// https://www.w3.org/TR/webauthn-3/#enum-attachment
    authenticator_attachment: Option<String>,

    /// https://www.w3.org/TR/webauthn-3/#enum-residentKeyRequirement
    resident_key: Option<String>,

    // Implied by resident_key == "required",
    // https://www.w3.org/TR/webauthn-3/#enum-residentKeyRequirement
    // require_resident_key: Option<bool>,
    /// https://www.w3.org/TR/webauthn-3/#enumdef-userverificationrequirement
    user_verification: Option<String>,
}

#[derive(DeserializeDict, Type)]
#[zvariant(signature = "dict")]
/// https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialparameters
pub(crate) struct PublicKeyCredentialParameters {
    cred_type: String,
    alg: i64,
}
