pub(crate) mod store;
// mod cbor;

use std::time::Duration;


use openssl::{rsa::Rsa, pkey::PKey};
use ring::{digest::digest, pkcs8::Document, rand::{SystemRandom}, signature::{EcdsaSigningAlgorithm, ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair, Ed25519KeyPair, RsaKeyPair, RSA_PKCS1_SHA256}, digest};
use zbus::zvariant::{DeserializeDict, Type};
use store::{lookup_stored_credentials, store_credential};

static P256: &EcdsaSigningAlgorithm = &ECDSA_P256_SHA256_ASN1_SIGNING;
// static RNG: &Box<dyn SecureRandom> = &Box::new(SystemRandom::new());


#[derive(Debug)]
pub enum Error {
    UnknownError,
    NotSupportedError,
    InvalidStateError,
    NotAllowedError,
    ConstraintError,
}

pub(crate) async fn make_credential(client_data_hash: Vec<u8>, rp_entity: RelyingParty, user_entity: User, require_resident_key: bool, require_user_presence: bool, require_user_verification: bool, cred_pub_key_algs: Vec<PublicKeyCredentialParameters>, exclude_credential_descriptor_list: Vec<CredentialDescriptor>, enterprise_attestation_possible: bool, extensions: Option<()>) -> Result<Vec<u8>, Error> {

    // Before performing this operation, all other operations in progress in the authenticator session MUST be aborted by running the authenticatorCancel operation.
    // TODO: 
    let supported_algorithms: [i64; 2] = [
        -8, // Ed25519
        -7, // P-256
        // -257 // RSA-PKCS1-SHA256, TODO: key generation not supported right now
    ];
    
    // When this operation is invoked, the authenticator MUST perform the following procedure:
    // Check if all the supplied parameters are syntactically well-formed and of the correct length. If not, return an error code equivalent to "UnknownError" and terminate the operation.
    if client_data_hash.len() != 32 { return Err(Error::UnknownError); }
    if rp_entity.id.is_empty() || rp_entity.name.is_empty() { return Err(Error::UnknownError); }
    if user_entity.id.is_empty() || user_entity.name.is_empty() { return Err(Error::UnknownError); }

    // Check if at least one of the specified combinations of PublicKeyCredentialType and cryptographic parameters in credTypesAndPubKeyAlgs is supported. If not, return an error code equivalent to "NotSupportedError" and terminate the operation.
    let cred_pub_key_parameters = match cred_pub_key_algs.iter().find(|p| p.cred_type == "public-key" && supported_algorithms.contains(&p.alg)) {
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
        if let Some((found, rp)) = lookup_stored_credentials(cd.id.clone()) {
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

    // If requireResidentKey is true or the authenticator chooses to create a client-side discoverable public key credential source:
        // Let credentialId be a new credential id.
    // Note: We'll always create a discoverable credential, so generate a random credential ID.
    let credential_id: Vec<u8> = ring::rand::generate::<[u8; 16]>(&SystemRandom::new())
        .map_err(|_e| Error::UnknownError)?
        .expose()
        .into();

    // Let credentialSource be a new public key credential source with the fields:
    let credential_source = CredentialSource {
        // type
            // public-key.
        cred_type: PublicKeyCredentialType::PublicKey,
        // Set credentialSource.id to credentialId.
        id: credential_id.to_vec(),
        // privateKey
            // privateKey
        private_key: key_pair.clone(),
        // rpId
            // rpEntity.id
        rp_id: rp_entity.id,
        // userHandle
            // userHandle
        user_handle: Some(user_handle),
        // otherUI
            // Any other information the authenticator chooses to include.
        other_ui: None,
    };

    store_credential(credential_source.clone()).await?;

    // If any error occurred while creating the new credential object, return an error code equivalent to "UnknownError" and terminate the operation.

    // Let processedExtensions be the result of authenticator extension processing for each supported extension identifier → authenticator extension input in extensions.
    let _processed_extensions = if let Some(extensions) = extensions {
        process_authenticator_extensions(extensions).expect("Extension processing not yet supported");
    };

    // If the authenticator:

    let counter_type = WebAuthnDeviceCounterType::PerCredential;
    let signature_counter: u32 = match counter_type {
        // is a U2F device
            // let the signature counter value for the new credential be zero. (U2F devices may support signature counters but do not return a counter when making a credential. See [FIDO-U2F-Message-Formats].)
        WebAuthnDeviceCounterType::U2F => 0,
        // supports a global signature counter
            // Use the global signature counter's actual value when generating authenticator data.
        WebAuthnDeviceCounterType::Global => todo!(), // authenticator.sign_count
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
    let mut aaguid = vec![0 as u8; 16];
    let mut attested_credential_data: Vec<u8> = Vec::new();
    attested_credential_data.append(&mut aaguid);
    let cred_length: u16 = TryInto::<u16>::try_into(credential_id.len()).unwrap();
    let cred_length_bytes: Vec<u8> = cred_length.to_be_bytes().to_vec();
    attested_credential_data.extend(&cred_length_bytes);
    attested_credential_data.extend(&credential_id.clone());
    let public_key = cose_encode_public_key(&cred_pub_key_parameters, &key_pair)?;
    attested_credential_data.extend(&public_key);

    // Let authenticatorData be the byte array specified in § 6.1 Authenticator Data, including attestedCredentialData as the attestedCredentialData and processedExtensions, if any, as the extensions.
    let mut authenticator_data: Vec<u8> = Vec::new();
    let rp_id_hash = digest(&digest::SHA256, (&credential_source).rp_id.as_bytes());
    authenticator_data.extend(rp_id_hash.as_ref());
    authenticator_data.push(0b0100_0101); // UP, UV, AT
    authenticator_data.extend(signature_counter.to_be_bytes());
    authenticator_data.extend(&attested_credential_data);
    // TODO: authenticator_data.append(processed_extensions.to_bytes());

    // Create an attestation object for the new credential using the procedure specified in § 6.5.4 Generating an Attestation Object, using an authenticator-chosen attestation statement format, authenticatorData, and hash, as well as taking into account the value of enterpriseAttestationPossible. For more details on attestation, see § 6.5 Attestation.
    // TODO: attestation not supported for now
    let signed_data: Vec<u8> = [authenticator_data.as_slice(), client_data_hash.as_slice()].concat();
    let rng = &SystemRandom::new();
    let signature = match cred_pub_key_parameters.alg {
        -7 => {
            let ecdsa = EcdsaKeyPair::from_pkcs8(&P256, &key_pair.as_ref()).unwrap();
                ecdsa.sign(rng, &signed_data).unwrap().as_ref().to_vec()
        },
        -8 => {
            let eddsa = Ed25519KeyPair::from_pkcs8(&key_pair.as_ref()).unwrap();
            eddsa.sign(&signed_data).as_ref().to_vec()
        }
        -257 => {
            let rsa = RsaKeyPair::from_pkcs8(&key_pair.as_ref()).unwrap();
            let mut signature = vec![0; rsa.public_modulus_len()];
            rsa.sign(&RSA_PKCS1_SHA256, rng, &signed_data, &mut signature);
            signature
        },
        _ => {
            return Err(Error::NotSupportedError)
        }
    };
    let attestation_object = create_attestation_object(cred_pub_key_parameters.alg, &authenticator_data, signature, enterprise_attestation_possible)?;

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

fn create_key_pair(alg: i64) -> Result<Vec<u8>, Error> {
    let rng = &SystemRandom::new();
    let key_pair = match alg {
        -7 => EcdsaKeyPair::generate_pkcs8(P256, rng).map(|d| d.as_ref().to_vec()),
        -8 => Ed25519KeyPair::generate_pkcs8(rng).map(|d| d.as_ref().to_vec()),
        -257 => {
            let rsa_key = Rsa::generate(2048).unwrap();
            let private_key = PKey::from_rsa(rsa_key).unwrap();
            let pkcs8 = private_key.private_key_to_pkcs8().unwrap();
            Ok(pkcs8.to_vec())
        },
        _ => todo!("Unknown signature algorithm given pair generated"),
        

    };
    key_pair.map_err(|_e| Error::UnknownError)
}

fn ask_disclosure_consent() -> bool {
    todo!();
}

fn is_user_verification_available() -> bool {
    todo!();
}

fn collect_authorization_gesture(_require_user_presence: bool, _require_user_verification: bool) -> Result<(), Error> {
    todo!();
}

fn process_authenticator_extensions(_extensions: ()) -> Result<(), Error> {
    todo!();
}

fn create_attestation_object(algorithm: i64, authenticator_data: &[u8], signature: Vec<u8>, enterprise_attestation_possible: bool) -> Result<Vec<u8>, Error> {
        let mut attestation_object = Vec::new();
        attestation_object.push(0b101_00011); // map with 3 elements
        attestation_object.push(0b011_01000); // <text, length 8>
        attestation_object.extend(b"authData");
        attestation_object.push(0b010_01000); // <bytes, length 8>
        attestation_object.push(0b011_00011); // <text, length 3>
        attestation_object.extend(b"fmt");
        attestation_object.push(0b011_00110); // <text, length 6>
        attestation_object.extend(b"packed");
        attestation_object.push(0b011_00111); // <text, length 7>
        attestation_object.extend(b"attStmt");
        attestation_object.push(0b101_00010); // map, length 2
        attestation_object.push(0b011_00100); // text, length 4
        attestation_object.extend(b"authData");
        attestation_object.push (0b011_00000); // bytes, length authenticator_data.len() // todo:
        attestation_object.extend(authenticator_data);
        attestation_object.push(0b011_00011); // text, length 3
        attestation_object.extend(b"alg");
        attestation_object.push(((algorithm + 1) as u8) | 0b001000); // TODO:
        attestation_object.push(0b011_00011); // text, length 3
        attestation_object.extend(b"sig");
        attestation_object.extend([0b010_11000, 0b0000_0000, 0b0000_0000]); // TODO:
        attestation_object.extend(signature);
        Ok(attestation_object)
}

fn cose_encode_public_key(parameters: &PublicKeyCredentialParameters, pkcs8_key: &[u8]) -> Result<Vec<u8>, Error> {
    match parameters.alg {
        -7 => {
            let key_pair = EcdsaKeyPair::from_pkcs8(&P256, pkcs8_key.as_ref()).map_err(|_| Error::UnknownError)?;
            let public_key = key_pair.public_key().as_ref();
            // ring outputs public keys with uncompressed 32-byte x and y coordinates
            if public_key.len() != 65 || public_key[0] != 0x04 {
                return Err(Error::UnknownError)
            }
            let (x, y) = public_key[1..].split_at(32);
            let mut cose_key: Vec<u8> = Vec::new();
            cose_key.push(0b101_00101); // map with 5 items
            cose_key.extend([0b000_00001, 0b000_00010]); // kty (1): EC2 (2)
            cose_key.extend([0b000_00011, 0b001_00110]); // alg (3): ECDSA-SHA256 (-7)
            cose_key.extend([0b001_00000, 0b000_00001]); // crv (-1): P256 (1)
            cose_key.extend([0b001_00001, 0b010_11000, 0b0010_0000]); // x (-2): <32-byte string>
            cose_key.extend(x);
            cose_key.extend([0b001_00010, 0b010_11000, 0b0010_0000]); // y (-3): <32-byte string>
            cose_key.extend(y);
            Ok(cose_key)
        },
        -8 => {
            // TODO: Check this
            let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_key.as_ref()).map_err(|_| Error::UnknownError)?;
            let public_key = key_pair.public_key().as_ref();
            let mut cose_key: Vec<u8> = Vec::new();
            cose_key.push(0b101_00100); // map with 4 items
            cose_key.extend([0b000_00001, 0b000_00001]); // kty (1): OKP (1)
            cose_key.extend([0b000_00011, 0b001_00110]); // alg (3): EdDSA (-8)
            cose_key.extend([0b001_00000, 0b000_00110]); // crv (-1): ED25519 (6)
            cose_key.extend([0b001_00001, 0b010_11000, 0b0010_0000]); // x (-2): <32-byte string>
            cose_key.extend(public_key);
            Ok(cose_key)
        },
        -257 => {
            let key_pair = RsaKeyPair::from_pkcs8(pkcs8_key.as_ref()).map_err(|_| Error::UnknownError)?;
            let public_key = key_pair.public_key().as_ref();
            // TODO: This is ASN.1 with DER encoding. We could parse this to extract
            // the modulus and exponent properly, but the key length will
            // probably not change, so we're winging it
            // https://stackoverflow.com/a/12750816/11931787
            let n = &public_key[9..(9+256)];
            let e = &public_key[public_key.len()-3..];
            debug_assert_eq!(n.len(), key_pair.public_modulus_len());
            let mut cose_key: Vec<u8> = Vec::new();
            cose_key.push(0b101_00100); // map with 4 items
            cose_key.extend([0b000_00001, 0b000_00010]); // kty (1): RSA (3)
            cose_key.extend([0b000_00011, 0b001_00110]); // alg (3): RSASSA-PKCS1-v1_5 using SHA-256 (-257)
            cose_key.extend([0b001_00000, 0b010_11001, 0b0000_0001, 0b0000_0000]); // n (-1): <256-byte string>
            cose_key.extend(n);
            cose_key.extend([0b001_00001, 0b010_00011]); // e (-2): <3-byte string>
            cose_key.extend(e);
            Ok(cose_key)
        },
        _ => todo!(),
    }
}

#[test]
fn test_rsa_key_pair() {
    let f = std::fs::read("rsa-2048-private-key.pk8").unwrap();
    let key_pair = RsaKeyPair::from_pkcs8(&f).unwrap();
    // println!(key_pair.public_key().as_ref().iter().map(|b| format!("{b:2x}").to_string()).collect::<Vec<String>>().join(""));
    for b in key_pair.public_key().as_ref().to_vec() {
        print!("{b:02x}");
    }
    println!();
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

#[derive(Clone)]
struct CredentialSource {
    cred_type: PublicKeyCredentialType,

    /// A probabilistically-unique byte sequence identifying a public key
    /// credential source and its authentication assertions.
    id: Vec<u8>,

    /// The credential private key
    private_key: Vec<u8>,

    /// The Relying Party Identifier, for the Relying Party this public key
    /// credential source is scoped to.
    rp_id: String,

    /// The user handle is specified by a Relying Party, as the value of
    /// `user.id`, and used to map a specific public key credential to a specific
    /// user account with the Relying Party. Authenticators in turn map RP IDs
    /// and user handle pairs to public key credential sources.
    /// 
    /// A user handle is an opaque byte sequence with a maximum size of 64
    /// bytes, and is not meant to be displayed to the user.
    user_handle: Option<Vec<u8>>,

    // Any other information the authenticator chooses to include.
    /// other information used by the authenticator to inform its UI. For
    /// example, this might include the user’s displayName. otherUI is a
    /// mutable item and SHOULD NOT be bound to the public key credential
    /// source in a way that prevents otherUI from being updated.
    other_ui: Option<String>,
}

#[derive(Clone)]
enum PublicKeyCredentialType {
    PublicKey,
}
enum WebAuthnDeviceCounterType {
    /// Authenticator is a U2F device (and therefore does not support a counter
    /// on registration and may or may not support a counter on assertion).
    U2F,
    /// Authenticator supports a global signature counter.
    Global,
    /// Authenticator supports a per credential signature counter.
    PerCredential,
    /// Authenticator does not support a signature counter.
    Unsupported,
}

enum AttestationStatementFormat {
    None,
    Packed,
}