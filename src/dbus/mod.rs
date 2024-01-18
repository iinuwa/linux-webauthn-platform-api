use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use openssl::pkey::Public;
use ring::digest::{digest, SHA256};
use serde::Deserializer;
use serde_json::json;
use zbus::zvariant::{DeserializeDict, SerializeDict};
use zbus::{dbus_interface, fdo, Connection, ConnectionBuilder, Result, zvariant::Type};

use crate::webauthn::{
    self, MakeCredentialOptions, PublicKeyCredentialParameters, RelyingParty, User,
};

pub(crate) async fn start_service(
    service_name: &str,
    path: &str,
    seed_key: Vec<u8>,
) -> Result<Connection> {
    ConnectionBuilder::session()?
        .name(service_name)?
        .serve_at(path, CredentialManager { seed_key })?
        .build()
        .await
}
struct CredentialManager {
    seed_key: Vec<u8>,
}

#[dbus_interface(name = "xyz.iinuwa.credentials.CredentialManager1")]
impl CredentialManager {
    async fn create_credential(
        &self,
        request: CreateCredentialRequest,
    ) -> fdo::Result<CreateCredentialResponse> {

        let response = match request {
            CreateCredentialRequest { password: Some(password_request), .. } => {
                let password_response = create_password(password_request).await?;
                Ok(password_response.into())
            },
            CreateCredentialRequest { public_key: Some(passkey_request), .. } => {

                let origin = "xyz.iinuwa.credentials.CredentialManager:local";
                let passkey_response = create_passkey(origin, passkey_request).await?;
                Ok(passkey_response.into())
            }
            _ => Err(fdo::Error::Failed("Unknown credential request type".to_string())),
        };
        response
    }

    async fn get_credential(&self, request: GetCredentialRequest) -> fdo::Result<GetCredentialResponse> {
        for option in request.options {
            if option.password.is_some() {
                if let Some((id, password)) = super::webauthn::store::lookup_password_credentials(&request.origin).await {
                    return Ok(PasswordCredential { id, password }.into())
                }
            }
        }
        Err(fdo::Error::Failed("User cancelled or password not found".to_string()))
    }

    #[dbus_interface(property)]
    async fn is_user_verifying_platform_authenticator_enabled(&self) -> bool {
        true
    }
}

async fn create_password(request: CreatePasswordCredentialRequest) -> fdo::Result<CreatePasswordCredentialResponse> {
    super::webauthn::store::store_password(&request.origin, &request.id, &request.password).await
        .map(|_| CreatePasswordCredentialResponse{})
        .map_err(|_| fdo::Error::Failed("Failed to store password".to_string()))
}

async fn create_passkey(origin: &str, request: CreatePublicKeyCredentialRequest) -> fdo::Result<CreatePublicKeyCredentialResponse> {
    let request_value = serde_json::from_str::<serde_json::Value>(&request.request_json)
        .map_err(|_| fdo::Error::InvalidArgs("Invalid request JSON".to_string()))?;
    let json = request_value.as_object()
        .ok_or_else(|| fdo::Error::InvalidArgs("Invalid request JSON".to_string()))?;
    let challenge = json.get("challenge")
        .and_then(|c| c.as_str())
        .ok_or_else(|| fdo::Error::InvalidArgs("JSON missing `challenge` field".to_string()))?
        .to_owned();
    let rp = json.get("rp")
        .and_then(|rp| serde_json::from_value::<RelyingParty>(rp.clone()).ok())
        .ok_or_else(|| fdo::Error::InvalidArgs("JSON missing `rp` field".to_string()))?;
    let user = json.get("user")
        .and_then(|rp| serde_json::from_value::<User>(rp.clone()).ok())
        .ok_or_else(|| fdo::Error::InvalidArgs("JSON missing `user` field".to_string()))?;
    let options = serde_json::from_value::<MakeCredentialOptions>(request_value.clone())
        .map_err(|_| fdo::Error::InvalidArgs("Invalid request JSON".to_string()))?;
    let (require_resident_key, require_user_verification) =
        if let Some(authenticator_selection) = options.authenticator_selection {
            let is_authenticator_storage_capable = true;
            let require_resident_key = authenticator_selection.resident_key.map_or_else(
                || false,
                |r| r == "required" || (r == "preferred" && is_authenticator_storage_capable),
            ); // fallback to authenticator_selection.require_resident_key == true for WebAuthn Level 1?

            let authenticator_can_verify_users = true;
            let require_user_verification =
                authenticator_selection.user_verification.map_or_else(
                    || false,
                    |r| r == "required" || (r == "preferred" && authenticator_can_verify_users),
                );

            (require_resident_key, require_user_verification)
        } else {
            (false, false)
        };
    let require_user_presence = true;
    let enterprise_attestation_possible = false;
    let extensions = None;
    let credential_parameters = request_value.clone().get("pubKeyCredParams")
        .and_then(|c| serde_json::from_value::<Vec<PublicKeyCredentialParameters>>(c.clone()).ok())
        .ok_or_else(|| fdo::Error::InvalidArgs("Request JSON missing or invalid `pubKeyCredParams` key".to_string()))?;
    let excluded_credentials = options.excluded_credentials.unwrap_or(Vec::new());

    let client_data_hash = match request.client_data_hash {
        Some(hash) => hash,
        None => {
            format!("{{\"type\":\"webauthn.create\",\"challenge\":\"{challenge}\",\"origin\":\"{origin}\",\"crossOrigin\":false}}").as_bytes().to_owned()
        }
    };
    let response = super::webauthn::make_credential(
        client_data_hash,
        rp,
        user,
        require_resident_key,
        require_user_presence,
        require_user_verification,
        credential_parameters,
        excluded_credentials,
        enterprise_attestation_possible,
        extensions
    ).await
    .map_err(|_| fdo::Error::Failed("Failed to create public key credential".to_string()))?;
    Ok(CreatePublicKeyCredentialResponse { credential_creation_data_json: response.to_json() })
}

#[derive(DeserializeDict, Type)]
#[zvariant(signature = "dict")]
pub struct CreateCredentialRequest {
    #[zvariant(rename = "type")]
    r#type: String,
    password: Option<CreatePasswordCredentialRequest>,
    public_key: Option<CreatePublicKeyCredentialRequest>,
}

#[derive(DeserializeDict, Type)]
#[zvariant(signature = "dict")]
pub struct CreatePasswordCredentialRequest {
    origin: String,
    id: String,
    password: String,
}

#[derive(DeserializeDict, Type)]
#[zvariant(signature = "dict")]
pub struct CreatePublicKeyCredentialRequest {
    request_json: String,
    client_data_hash: Option<Vec<u8>>,
}

#[derive(SerializeDict, Type)]
#[zvariant(signature = "dict")]
pub struct CreateCredentialResponse {
    #[zvariant(rename = "type")]
    r#type: String,
    password: Option<CreatePasswordCredentialResponse>,
    public_key: Option<CreatePublicKeyCredentialResponse>,
}

#[derive(SerializeDict, Type)]
#[zvariant(signature = "dict")]
pub struct CreatePasswordCredentialResponse {}

impl Into<CreateCredentialResponse> for CreatePasswordCredentialResponse {
    fn into(self) -> CreateCredentialResponse {
        CreateCredentialResponse {
            r#type: "password".to_string(),
            password: Some(self),
            public_key: None,
        }
    }
}

#[derive(SerializeDict, Type)]
#[zvariant(signature = "dict")]
pub struct CreatePublicKeyCredentialResponse {
    credential_creation_data_json: String,
}

impl Into<CreateCredentialResponse> for CreatePublicKeyCredentialResponse {
    fn into(self) -> CreateCredentialResponse {
        CreateCredentialResponse {
            r#type: "public-key".to_string(),
            public_key: Some(self),
            password: None,
        }
    }
}


#[derive(DeserializeDict, Type)]
#[zvariant(signature = "dict")]
pub struct GetCredentialRequest {
    origin: String,
    options: Vec<GetCredentialOption>,
}

#[derive(DeserializeDict, Type)]
#[zvariant(signature = "dict")]
pub struct GetCredentialOption {
    #[zvariant(rename = "type")]
    r#type: String,
    password: Option<GetPasswordRequestOption>,
    // public_key: Option<GetPublicKeyRequestOption>,
    
}

#[derive(DeserializeDict, Type)]
#[zvariant(signature = "dict")]
pub struct GetPasswordRequestOption {}

#[derive(SerializeDict, Type)]
#[zvariant(signature = "dict")]
pub struct GetCredentialResponse {
    #[zvariant(rename = "type")]
    r#type: String,
    password: PasswordCredential,
    // public_key: PublicKeyCredential,
}

#[derive(SerializeDict, Type)]
#[zvariant(signature = "dict")]
pub struct PasswordCredential {
    id: String,
    password: String,
}

impl Into<GetCredentialResponse> for PasswordCredential {
    fn into(self) -> GetCredentialResponse {
        GetCredentialResponse {
            r#type: "password".to_string(),
            password: self,
        }
    }
}