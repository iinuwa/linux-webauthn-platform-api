use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use zbus::zvariant::{DeserializeDict, SerializeDict};
use zbus::{dbus_interface, fdo, zvariant::Type, Connection, ConnectionBuilder, Result};

use crate::store;
use crate::webauthn;

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
        let origin = request
            .origin
            .unwrap_or("xyz.iinuwa.credentials.CredentialManager:local".to_string());
        let response = match (
            request.r#type.as_ref(),
            request.password,
            request.public_key,
        ) {
            ("password", Some(password_request), _) => {
                let password_response = create_password(&origin, password_request).await?;
                Ok(password_response.into())
            }
            ("publicKey", _, Some(passkey_request)) => {
                let passkey_response = create_passkey(&origin, passkey_request).await?;
                Ok(passkey_response.into())
            }
            _ => Err(fdo::Error::Failed(
                "Unknown credential request type".to_string(),
            )),
        };
        response
    }

    async fn get_credential(
        &self,
        request: GetCredentialRequest,
    ) -> fdo::Result<GetCredentialResponse> {
        for option in request.options {
            match (option.r#type.as_ref(), option.password, option.public_key) {
                ("password", Some(_), _) => {
                    if let Some((id, password)) =
                        store::lookup_password_credentials(&request.origin).await
                    {
                        return Ok(PasswordCredential { id, password }.into());
                    }
                }
                ("publicKey", _, Some(_)) => {
                    todo!("Get credential assertion")
                }
                _ => {
                    return Err(fdo::Error::Failed(
                        "Unknown credential request type".to_string(),
                    ))
                }
            }
        }
        Err(fdo::Error::Failed(
            "User cancelled or password not found".to_string(),
        ))
    }

    #[dbus_interface(property)]
    async fn is_user_verifying_platform_authenticator_enabled(&self) -> bool {
        true
    }
}

async fn create_password(
    origin: &str,
    request: CreatePasswordCredentialRequest,
) -> fdo::Result<CreatePasswordCredentialResponse> {
    /*
    store::store_password(&request.origin, &request.id, &request.password).await
        .map(|_| CreatePasswordCredentialResponse{})
        .map_err(|_| fdo::Error::Failed("Failed to store password".to_string()));
    */
    let contents = format!(
        "id={}&password={}",
        request.id.replace("%", "%25").replace('&', "%26"),
        request.password.replace("%", "%25").replace('&', "%26")
    );
    let display_name = format!("Password for {origin}"); // TODO
    store::store_secret(
        &[origin],
        &display_name,
        &request.id,
        "secret/password",
        None,
        contents.as_bytes(),
    )
    .await
    .map_err(|_| fdo::Error::Failed("".to_string()))?;
    Ok(CreatePasswordCredentialResponse {})
}

async fn create_passkey(
    origin: &str,
    request: CreatePublicKeyCredentialRequest,
) -> fdo::Result<CreatePublicKeyCredentialResponse> {
    let (response, cred_source, user) =
        webauthn::create_credential(origin, &request.request_json, true).map_err(|_| {
            fdo::Error::Failed("Failed to create public key credential".to_string())
        })?;

    let mut contents = String::new();
    contents.push_str("type=public-key"); // TODO: Don't hardcode public-key?
    contents.push_str("&id=");
    URL_SAFE_NO_PAD.encode_string(cred_source.id, &mut contents);
    contents.push_str("&key=");
    URL_SAFE_NO_PAD.encode_string(cred_source.private_key, &mut contents);
    contents.push_str("&rp_id=");
    contents.push_str(&cred_source.rp_id);
    if let Some(user_handle) = &cred_source.user_handle {
        contents.push_str("&user_handle=");
        URL_SAFE_NO_PAD.encode_string(user_handle, &mut contents);
    }

    if let Some(other_ui) = cred_source.other_ui {
        contents.push_str("&other_ui=");
        contents.push_str(&other_ui);
    }
    let content_type = "secret/public-key";
    let display_name = "test"; // TODO
    store::store_secret(
        &[origin],
        display_name,
        &user.display_name,
        content_type,
        None,
        contents.as_bytes(),
    )
    .await
    .map_err(|_| fdo::Error::Failed("Failed to save passkey to storage".to_string()))?;

    Ok(CreatePublicKeyCredentialResponse {
        credential_creation_data_json: response.to_json(),
    })
}

#[derive(DeserializeDict, Type)]
#[zvariant(signature = "dict")]
pub struct CreateCredentialRequest {
    origin: Option<String>,
    #[zvariant(rename = "type")]
    r#type: String,
    password: Option<CreatePasswordCredentialRequest>,
    #[zvariant(rename = "publicKey")]
    public_key: Option<CreatePublicKeyCredentialRequest>,
}

#[derive(DeserializeDict, Type)]
#[zvariant(signature = "dict")]
pub struct CreatePasswordCredentialRequest {
    id: String,
    password: String,
}

#[derive(DeserializeDict, Type)]
#[zvariant(signature = "dict")]
pub struct CreatePublicKeyCredentialRequest {
    request_json: String,
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
            // TODO: Decide on camelCase or kebab-case for cred types
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
    public_key: Option<GetPublicKeyRequestOption>,
}

#[derive(DeserializeDict, Type)]
#[zvariant(signature = "dict")]
pub struct GetPublicKeyRequestOption {
    credential_assert_request_json: String,
}

#[derive(DeserializeDict, Type)]
#[zvariant(signature = "dict")]
pub struct GetPasswordRequestOption {}

#[derive(SerializeDict, Type)]
#[zvariant(signature = "dict")]
pub struct GetCredentialResponse {
    #[zvariant(rename = "type")]
    r#type: String,
    password: Option<PasswordCredential>,
    public_key: Option<PublicKeyCredential>,
}

#[derive(SerializeDict, Type)]
#[zvariant(signature = "dict")]
pub struct PasswordCredential {
    id: String,
    password: String,
}

#[derive(SerializeDict, Type)]
#[zvariant(signature = "dict")]
pub struct PublicKeyCredential {
    assertion_response_json: String,
}

impl Into<GetCredentialResponse> for PasswordCredential {
    fn into(self) -> GetCredentialResponse {
        GetCredentialResponse {
            r#type: "password".to_string(),
            password: Some(self),
            public_key: None,
        }
    }
}

#[cfg(test)]
mod test {
    use serde_json::json;

    use super::{create_passkey, CreatePublicKeyCredentialRequest};
    #[test]
    fn test_json() {
        super::store::initialize();
        let request_json = json!({
            "challenge": "LcBRERr1VHJSTR3vtTG35w",
            "rp": {"name": "Example Org", "id": "example.com"},
            "user": {"id": "MTIzYWJkc2FjZGR3", "name": "user@example.com", "displayName": "User 1"},
            "pubKeyCredParams": [
                {"type": "public-key", "alg": -7},
                {"type": "public-key", "alg": -257},
                {"type": "public-key", "alg": -8}
            ]
        })
        .to_string();
        let request = CreatePublicKeyCredentialRequest { request_json };
        let response = async_std::task::block_on(create_passkey("", request));
        if let Err(e) = &response {
            println!("{e}");
        }
        assert_eq!(response.is_ok(), true);
    }
}
