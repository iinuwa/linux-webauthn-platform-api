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
}
