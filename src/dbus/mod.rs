use ring::digest::{digest, SHA256};
use zbus::{dbus_interface, fdo, Connection, ConnectionBuilder, Result};

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
    async fn make_credential(
        &self,
        rp: RelyingParty,
        user: User,
        credential_parameters: Vec<PublicKeyCredentialParameters>,
        client_data: String,
        options: MakeCredentialOptions,
    ) -> fdo::Result<Vec<u8>> {
        let (require_resident_key, require_user_verification) =
            if let Some(authenticator_selection) = options.authenticator_selection {
                let is_authenticator_storage_capable = true;
                let require_resident_key = authenticator_selection.require_resident_key.map_or_else(
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
        let client_data_hash = digest(&SHA256, client_data.as_bytes()).as_ref().to_vec();
        let extensions = None;
        let excluded_credentials = options.excluded_credentials.unwrap_or(Vec::new());
        webauthn::make_credential(
            client_data_hash,
            rp,
            user,
            require_resident_key,
            require_user_presence,
            require_user_verification,
            credential_parameters,
            excluded_credentials,
            enterprise_attestation_possible,
            extensions,
        )
        .await
        .map_err(|e| match e {
            webauthn::Error::NotSupportedError => {
                fdo::Error::NotSupported("Operation not supported".to_string())
            }
            webauthn::Error::UnknownError => fdo::Error::Failed("Unknown error".to_string()),
            webauthn::Error::InvalidStateError => fdo::Error::Failed("Invalid state".to_string()),
            webauthn::Error::NotAllowedError => fdo::Error::AccessDenied("Not allowed".to_string()),
            webauthn::Error::ConstraintError => fdo::Error::Failed("Constraint error".to_string()),
        })
    }

    async fn say_hello(&self, name: &str) -> String {
        format!("Hello {}!", name)
    }

    #[dbus_interface(property)]
    async fn is_user_verifying_platform_authenticator_enabled(&self) -> bool {
        true
    }
    /*
    pub async fn get_assertion(&self, window_handle: u8, rp_id: &str, client_data: ClientData, assertion_options: Option<AssertionOptions>) -> Result<Option<Assertion>, Box<dyn Error>> {
        todo!();
    }
    */
}
