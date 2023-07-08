use zbus::{dbus_interface, Connection, ConnectionBuilder, Result};



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
    /*
    async fn make_credential(&self, rp: RelyingParty, user: User, credential_parameters: PublicKeyCredentialParameters, client_data: String, options: MakeCredentialOptions) -> Result<Vec<u8>> {
        todo!();
    }
    */

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
