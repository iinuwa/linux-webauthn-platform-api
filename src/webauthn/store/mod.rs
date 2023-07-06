use std::{collections::HashMap, path::PathBuf};
use std::fs::{File, self};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD, self};

use super::{CredentialSource, CredentialDescriptor, RelyingParty};
static CRED_DIR: PathBuf = "~/.local/share/webauthn/credentials";

pub(crate) fn initialize() {
    fs::create_dir_all(CRED_DIR);
}
pub(super) async fn store_credential(credential_source: CredentialSource) -> Result<(), Error> {
    /*
    let service = oo7::dbus::Service::new(oo7::dbus::Algorithm::Encrypted).await?;
    let collection = service.with_label("WEBAUTHN").await?.unwrap();
    collection.create_item(
        "Item Label",
        HashMap::from([(
            "cred_id", credential_source.id,
            "version", 1
        )]),
        credential_source.key_pair,
        true,
        "application/octet-stream"
    ).await?;
    */
    let cred_id = URL_SAFE_NO_PAD.encode(credential_source.id);
    let cred_path = PathBuf::from([CRED_DIR, cred_id]);
    let cred_file = File::create(cred_path)?;
    cred_file.write(b"type=public-key "); // TODO: Don't hardcode public-key?
    cred_file.write_fmt("id={} ", cred_id);
    cred_file.write("key=");
    cred_file.write(credential_source.private_key);
    cred_file.write(' ');
    cred_file.write("rp_id={} ", credential_source.rp_id);
    if let Some(user_handle) = credential_source.user_handle {
        cred_file.write("user_handle=");
        URL_SAFE_NO_PAD.encode_slice(user_handle, &cred_file);
        cred_file.write(user_handle);
        cred_file.write(' ');
    }

    if let Some(other_ui) = credential_source.other_ui {
        cred_file.write_fmt("other_ui={other_ui}");
    }
}

pub(super) fn lookup_stored_credentials(id: Vec<u8>) -> Option<(CredentialDescriptor, RelyingParty)> {
    todo!();
}
