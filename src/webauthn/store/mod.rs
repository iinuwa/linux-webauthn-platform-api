use std::io::Write;
use std::path::PathBuf;
use std::fs::{File, self};
use std::str::FromStr;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD, self};

use super::{CredentialSource, CredentialDescriptor, Error, RelyingParty};
static CRED_DIR: &'static str = "~/.local/share/webauthn/credentials";

pub(crate) fn initialize() {
    fs::create_dir_all(PathBuf::from_str(CRED_DIR).unwrap());
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
    
    let cred_path = PathBuf::from_str(CRED_DIR).unwrap().join(&cred_id);
    let mut cred_file = File::create(cred_path).unwrap();
    cred_file.write(b"type=public-key "); // TODO: Don't hardcode public-key?
    cred_file.write_fmt(format_args!("id={} ", cred_id));
    cred_file.write(b"key=");
    cred_file.write(&credential_source.private_key);
    cred_file.write(b" ");
    cred_file.write_fmt(format_args!("rp_id={} ", credential_source.rp_id));
    if let Some(user_handle) = credential_source.user_handle {
        cred_file.write(b"user_handle=");
        let user_handle_b64 = URL_SAFE_NO_PAD.encode(user_handle);
        cred_file.write(user_handle_b64.as_bytes());
        cred_file.write(b" ");
    }

    if let Some(other_ui) = credential_source.other_ui {
        cred_file.write_fmt(format_args!("other_ui={other_ui} "));
    }
    Ok(())
}

pub(super) fn lookup_stored_credentials(id: Vec<u8>) -> Option<(CredentialDescriptor, RelyingParty)> {
    todo!();
}
