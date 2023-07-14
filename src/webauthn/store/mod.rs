use std::env;
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use std::str::FromStr;

use base64::{self, engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

use super::{CredentialDescriptor, CredentialSource, Error, RelyingParty};
static mut CRED_DIR: String = String::new();

pub(crate) fn initialize() {
    let cred_dir = get_cred_dir();
    fs::create_dir_all(cred_dir).unwrap();
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

    let cred_path = get_cred_dir().join(&cred_id);
    let mut cred_file = File::create(cred_path).unwrap();
    cred_file.write(b"v=1 ").unwrap();
    cred_file.write(b"type=public-key ").unwrap(); // TODO: Don't hardcode public-key?
    cred_file.write_fmt(format_args!("id={} ", cred_id)).unwrap();
    cred_file.write(b"key=").unwrap();
    cred_file.write(&credential_source.private_key).unwrap();
    cred_file.write(b" ").unwrap();
    cred_file.write_fmt(format_args!("rp_id={} ", credential_source.rp_id)).unwrap();
    if let Some(user_handle) = credential_source.user_handle {
        cred_file.write(b"user_handle=").unwrap();
        let user_handle_b64 = URL_SAFE_NO_PAD.encode(user_handle);
        cred_file.write(user_handle_b64.as_bytes()).unwrap();
        cred_file.write(b" ").unwrap();
    }

    if let Some(other_ui) = credential_source.other_ui {
        cred_file.write_fmt(format_args!("other_ui={other_ui} ")).unwrap();
    }
    Ok(())
}

pub(super) fn lookup_stored_credentials(
    _id: Vec<u8>,
) -> Option<(CredentialDescriptor, RelyingParty)> {
    todo!();
}

fn get_cred_dir() -> PathBuf {
    let data_home = if let Ok(data_home) = env::var("XDG_DATA_HOME") {
        PathBuf::from_str(&data_home).unwrap()
    }
    else {
        PathBuf::from_str(&env::var("HOME").expect("$HOME not set")).unwrap().join(".local/share")
    };
    data_home.join("webauthn/credentials")
}