use std::sync::{Arc, Mutex};
use std::thread;

use async_std::channel::{Receiver, Sender};
use async_std::sync::Mutex as AsyncMutex;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use gettextrs::{gettext, LocaleCategory};
use gtk::{gio, glib};

use zbus::zvariant::{DeserializeDict, SerializeDict, Type};
use zbus::{fdo, interface, Connection, ConnectionBuilder, Result};

use crate::application::ExampleApplication;
use crate::config::{GETTEXT_PACKAGE, LOCALEDIR, RESOURCES_FILE};
use crate::credential_service::CredentialService;
use crate::store;
use crate::view_model::CredentialType;
use crate::view_model::Device;
use crate::view_model::Operation;
use crate::view_model::Transport;
use crate::view_model::{self, ViewEvent, ViewUpdate};
use crate::webauthn;
// use crate::store;
// use crate::webauthn;

pub(crate) async fn start_service(service_name: &str, path: &str) -> Result<Connection> {
    let (gui_tx, gui_rx) = async_std::channel::bounded(1);
    let lock: Arc<AsyncMutex<Sender<Sender<(Device, String)>>>> = Arc::new(AsyncMutex::new(gui_tx));
    start_gui_thread(gui_rx);
    ConnectionBuilder::session()?
        .name(service_name)?
        .serve_at(path, CredentialManager { app_lock: lock })?
        .build()
        .await
}

fn start_gui_thread(rx: Receiver<Sender<(Device, String)>>) {
    thread::Builder::new()
        .name("gui".into())
        .spawn(move || {
            while let Ok(response_tx) = rx.recv_blocking() {
                let (tx_update, rx_update) = async_std::channel::unbounded::<ViewUpdate>();
                let (tx_event, rx_event) = async_std::channel::unbounded::<ViewEvent>();
                let data = Arc::new(Mutex::new(None));
                let credential_service = CredentialService::new(data.clone());
                let event_loop = async_std::task::spawn(async move {
                    let operation = Operation::Create {
                        cred_type: CredentialType::Passkey,
                    };
                    let mut vm = view_model::ViewModel::new(
                        operation,
                        credential_service,
                        rx_event,
                        tx_update,
                    );
                    vm.start_event_loop().await;
                    println!("event loop ended?");
                });
                start_gtk_app(tx_event, rx_update);

                async_std::task::block_on(event_loop.cancel());
                let lock = data.lock().unwrap();
                let response = lock.as_ref().unwrap().clone();
                response_tx.send_blocking(response).unwrap();
            }
        })
        .unwrap();
}

fn start_gtk_app(tx_event: Sender<ViewEvent>, rx_update: Receiver<ViewUpdate>) {
    // Prepare i18n
    gettextrs::setlocale(LocaleCategory::LcAll, "");
    gettextrs::bindtextdomain(GETTEXT_PACKAGE, LOCALEDIR).expect("Unable to bind the text domain");
    gettextrs::textdomain(GETTEXT_PACKAGE).expect("Unable to switch to the text domain");

    if glib::application_name().is_none() {
        glib::set_application_name(&gettext("Credential Manager"));
    }
    let res = gio::Resource::load(RESOURCES_FILE).expect("Could not load gresource file");
    gio::resources_register(&res);

    let app = ExampleApplication::new(tx_event, rx_update);
    app.run();
}

struct CredentialManager {
    app_lock: Arc<AsyncMutex<Sender<Sender<(Device, String)>>>>,
}

#[interface(name = "xyz.iinuwa.credentials.CredentialManagerUi1")]
impl CredentialManager {
    async fn create_credential(
        &self,
        request: CreateCredentialRequest,
    ) -> fdo::Result<CreateCredentialResponse> {
        if let Some(tx) = self.app_lock.try_lock() {
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
                    let (data_tx, data_rx) = async_std::channel::bounded(1);
                    tx.send(data_tx).await.unwrap();
                    let data_rx = Arc::new(data_rx);
                    let (device, cred_id) = data_rx.recv().await.unwrap();
                    match device.transport {
                        Transport::Internal => {
                            Ok(create_passkey(&origin, passkey_request).await?.into())
                        }
                        _ => todo!("Transport {:?} not implemented", device.transport),
                    }
                }
                _ => Err(fdo::Error::Failed(
                    "Unknown credential request type".to_string(),
                )),
            };
            response
        } else {
            tracing::debug!("Window already open");
            Err(fdo::Error::ObjectPathInUse(
                "WebAuthn session already open.".into(),
            ))
        }
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
        request.id.replace('%', "%25").replace('&', "%26"),
        request.password.replace('%', "%25").replace('&', "%26")
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
        registration_response_json: response.to_json(),
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

impl From<CreatePasswordCredentialResponse> for CreateCredentialResponse {
    fn from(response: CreatePasswordCredentialResponse) -> Self {
        CreateCredentialResponse {
            r#type: "password".to_string(),
            password: Some(response),
            public_key: None,
        }
    }
}

#[derive(SerializeDict, Type)]
#[zvariant(signature = "dict")]
pub struct CreatePublicKeyCredentialResponse {
    registration_response_json: String,
}

impl From<CreatePublicKeyCredentialResponse> for CreateCredentialResponse {
    fn from(response: CreatePublicKeyCredentialResponse) -> Self {
        CreateCredentialResponse {
            // TODO: Decide on camelCase or kebab-case for cred types
            r#type: "public-key".to_string(),
            public_key: Some(response),
            password: None,
        }
    }
}
