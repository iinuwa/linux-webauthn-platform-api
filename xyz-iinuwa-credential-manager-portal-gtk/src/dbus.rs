use std::sync::mpsc;
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;

// use base64::engine::general_purpose::URL_SAFE_NO_PAD;
// use base64::Engine;
use gettextrs::{gettext, LocaleCategory};
use gtk::{gio, glib};

use zbus::{interface, Connection, ConnectionBuilder, Result};

use crate::application::ExampleApplication;
use crate::config::{GETTEXT_PACKAGE, LOCALEDIR, RESOURCES_FILE};
use crate::view_model::gtk::ViewModel;
// use crate::store;
// use crate::webauthn;

pub(crate) async fn start_service(service_name: &str, path: &str) -> Result<Connection> {
    let lock = Arc::new(Mutex::new(false));
    let lock2 = lock.clone();
    let (tx, rx) = mpsc::channel::<()>();
    thread::Builder::new()
        .name("gui".into())
        .spawn(move || {
            loop {
                if let Ok(()) = rx.recv() {
                    // Prepare i18n
                    gettextrs::setlocale(LocaleCategory::LcAll, "");
                    gettextrs::bindtextdomain(GETTEXT_PACKAGE, LOCALEDIR)
                        .expect("Unable to bind the text domain");
                    gettextrs::textdomain(GETTEXT_PACKAGE)
                        .expect("Unable to switch to the text domain");
                    glib::set_application_name(&gettext("Credential Manager"));

                    let res =
                        gio::Resource::load(RESOURCES_FILE).expect("Could not load gresource file");
                    gio::resources_register(&res);
                    let view_model = ViewModel::new("Testing");
                    let app = ExampleApplication::new(view_model);
                    app.run();
                    let mut running = lock2.lock().unwrap();
                    *running = false;
                } else {
                    break;
                }
            }
        })
        .unwrap();
    ConnectionBuilder::session()?
        .name(service_name)?
        .serve_at(
            path,
            CredentialManager {
                app_signaller: tx,
                app_lock: lock,
            },
        )?
        .build()
        .await
}
struct CredentialManager {
    app_signaller: Sender<()>,
    app_lock: Arc<Mutex<bool>>,
}

#[interface(name = "xyz.iinuwa.credentials.CredentialManagerUi1")]
impl CredentialManager {
    async fn start_app(&self) {
        if let Ok(mut running) = self.app_lock.try_lock() {
            if !*running {
                *running = true;
                self.app_signaller.send(()).unwrap();
            } else {
                tracing::debug!("Window already open");
            }
        } else {
            tracing::debug!("Window already open");
        }
    }
    /*
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
    */
}
