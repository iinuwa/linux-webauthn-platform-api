mod application;
#[rustfmt::skip]
mod config;
mod dbus;
mod view_model;
mod window;

use std::error::Error;

use async_std::task;

use self::application::ExampleApplication;
use self::config::{GETTEXT_PACKAGE, LOCALEDIR, RESOURCES_FILE};

fn main() {
    // Initialize logger
    tracing_subscriber::fmt::init();

    println!("Starting...");
    task::block_on(run());
}

async fn run() -> Result<(), Box<dyn Error>> {
    let service_name = "xyz.iinuwa.credentials.CredentialManagerUi";
    let path = "/xyz/iinuwa/credentials/CredentialManagerUi";
    let _conn = dbus::start_service(service_name, path).await?;
    /// store::initialize();
    // let _conn = dbus::start_service(service_name, path, seed_key).await?;
    println!("Started");
    loop {
        // do something else, wait forever or timeout here:
        // handling D-Bus messages is done in the background

        std::future::pending::<()>().await;
    }
}
