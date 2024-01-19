mod dbus;
mod store;
mod webauthn;

use std::{error::Error, fs, path::Path};

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();
    let path_to_key = Path::new(&args[0]);
    let seed_key = fs::read(path_to_key)?;
    println!("Starting...");
    async_std::task::block_on(run(seed_key))
}

async fn run(seed_key: Vec<u8>) -> Result<(), Box<dyn Error>> {
    let service_name = "xyz.iinuwa.credentials.CredentialManager";
    let path = "/xyz/iinuwa/credentials/CredentialManager";
    store::initialize();
    let _conn = dbus::start_service(service_name, path, seed_key).await?;
    println!("Started");
    loop {
        // do something else, wait forever or timeout here:
        // handling D-Bus messages is done in the background

        std::future::pending::<()>().await;
    }
}
