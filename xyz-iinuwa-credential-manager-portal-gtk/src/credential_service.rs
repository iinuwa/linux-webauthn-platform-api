use crate::view_model::{Device, Transport};

#[derive(Debug)]
pub struct CredentialService {
    devices: Vec<Device>,
}

impl CredentialService {
    pub fn new() -> Self {
        let devices = vec![Device { id: String::from("0"), transport: Transport::Usb }];
        Self {
            devices,
        }
    }

    pub async fn get_available_public_key_devices(&self) -> Result<Vec<Device>, ()> {
        Ok(self.devices.to_owned())
    }
}
