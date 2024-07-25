use std::{ops::Add, thread, time::{Duration, SystemTime, UNIX_EPOCH }};

use async_std::task;

use crate::view_model::{Device, InternalPinState, Transport};

#[derive(Debug)]
pub struct CredentialService {
    devices: Vec<Device>,

    usb_state: UsbState,
    usb_poll_count: i32,
    usb_needs_pin: bool,
    usb_pin_entered: bool,

    internal_device_credentials: Vec<CredentialMetadata>,
    internal_device_state: InternalDeviceState,
    internal_pin_attempts_left: u32,
    internal_pin_unlock_time: Option<SystemTime>,

    completed_credential: Option<(Device, String)>,
}

impl CredentialService {
    pub fn new() -> Self {
        let devices = vec![
            Device { id: String::from("0"), transport: Transport::Usb },
            Device { id: String::from("1"), transport: Transport::Internal },
        ];
        let internal_device_credentials = vec![
            CredentialMetadata { id: String::from("0"), origin: String::from("foo.example.com"), display_name: String::from("Foo"), username: String::from("joecool") },
            CredentialMetadata { id: String::from("1"), origin: String::from("bar.example.org"), display_name: String::from("Bar"), username: String::from("cooliojoe") },
        ];
        Self {
            devices,

            usb_state: UsbState::Idle,
            usb_poll_count: -1,
            usb_needs_pin: false,
            usb_pin_entered: false,

            internal_device_credentials,
            internal_device_state: InternalDeviceState::Idle,
            internal_pin_attempts_left: 5,
            internal_pin_unlock_time: None,

            completed_credential: None,
        }
    }

    pub async fn get_available_public_key_devices(&self) -> Result<Vec<Device>, ()> {
        Ok(self.devices.to_owned())
    }

    pub(crate) async fn start_device_discovery_usb(&mut self) -> Result<UsbPollResponse, ()> {
        println!("frontend: Start USB flow");
        self.usb_state = UsbState::Waiting;
        self.usb_poll_count = 0;
        self.usb_needs_pin = true;
        self.usb_pin_entered = false;
        Ok(UsbPollResponse {
            state: self.usb_state,
            poll_count: self.usb_poll_count,
            needs_pin: self.usb_needs_pin,
            pin_entered: self.usb_pin_entered,
        })
    }

    pub(crate) async fn poll_device_discovery_usb(&mut self) -> Result<UsbState, String> {
        thread::sleep(Duration::from_millis(25));

        match self.usb_state {
            // process polling
            UsbState::Waiting  => { }
            UsbState::Idle => return Err(String::from("USB polling not started.")),
            // UsbPinState::Completed => return Err(String::from("USB polling not started.")),
            _ => {}
        }

        let prev_state = self.usb_state;
        let mut msg = None;

        self.usb_poll_count += 1;
        if self.usb_poll_count < 10 {
            self.usb_state = UsbState::Waiting;
        } else if self.usb_poll_count < 20 {
            msg.replace("frontend: Discovered FIDO USB key");
            self.usb_state = UsbState::Connected;
            self.usb_needs_pin = true; // This may be false for U2F devices or devices that don't support user verification.
        } else if self.usb_poll_count < 25 && self.usb_state == UsbState::Connected {
            if self.usb_needs_pin {
                msg.replace("frontend: FIDO USB token requested PIN unlock");
                self.usb_state = UsbState::NeedsPin;
            } else {
                msg.replace("frontend: Received user verification and credential from FIDO USB device.");
                self.usb_poll_count = -1;
                self.usb_state = UsbState::Completed;
            }
        }

        if prev_state != self.usb_state && msg.is_some() {
            println!("{}", msg.unwrap());
        }
        Ok(self.usb_state)
    }

    pub(crate) async fn cancel_device_discovery_usb(&mut self) -> Result<(), String> {
        self.usb_state = UsbState::Idle;
        self.usb_poll_count = -1;
        println!("frontend: Cancel USB request");
        Ok(())
    }

    pub(crate) async fn validate_usb_device_pin(&mut self, pin: &str) -> Result<bool, ()> {
        if self.usb_state != UsbState::NeedsPin {
            return Err(());
        }
        if pin == "123456" {
            self.usb_state = UsbState::Completed;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub(crate) async fn get_internal_device_credentials(&self) -> Result<&Vec<CredentialMetadata>, ()> {
        Ok(&self.internal_device_credentials)
    }

    pub(crate) async fn validate_internal_device_pin(&mut self, pin: &str, cred_id: &str) -> Result<InternalPinState, ()> {
        // TODO: Should this have the selected credential ID included with it to make sure the
        // frontend and backend are talking about the same credential?
        let now = SystemTime::now();
        if let Some(unlock_time) = self.internal_pin_unlock_time {
            if unlock_time < now {
                let t = unlock_time.duration_since(UNIX_EPOCH).unwrap();
                return Ok(InternalPinState::LockedOut { unlock_time: t });
            } else {
                self.internal_pin_unlock_time = None;
            }
        }
        if pin == "123456" {
            let device = self.devices.iter().find(|d| d.transport == Transport::Internal).unwrap().clone();
            self.internal_device_state = InternalDeviceState::Completed { device, cred_id: cred_id.to_owned() };
            Ok(InternalPinState::PinCorrect { completion_token: "pin".to_string() })
        } else {
            self.internal_device_state = InternalDeviceState::NeedsPin;
            self.internal_pin_attempts_left -= 1;
            if self.internal_pin_attempts_left > 0 {
                Ok(InternalPinState::PinIncorrect { attempts_left: self.internal_pin_attempts_left })
            } else {
                let t = now.add(Duration::from_secs(10));
                self.internal_pin_unlock_time = Some(t);
                Ok(InternalPinState::LockedOut { unlock_time: t.duration_since(UNIX_EPOCH).unwrap() })
            }
        }
    }

    pub(crate) async fn start_device_discovery_internal(&mut self) -> Result<InternalDeviceState, String> {
        println!("frontend: Start Internal flow");
        if let InternalDeviceState::Idle = self.internal_device_state {
            self.internal_device_state = InternalDeviceState::NeedsPin;
            Ok(self.internal_device_state.clone())
        } else {
            Err(format!("Invalid state to begin discovery: {:?}", self.internal_device_state))
        }
    }

    pub(crate) async fn poll_device_discovery_internal(&mut self) -> Result<InternalDeviceState, String> {
        task::sleep(Duration::from_millis(5)).await;

        if let InternalDeviceState::Idle = self.internal_device_state {
            return Err(String::from("Internal polling not started."));
        }

        Ok(self.internal_device_state.clone())
    }

    pub(crate) async fn cancel_device_discovery_internal(&mut self) -> Result<(), String> {
        self.internal_device_state = InternalDeviceState::Idle;
        Ok(())
    }

    pub(crate) fn complete_auth(&mut self, device: &Device, cred_id: &str) {
        self.completed_credential = Some((device.clone(), cred_id.to_owned()));
    }

    pub(crate) fn get_completed_credential(&self) -> Result<&(Device, String), String> {
        self.completed_credential.as_ref().ok_or_else(||"Credential operation not completed".to_string())
    }

}

#[derive(Clone, Copy)]
pub(crate) struct UsbPollResponse {
    pub state: UsbState,
    poll_count: i32,
    needs_pin: bool,
    pin_entered: bool,
}

#[derive(Copy, Clone, Debug, Default, PartialEq)]
pub enum UsbState {
    /// Not polling for FIDO USB device.
    #[default]
    Idle,

    /// Awaiting FIDO USB device to be plugged in.
    Waiting,

    /// USB device connected, prompt user to tap
    Connected,

    /// The device needs the PIN to be entered.
    NeedsPin,

    /// USB tapped, received credential
    Completed,

    // This isn't actually sent from the server.
    UserCancelled,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub enum InternalDeviceState {
    /// Not awaiting for internal FIDO device.
    #[default]
    Idle,

    /// The device needs the PIN to be entered.
    NeedsPin,

    /// Internal device credentials
    Completed { device: Device, cred_id: String },

    // This isn't actually sent from the server.
    UserCancelled,
}

pub enum PinResponse {
    Correct,
    /// Incorrect PIN given, contains time (in seconds since Unix epoch) when
    /// the user can retry.
    // TODO: Should we show how many retries are left?
    Incorrect(usize),

    /// PIN locked out, contains time (in seconds since Unix epoch) when
    /// the user can retry.
    Locked(Duration),
}

#[derive(Debug)]
pub(crate) struct CredentialMetadata {
    /// ID of credential, to be used in `SelectCredential()`.
    pub(crate) id: String,

    /// Origin of credential.
    // TODO: Does this need to be multiple origins?
    pub(crate) origin: String,

    /// User-chosen name for the credential.
    pub(crate) display_name: String,

    /// Username of credential, if any.
    pub(crate) username: String,
}
