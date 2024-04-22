use std::{thread, time::Duration};

use crate::view_model::{Device, Transport};

#[derive(Debug)]
pub struct CredentialService {
    devices: Vec<Device>,

    usb_state: UsbState,
    usb_poll_count: i32,
    usb_needs_pin: bool,
}

impl CredentialService {
    pub fn new() -> Self {
        let devices = vec![Device { id: String::from("0"), transport: Transport::Usb }];
        Self {
            devices,

            usb_state: UsbState::Idle,
            usb_poll_count: -1,
            usb_needs_pin: false,
        }
    }

    pub async fn get_available_public_key_devices(&self) -> Result<Vec<Device>, ()> {
        Ok(self.devices.to_owned())
    }

    pub(crate) async fn start_device_discovery_usb(&mut self) -> Result<UsbState, ()> {
        self.usb_state = UsbState::Waiting;
        self.usb_poll_count = 0;
        println!("frontend: Start USB flow");
        Ok(self.usb_state)
    }

    pub(crate) async fn poll_device_discovery_usb(&mut self) -> Result<UsbState, String> {
        thread::sleep(Duration::from_millis(25));

        match self.usb_state {
            // process polling
            UsbState::Waiting  => { }
            UsbState::Idle => return Err(String::from("USB polling not started.")),
            // UsbPinState::Completed => return Err(String::from("USB polling not started.")),
            _ => return Ok(self.usb_state),
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

    pub(crate) fn cancel_device_discovery_usb(_request: &UsbPollResponse) {
        println!("frontend: Cancel USB request")
    }

    pub(crate) fn validate_usb_device_pin(&mut self, pin: &str) -> Result<bool, ()> {
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
