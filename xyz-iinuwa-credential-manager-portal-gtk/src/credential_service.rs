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

    pub(crate) async fn start_device_discovery_usb(&self) -> Result<UsbPollResponse, ()> {
        println!("frontend: Start USB flow");
        Ok(UsbPollResponse {
            state: UsbState::Waiting,
            poll_count: 0,
            needs_pin: true,
            pin_entered: false,
        })
    }

    pub(crate) async fn poll_device_discovery_usb(&self, handle: &mut UsbPollResponse) -> Result<(), String> {
        thread::sleep(Duration::from_millis(25));

        match handle.state {
            // process polling
            UsbState::Waiting  => { }
            UsbState::Idle => return Err(String::from("USB polling not started.")),
            // UsbPinState::Completed => return Err(String::from("USB polling not started.")),
            _ => {}
        }

        let prev_state = handle.state;
        let mut msg = None;

        handle.poll_count += 1;
        if handle.poll_count < 10 {
            handle.state = UsbState::Waiting;
        } else if handle.poll_count < 20 {
            msg.replace("frontend: Discovered FIDO USB key");
            handle.state = UsbState::Connected;
            handle.needs_pin = true; // This may be false for U2F devices or devices that don't support user verification.
        } else if handle.poll_count < 25 && handle.state == UsbState::Connected {
            if handle.needs_pin {
                msg.replace("frontend: FIDO USB token requested PIN unlock");
                handle.state = UsbState::NeedsPin;
            } else {
                msg.replace("frontend: Received user verification and credential from FIDO USB device.");
                handle.poll_count = -1;
                handle.state = UsbState::Completed;
            }
        }

        if prev_state != handle.state && msg.is_some() {
            println!("{}", msg.unwrap());
        }
        Ok(())
    }

    pub(crate) async fn cancel_device_discovery_usb(&mut self) -> Result<(), String> {
        self.usb_state = UsbState::Idle;
        self.usb_poll_count = -1;
        println!("frontend: Cancel USB request");
        Ok(())
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
