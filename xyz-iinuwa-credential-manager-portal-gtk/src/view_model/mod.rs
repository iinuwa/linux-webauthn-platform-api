pub mod gtk;

use std::time::Duration;

struct ViewModel<'a> {
    title: String,
    operation: Operation,

    // This includes devices like platform authenticator, USB, hybrid
    devices: Vec<Device>,
    selected_device: Device,

    providers: Vec<Provider>,

    internal_uv_methods: Vec<UserVerificationMethod>,
    internal_selected_uv_method: &'a UserVerificationMethod,
    internal_device_credentials: Vec<Credential>,
    internal_device_pin_state: InternalPinState,
    internal_fingerprint_sensor_state: FingerprintSensorState,

    usb_device_state: UsbState,
    usb_device_pin_state: UsbPinState,

    hybrid_qr_state: HybridState,
    hybrid_qr_code_data: Vec<u8>,

    hybrid_linked_state: HybridState,
}

impl ViewModel<'_> {
    fn start_authentication(&self) {} // open page
    fn cancel_authentication(&self) {}

    fn start_fingerprint_authentication(&self) {
        todo!("not implemented");
    }
    fn cancel_fingerprint_authentication(&self) {}

    fn start_hybrid_qr_authentication(&self) {}
    fn cancel_hybrid_qr_authentication(&self) {
        todo!("not implemented");
    }

    fn start_hybrid_linked_authentication(&self) {
        todo!("not implemented");
    }
    fn cancel_hybrid_linked_authentication(&self) {
        todo!("not implemented");
    }

    // Can this be used for internal uv method too?
    fn start_usb_authentication(&self) {
        todo!("not implemented");
    }
    fn cancel_usb_authentication(&self) {
        todo!("not implemented");
    }
    fn send_usb_device_pin(&self) {
        todo!("not implemented");
    }

    fn select_uv_method(&self) {
        todo!("not implemented");
    }
    fn send_internal_device_pin(&self) {
        todo!("not implemented");
    }

    fn finish_authentication(&self) {
        todo!("not implemented");
    }

    fn select_device(&self) {
        todo!("not implemented");
    }
}

pub enum ViewEvent {
}

pub enum ViewUpdate {
    SetTitle(String),
}

pub struct Credential {
    id: String,
    name: String,
    username: Option<String>,
}
pub enum FingerprintSensorState {}

pub enum CredentialType {
    Passkey,
    Password,
}

pub struct Device {
    id: String,
    transport: Transport,
}

#[derive(Clone, Debug)]
pub enum HybridState {
    /// Default state, not listening for hybrid transport.
    Idle,

    /// Awaiting BLE advert from phone.
    Waiting,

    /// Connecting to caBLE tunnel.
    Connecting,

    /// Connected to device via caBLE tunnel.
    // I don't think is necessary to signal
    // Connected,

    /// Credential received over tunnel.
    Completed,

    // This isn't actually sent from the server.
    UserCancelled,
}

pub enum InternalPinState {
    Waiting,

    PinIncorrect { attempts_left: u32 },

    LockedOut { unlock_time: Duration },

    PinCorrect,
}

pub enum Operation {
    Create { cred_type: CredentialType },
    Get { cred_types: Vec<CredentialType> },
}

pub struct Provider;

pub enum Transport {
    Ble,
    HybridLinked,
    HybridQr,
    Internal,
    Nfc,
    Usb,
}

pub enum UsbState {
    /// Not currently listening for USB devices.
    NotListening,

    /// Awaiting FIDO USB device to be plugged in.
    Waiting,

    /// The device needs the PIN to be entered.
    NeedsPin,

    /// USB device connected, prompt user to tap
    Connected,

    /// USB tapped, received credential
    Completed,

    // This isn't actually sent from the server.
    UserCancelled,
}
pub enum UsbPinState {
    Waiting,

    PinIncorrect { attempts_left: u32 },

    LockedOut { unlock_time: Duration },

    PinCorrect,
}

pub struct UserVerificationMethod;
