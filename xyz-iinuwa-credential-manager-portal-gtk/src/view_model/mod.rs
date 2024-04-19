pub mod gtk;

use std::time::Duration;

#[derive(Debug)]
pub(crate) struct ViewModel {
    // title: String,
    operation: Operation,

    // This includes devices like platform authenticator, USB, hybrid
    devices: Vec<Device>,
    selected_device: Option<Device>,

    providers: Vec<Provider>,

    internal_uv_methods: Vec<UserVerificationMethod>,
    internal_selected_uv_method: UserVerificationMethod,
    internal_device_credentials: Vec<Credential>,
    internal_device_pin_state: InternalPinState,
    internal_fingerprint_sensor_state: FingerprintSensorState,

    usb_device_state: UsbState,
    usb_device_pin_state: UsbPinState,

    hybrid_qr_state: HybridState,
    hybrid_qr_code_data: Option<Vec<u8>>,

    hybrid_linked_state: HybridState,
}

impl ViewModel {
    pub(crate) fn new(operation: Operation, devices: Vec<Device>) -> Self {
        Self {
            operation,
            devices: devices,
            selected_device: None,
            providers: Vec::new(),
            internal_uv_methods: Vec::new(),
            internal_selected_uv_method: UserVerificationMethod::default(),
            internal_device_credentials: Vec::new(),
            internal_device_pin_state: InternalPinState::default(),
            internal_fingerprint_sensor_state: FingerprintSensorState::default(),
            usb_device_state: UsbState::default(),
            usb_device_pin_state: UsbPinState::default(),
            hybrid_qr_state: HybridState::default(),
            hybrid_qr_code_data: None,
            hybrid_linked_state: HybridState::default() }
    }
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
    ButtonClicked,
}

pub enum ViewUpdate {
    SetTitle(String),
}

#[derive(Debug, Default)]
pub struct Credential {
    id: String,
    name: String,
    username: Option<String>,
}

#[derive(Debug, Default)]
pub enum FingerprintSensorState {
    #[default]
    Idle,
}

#[derive(Debug)]
pub enum CredentialType {
    Passkey,
    Password,
}

#[derive(Debug)]
pub struct Device {
    pub id: String,
    pub transport: Transport,
}

#[derive(Clone, Debug, Default)]
pub enum HybridState {
    /// Default state, not listening for hybrid transport.
    #[default]
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

#[derive(Debug, Default)]
pub enum InternalPinState {
    #[default]
    Waiting,

    PinIncorrect { attempts_left: u32 },

    LockedOut { unlock_time: Duration },

    PinCorrect,
}

#[derive(Debug)]
pub enum Operation {
    Create { cred_type: CredentialType },
    Get { cred_types: Vec<CredentialType> },
}

#[derive(Debug, Default)]
pub struct Provider;

#[derive(Debug)]
pub enum Transport {
    Ble,
    HybridLinked,
    HybridQr,
    Internal,
    Nfc,
    Usb,
}

#[derive(Debug, Default)]
pub enum UsbState {
    /// Not currently listening for USB devices.
    #[default]
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

#[derive(Debug, Default)]
pub enum UsbPinState {
    #[default]
    Waiting,

    PinIncorrect { attempts_left: u32 },

    LockedOut { unlock_time: Duration },

    PinCorrect,
}

#[derive(Debug, Default)]
pub struct UserVerificationMethod;
