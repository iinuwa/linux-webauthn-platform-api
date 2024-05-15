pub mod gtk;

use std::sync::Arc;
use std::time::Duration;

use async_std::prelude::*;
use async_std::{channel::{Receiver, Sender}, sync::Mutex};

use crate::credential_service::CredentialService;

#[derive(Debug)]
pub(crate) struct ViewModel {
    credential_service: Arc<Mutex<CredentialService>>,
    tx_update: Sender<ViewUpdate>,
    rx_event: Receiver<ViewEvent>,
    bg_update: Sender<BackgroundEvent>,
    bg_event: Receiver<BackgroundEvent>,
    title: String,
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
    pub(crate) fn new(operation: Operation, credential_service: CredentialService, rx_event: Receiver<ViewEvent>, tx_update: Sender<ViewUpdate>) -> Self {
        let (bg_update, bg_event) = async_std::channel::unbounded::<BackgroundEvent>();
        Self {
            credential_service: Arc::new(Mutex::new(credential_service)),
            rx_event,
            tx_update,
            bg_update,
            bg_event,
            operation,
            title: String::default(),
            devices: Vec::new(),
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
            hybrid_linked_state: HybridState::default()
        }
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

    async fn update_title(&mut self) {
        self.title = match self.operation {
            Operation::Create{ .. } => "Create new credential",
            Operation::Get { .. } => "Use a credential",
        }.to_string();
        self.tx_update.send(ViewUpdate::SetTitle(self.title.to_string())).await.unwrap();
    }

    async fn update_devices(&mut self) {
        let devices = self.credential_service.lock().await.get_available_public_key_devices().await.unwrap();
        self.devices = devices;
        self.tx_update.send(ViewUpdate::SetDevices(self.devices.to_owned())).await.unwrap();
    }

    pub(crate) async fn select_device(&mut self, id: &str) {
        let device = self.devices.iter().find(|d| &d.id == id).unwrap();
        println!("{:?}", device);

        // Handle previous device
        if let Some(prev_device) = self.selected_device.replace(device.clone()) {
            if *device == prev_device {
                return;
            }
            match prev_device.transport {
                Transport::Usb => { self.credential_service.lock().await.cancel_device_discovery_usb().await.unwrap() },
                _ => { todo!() }
            };
        }

        // start discovery for newly selected device
        match device.transport {
            Transport::Usb => {
                let cred_service = self.credential_service.clone();
                let mut handle = self.credential_service.lock().await.start_device_discovery_usb().await.unwrap();
                let tx = self.bg_update.clone();
                async_std::task::spawn(async move {
                    // TODO: repeat poll in loop
                    async_std::task::sleep(Duration::from_millis(100)).await;
                    // TODO: add cancellation
                    let mut prev_state = UsbState::default();
                    while let Ok(()) = cred_service.lock().await.poll_device_discovery_usb(&mut handle).await {
                        let state = handle.state.into();
                        if prev_state != state {
                            println!("{:?}", state);
                            tx.send(BackgroundEvent::UsbStateChanged(state.clone())).await.unwrap();
                        }
                        prev_state = state;
                    }
                });
             },
            _ => { todo!() }
        }

        self.tx_update.send(ViewUpdate::SelectDevice(device.clone())).await.unwrap();
    }

    pub(crate) async fn start_event_loop(&mut self) {
        let view_events = self.rx_event.clone().map(Event::View);
        let bg_events = self.bg_event.clone().map(Event::Background);
        let mut all_events = view_events.merge(bg_events);
        while let Some(event) = all_events.next().await {
            match event {
                Event::View(ViewEvent::Initiated) => {
                    self.update_title().await;
                    self.update_devices().await;
                },
                Event::View(ViewEvent::ButtonClicked) => { println!("Got it!") },
                Event::View(ViewEvent::DeviceSelected(id)) => {
                    self.select_device(&id).await;
                    println!("Selected device {id}");
                },
                Event::Background(BackgroundEvent::UsbPressed) => {
                    println!("UsbPressed");
                }
                Event::Background(BackgroundEvent::UsbStateChanged(state)) => {
                    self.usb_device_state = state;
                    match self.usb_device_state {
                        UsbState::NeedsPin => {
                            self.tx_update.send(ViewUpdate::UsbNeedsPin).await.unwrap();
                        },
                        _ => {},
                    }
                }
            };
        }
    }
}

pub enum ViewEvent {
    Initiated,
    ButtonClicked,
    DeviceSelected(String),
}

pub enum ViewUpdate {
    SetTitle(String),
    SetDevices(Vec<Device>),
    SelectDevice(Device),
    UsbNeedsPin,
}

pub enum BackgroundEvent {
    UsbPressed,
    UsbStateChanged(UsbState),
}

pub enum Event {
    Background(BackgroundEvent),
    View(ViewEvent)
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

#[derive(Clone, Debug, PartialEq)]
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

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Transport {
    Ble,
    HybridLinked,
    HybridQr,
    Internal,
    Nfc,
    Usb,
}

pub enum Error {
    ConversionError,
}

impl TryInto<Transport> for String {
    type Error = String;

    fn try_into(self) -> Result<Transport, String> {
        let value: &str = self.as_ref();
        value.try_into()
    }
}

impl TryInto<Transport> for &str {
    type Error = String;

    fn try_into(self) -> Result<Transport, String> {
        match self {
            "BLE" => Ok(Transport::Ble),
             "HybridLinked" => Ok(Transport::HybridLinked),
            "HybridQr" => Ok(Transport::HybridQr),
            "Internal" => Ok(Transport::Internal),
            "NFC" => Ok(Transport::Nfc),
            "USB" => Ok(Transport::Usb),
            _ => Err(format!("Unrecognized transport: {}", self.to_owned())),
        }
    }
}

impl Into<String> for Transport {
    fn into(self) -> String {
        self.as_str().to_string()
    }
}

impl Transport {
    fn as_str(&self) -> &'static str {
        match self {
            Transport::Ble => "BLE",
            Transport::HybridLinked => "HybridLinked",
            Transport::HybridQr => "HybridQr",
            Transport::Internal => "Internal",
            Transport::Nfc => "NFC",
            Transport::Usb => "USB",
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
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

impl Into<UsbState> for crate::credential_service::UsbState {
    fn into(self) -> UsbState {
        match self {
            crate::credential_service::UsbState::Idle => UsbState::NotListening,
            crate::credential_service::UsbState::Waiting => UsbState::Waiting,
            crate::credential_service::UsbState::Connected => UsbState::Connected,
            crate::credential_service::UsbState::NeedsPin => UsbState::NeedsPin,
            crate::credential_service::UsbState::Completed => UsbState::Completed,
            crate::credential_service::UsbState::UserCancelled => UsbState::UserCancelled,
        }
    }
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
