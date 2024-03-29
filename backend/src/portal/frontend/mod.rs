use std::{
    cell::RefCell,
    ops::Add,
    sync::atomic::{AtomicUsize, Ordering},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

// TODO: Do we need a separate device, or just the transport?
pub(crate) struct Device {
    pub id: String,
    pub transport: DeviceTransport,
}

pub(crate) enum DeviceTransport {
    Ble,
    HybridLinked(String),
    HybridQr,
    Internal,
    Nfc,
    PasskeyProvider,
    Usb,
}

/// Enumerate devices that the frontend can support.
pub(crate) fn get_available_public_key_devices() -> Result<Vec<Device>, ()> {
    // Simulate D-Bus latency
    thread::sleep(Duration::from_millis(15));
    // TODO: do we need some sort of order hints? Like last used, or preferred (based on requested transports from the request?)
    Ok(vec![
        Device {
            id: String::from("1"),
            transport: DeviceTransport::Internal,
        },
        Device {
            id: String::from("2"),
            transport: DeviceTransport::HybridQr,
        },
        Device {
            id: String::from("3"),
            transport: DeviceTransport::HybridLinked(String::from("Pixel 7")),
        },
        Device {
            id: String::from("4"),
            transport: DeviceTransport::Usb,
        },
        Device {
            id: String::from("5"),
            transport: DeviceTransport::PasskeyProvider,
        },
    ])
}

#[derive(Clone, Copy)]
pub(crate) struct HybridRequest {
    poll_count: i32,
    state: HybridPollResponse,
}

/// Returns string of "FIDO:/...", which should be QR-encoded and displayed to the user.
pub(crate) fn start_device_discovery_hybrid(
    device: Option<String>,
) -> Result<(HybridRequest, Option<String>), ()> {
    // TODO: Do we need to add a parameter for state.
    if let Some(device) = device {
        // State-assisted
        println!("frontend: Start linked device hybrid flow for {device}");
        Ok((
            HybridRequest {
                poll_count: 0,
                state: HybridPollResponse::Connecting,
            },
            None,
        ))
    } else {
        println!("frontend: Start QR hybrid flow");
        let qr_data = String::from("FIDO:/078241338926040702789239694720083010994762289662861130514766991835876383562063181103169246410435938367110394959927031730060360967994421343201235185697538107096654083332");
        Ok((
            HybridRequest {
                poll_count: 0,
                state: HybridPollResponse::Waiting,
            },
            Some(qr_data),
        ))
    }
}

// TODO: I don't know if it's better to design this API for the backend to
// subscribe to frontend notifications, or for the frontend to poll the backend.
// Polling is simpler.

#[derive(Copy, Clone)]
pub enum HybridPollResponse {
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

/// Poll for notificactions
pub(crate) fn poll_device_discovery_hybrid(
    request: &mut HybridRequest,
) -> Result<HybridPollResponse, ()> {
    thread::sleep(Duration::from_millis(25));
    if request.poll_count < 0 {
        return Err(());
    }

    request.poll_count += 1;
    if request.poll_count < 10 {
        request.state = HybridPollResponse::Waiting;
    } else if request.poll_count < 20 {
        if let HybridPollResponse::Connecting = request.state {
        } else {
            println!("frontend: Received BLE advert from mobile device");
        }
        request.state = HybridPollResponse::Connecting
    } else if request.poll_count < 30 {
        // if let HybridQrPollResponse::Connected = request.state {
        // NOTE: this is actually out of order for state-assisted transactions.
        // I think the difference between connecting to the tunnel and receiving
        // the device BLE advert should be internal to the frontend,
        // and the frontend can correctly log its own internal state.
        if let HybridPollResponse::Connecting = request.state {
        } else {
            println!("frontend: Connected to caBLE tunnel for mobile device");
        }
        // request.state = HybridQrPollResponse::Connected;
        request.state = HybridPollResponse::Connecting;
    } else {
        if let HybridPollResponse::Completed = request.state {
        } else {
            println!("frontend: Received CTAP advert from mobile device");
        }
        request.poll_count = -1;
        request.state = HybridPollResponse::Completed;
    }
    Ok(request.state)
}

pub(crate) fn cancel_device_discovery_hybrid(_request: &HybridRequest) {
    println!("frontend: Cancel Hybrid request")
}

#[derive(Clone, Copy)]
pub(crate) struct UsbRequest {
    poll_count: i32,
    state: UsbPollResponse,
    needs_pin: bool,
    pin_entered: bool,
}

#[derive(Copy, Clone, PartialEq)]
pub enum UsbPollResponse {
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

/// Returns string of "FIDO:/...", which should be QR-encoded and displayed to the user.
pub(crate) fn start_device_discovery_usb() -> Result<UsbRequest, ()> {
    println!("frontend: Start USB flow");
    Ok(UsbRequest {
        poll_count: 0,
        state: UsbPollResponse::Waiting,
        needs_pin: true, // This may be false for U2F devices or devices that don't support user verification.
        pin_entered: false,
    })
}

pub(crate) fn poll_device_discovery_usb(request: &mut UsbRequest) -> Result<UsbPollResponse, ()> {
    thread::sleep(Duration::from_millis(25));
    if request.poll_count < 0 {
        return Err(());
    }

    request.poll_count += 1;
    if request.poll_count < 10 {
        request.state = UsbPollResponse::Waiting;
    } else if request.poll_count < 20 {
        if let UsbPollResponse::Connected = request.state {
        } else {
            println!("frontend: Discovered FIDO USB key");
        }
        request.state = UsbPollResponse::Connected
    } else if request.needs_pin && !request.pin_entered {
        if let UsbPollResponse::NeedsPin = request.state {
        } else {
            println!("frontend: FIDO USB token requested PIN unlock");
        }
        request.state = UsbPollResponse::NeedsPin;
    } else {
        if let UsbPollResponse::Completed = request.state {
        } else {
            println!("frontend: Received user verification and credential from FIDO USB device.");
        }
        request.poll_count = -1;
        request.state = UsbPollResponse::Completed;
    }
    Ok(request.state)
}

pub(crate) fn cancel_device_discovery_usb(_request: &UsbRequest) {
    println!("frontend: Cancel USB request")
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

#[allow(clippy::borrow_interior_mutable_const)] // This is just for demo purposes.
pub(crate) fn validate_usb_device_pin(/* request: &mut UsbRequest, */ pin: &str) -> Result<bool, ()> {
    if pin == "123456" {
        // request.state = UsbPollResponse::Completed;
        Ok(true)
    } else {
        Ok(false)
    }
}

static PIN_COUNT: AtomicUsize = AtomicUsize::new(0);

#[allow(clippy::declare_interior_mutable_const)] // This is just for demo purposes.
const UNLOCK_TIME: RefCell<Option<SystemTime>> = RefCell::new(None);

#[allow(clippy::borrow_interior_mutable_const)] // This is just for demo purposes.
pub(crate) fn validate_device_pin(pin: &str) -> Result<PinResponse, ()> {
    let pin_count = PIN_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    let unlock_time_option = *UNLOCK_TIME.borrow();
    let now = SystemTime::now();
    if let Some(unlock_time) = unlock_time_option {
        if unlock_time < now {
            let t = unlock_time.duration_since(UNIX_EPOCH).unwrap();
            return Ok(PinResponse::Locked(t));
        } else {
            *UNLOCK_TIME.borrow_mut() = None;
        }
    }

    const ATTEMPTS_BEFORE_LOCKOUT: usize = 5;
    if pin == "123456" {
        PIN_COUNT.store(0, Ordering::Relaxed);
        Ok(PinResponse::Correct)
    } else if pin_count < ATTEMPTS_BEFORE_LOCKOUT {
        Ok(PinResponse::Incorrect(ATTEMPTS_BEFORE_LOCKOUT - pin_count))
    } else {
        let t = now.add(Duration::from_secs(10));
        *UNLOCK_TIME.borrow_mut() = Some(t);
        Ok(PinResponse::Locked(t.duration_since(UNIX_EPOCH).unwrap()))
    }
}

/// One of https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html#user-verification-methods.
#[derive(PartialEq)]
pub(crate) enum UserVerificationMethod {
    PasscodeInternal,
    FingerprintInternal
}

/// List of User Verfication Methods supported by the internal platform authenticator.
pub(crate) /* TODO: async */ fn get_available_platform_user_verification_methods() -> Vec<UserVerificationMethod> {
    vec![
        UserVerificationMethod::PasscodeInternal,
        UserVerificationMethod::FingerprintInternal,
    ]
}

#[derive(Clone, Copy)]
pub(crate) enum FingerprintScanType {
    Swipe,
    Touch,
}

#[derive(Clone, Copy)]
pub(crate) struct FingerprintRequest {
    pub(crate) scan_type: FingerprintScanType,
    poll_count: i32,
}

#[derive(Clone, Copy)]
pub(crate) enum FingerprintPollResponse {
    Waiting,
    Retry, // Add other types? Cf. https://fprint.freedesktop.org/libfprint-dev/FpDevice.html#FpDeviceRetry
    Completed,
    
    Start,
    UserCancelled,
}

pub(crate) fn start_device_discovery_fingerprint() -> Result<FingerprintRequest, ()> {
    println!("frontend: Start fingerprint discovery");
    Ok(FingerprintRequest { scan_type: FingerprintScanType::Touch, poll_count: 0 })
}

pub(crate) fn poll_device_discovery_fingerprint(request: &mut FingerprintRequest) -> Result<FingerprintPollResponse, ()> {
    request.poll_count += 1;
    if request.poll_count < 10 {
        Ok(FingerprintPollResponse::Waiting)
    } else if request.poll_count == 10 {
        println!("frontend: Got bad fingerprint scan");
        Ok(FingerprintPollResponse::Retry)
    } else if request.poll_count < 20 {
        Ok(FingerprintPollResponse::Waiting)
    } else {
        println!("frontend: Got successful fingerprint scan");
        Ok(FingerprintPollResponse::Completed)
    }
}

pub(crate) fn cancel_device_discovery_fingerprint(_request: &FingerprintRequest) -> Result<(), ()> {
    println!("frontend: Cancel fingerprint scan");
    Ok(())
}

#[derive(PartialEq)]
pub enum PasskeyProviderResponse {
    /// Waiting on response from passkey provider
    Waiting,

    /// Completed request from provider
    Completed,

    UserCancelled,
}

pub struct PasskeyProviderRequest {
    state: PasskeyProviderResponse,
    poll_count: i32,
}

pub(crate) fn start_device_discovery_passkey_provider() -> Result<PasskeyProviderRequest, ()> {
    println!("frontend: Start passkey provider discovery");
    // This should send a message to the passkey provider with a copy of the WebAuthn request options and a request object.
    // The passkey provider should open a window in response.
    Ok(PasskeyProviderRequest { state: PasskeyProviderResponse::Waiting, poll_count: 0 })
}

pub(crate) fn poll_device_discovery_passkey_provider(request: &mut PasskeyProviderRequest) -> Result<PasskeyProviderResponse, ()> {
    request.poll_count += 1;
    if request.poll_count < 20 {
        Ok(PasskeyProviderResponse::Waiting)
    } else {
        println!("frontend: Got credential from passkey provider");
        request.state = PasskeyProviderResponse::Completed;
        Ok(PasskeyProviderResponse::Completed)
    }
}

/// Called by the passkey provider to convey the credential the user chose to use.
pub(crate) fn select_device_discovery_passkey_provider(request: &mut PasskeyProviderRequest, credential: String) -> Result<(), ()> {
    request.state = PasskeyProviderResponse::Completed;
    Ok(())
}

pub(crate) fn cancel_device_discovery_passkey_provider(_request: &PasskeyProviderRequest) -> Result<(), ()> {
    // request.state = PasskeyProviderResponse::UserCancelled;
    println!("frontend: User cancelled passkey provider discovery");
    Ok(())
}