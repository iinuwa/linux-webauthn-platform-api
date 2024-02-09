use std::{thread, time::Duration};

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
    ])
}

#[derive(Clone, Copy)]
pub(crate) struct HybridQrRequest {
    poll_count: i32,
    state: HybridQrPollResponse,
}

/// Returns string of "FIDO:/...", which should be QR-encoded and displayed to the user.
pub(crate) fn start_device_discovery_hybrid_qr() -> Result<(HybridQrRequest, String), ()> {
    println!("frontend: Start QR hybrid flow");
    Ok((HybridQrRequest{ poll_count: 0, state: HybridQrPollResponse::Waiting }, String::from("FIDO:/078241338926040702789239694720083010994762289662861130514766991835876383562063181103169246410435938367110394959927031730060360967994421343201235185697538107096654083332")))
}

// TODO: I don't know if it's better to design this API for the backend to
// subscribe to frontend notifications, or for the frontend to poll the backend.
// Polling is simpler.

#[derive(Copy, Clone)]
pub enum HybridQrPollResponse {
    /// Awaiting BLE advert from phone.
    Waiting,
    ///
    Connecting,
    /// Connected
    // I don't think is necessary to signal
    // Connected.
    Completed,

    // This isn't actually sent from the server.
    UserCancelled,
}

/// Poll for notificactions
pub(crate) fn poll_device_discovery_hybrid_qr(
    request: &mut HybridQrRequest,
) -> Result<HybridQrPollResponse, ()> {
    thread::sleep(Duration::from_millis(25));
    if request.poll_count < 0 {
        return Err(());
    }

    request.poll_count += 1;
    if request.poll_count < 10 {
        request.state = HybridQrPollResponse::Waiting;
    } else if request.poll_count < 20 {
        if let HybridQrPollResponse::Connecting = request.state {
        } else {
            println!("frontend: Received BLE advert from mobile device");
        }
        request.state = HybridQrPollResponse::Connecting
    } else if request.poll_count < 30 {
        // if let HybridQrPollResponse::Connected = request.state {
        if let HybridQrPollResponse::Connecting = request.state {
        } else {
            println!("frontend: Connected to caBLE tunnel for mobile device");
        }
        // request.state = HybridQrPollResponse::Connected;
        request.state = HybridQrPollResponse::Connecting;
    } else {
        if let HybridQrPollResponse::Completed = request.state {
        } else {
            println!("frontend: Received CTAP advert from mobile device");
        }
        request.poll_count = -1;
        request.state = HybridQrPollResponse::Completed;
    }
    Ok(request.state)
}

pub(crate) fn cancel_device_discovery_hybrid_qr(_request: &HybridQrRequest) {
    println!("frontend: Cancel Hybrid QR request")
}

#[derive(Clone, Copy)]
pub(crate) struct UsbRequest {
    poll_count: i32,
    state: UsbPollResponse,
}

#[derive(Copy, Clone)]
pub enum UsbPollResponse {
    /// Awaiting BLE advert from phone.
    Waiting,

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
