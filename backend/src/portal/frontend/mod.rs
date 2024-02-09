use std::{thread, time::Duration};

// TODO: Do we need a separate device, or just the transport?
pub(crate) struct Device {
    pub id: String,
    pub transport: DeviceTransport,
}

pub(crate) enum DeviceTransport {
    BLE,
    HybridLinked(String),
    HybridQr,
    Internal,
    NFC,
    USB,
}

/// Enumerate devices that the frontend can support.
pub(crate) /* TODO async */ fn get_available_public_key_devices() -> Vec<Device> {
    // Simulate D-Bus latency
    thread::sleep(Duration::from_millis(15));
    // TODO: do we need some sort of order hints? Like last used, or preferred (based on requested transports from the request?)
    vec![
        Device { id: String::from("1"), transport: DeviceTransport::Internal },
        Device { id: String::from("2"), transport: DeviceTransport::HybridQr },
        Device { id: String::from("3"), transport: DeviceTransport::HybridLinked(String::from("Pixel 7")) },
        Device { id: String::from("4"), transport: DeviceTransport::USB },
    ]
}