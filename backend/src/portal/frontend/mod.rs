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

/// Returns string of "FIDO:/...", which should be QR-encoded and displayed to the user.
pub(crate) fn start_device_discovery_hybrid_qr() -> Result<String, ()> {
    return Ok(String::from("FIDO:/078241338926040702789239694720083010994762289662861130514766991835876383562063181103169246410435938367110394959927031730060360967994421343201235185697538107096654083332"));
}
