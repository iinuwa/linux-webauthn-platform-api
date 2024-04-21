use std::cell::RefCell;

use gtk::glib;
use glib::Object;
use gtk::prelude::*;
use gtk::subclass::prelude::*;

use crate::view_model::Transport;

mod imp {
    use super::*;

    #[derive(glib::Properties, Default)]
    #[properties(wrapper_type = super::DeviceObject)]
    pub struct DeviceObject {
        #[property(get, set)]
        pub id: RefCell<String>,

        #[property(get, set)]
        pub transport: RefCell<String>,

        #[property(get, set)]
        pub name: RefCell<String>,
    }

    // The central trait for subclassing a GObject
    #[glib::object_subclass]
    impl ObjectSubclass for DeviceObject {
        const NAME: &'static str = "CredentialManagerDevice";
        type Type = super::DeviceObject;
    }

    // Trait shared by all GObjects
    #[glib::derived_properties]
    impl ObjectImpl for DeviceObject {}
}

glib::wrapper! {
    pub struct DeviceObject(ObjectSubclass<imp::DeviceObject>);
}

impl DeviceObject {
    pub fn new(id: &str, transport: &Transport, name: &str) -> Self {//, label: &str, icon_name: &str) -> Self {
        let transport = transport.as_str();
        Object::builder()
            .property("id", id)
            .property("transport", transport)
            .property("name", name)
            .build()
    }
}

fn transport_name(transport: &Transport) -> &'static str {
    match transport {
        Transport::Ble => "A Bluetooth device",
        Transport::Internal => "This device",
        Transport::HybridQr => "A mobile device",
        Transport::HybridLinked => "TODO: Linked Device",
        Transport::Nfc => "An NFC device",
        Transport::Usb => "A security key",
        // Transport::PasskeyProvider => ("symbolic-link-symbolic", "ACME Password Manager"),
    }
}
impl From<crate::view_model::Device> for DeviceObject {
    fn from(value: crate::view_model::Device) -> Self {
        let name = transport_name(&value.transport);
        Self::new(&value.id, &value.transport, name)
    }
}

impl From<&crate::view_model::Device> for DeviceObject {
    fn from(value: &crate::view_model::Device) -> Self {
        let name = transport_name(&value.transport);
        Self::new(&value.id, &value.transport, name)
    }
}
