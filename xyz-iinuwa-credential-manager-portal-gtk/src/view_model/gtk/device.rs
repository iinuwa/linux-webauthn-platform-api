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
        let transport = match transport {
            Transport::Ble => "BLE",
            Transport::HybridLinked => "Hybrid",
            Transport::HybridQr => "Hybrid",
            Transport::Internal => "Internal",
            Transport::Nfc => "NFC",
            Transport::Usb => "USB",
        };
        Object::builder()
            .property("id", id)
            .property("transport", transport)
            .property("name", name)
            .build()
    }
}

/*
impl From<view_model::Device> for DeviceObject {
    fn from(value: view_model::Device) -> Self {
        Self::new(&value.id, &value.transport)
    }
}

impl From<&view_model::Device> for DeviceObject {
    fn from(value: &view_model::Device) -> Self {
        Self::new(&value.id, &value.transport)
    }
}
*/
