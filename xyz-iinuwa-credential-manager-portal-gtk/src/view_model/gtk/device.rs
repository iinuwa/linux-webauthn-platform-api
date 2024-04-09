use std::cell::Cell;

use gtk::glib;
use glib::{Object, Properties};
use gtk::prelude::*;
use gtk::subclass::prelude::*;

use crate::view_model;

mod imp {
    use super::*;

    #[derive(Properties, Default)]
    #[properties(wrapper_type = super::Device)]
    pub struct Device {
        #[property(get, set)]
        device: RefCell<view_model::Device>,
    }

    // The central trait for subclassing a GObject
    #[glib::object_subclass]
    impl ObjectSubclass for Device {
        const NAME: &'static str = "CredentialManagerDevice";
        type Type = super::Device;
    }

    // Trait shared by all GObjects
    #[glib::derived_properties]
    impl ObjectImpl for Device {}
}

glib::wrapper! {
    pub struct Device(ObjectSubclass<imp::Device>);
}

impl Device {
    pub fn new(device: view_model::Device) -> Self {
        Object::builder().property("device", device).build()
    }
}
