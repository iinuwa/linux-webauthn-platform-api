use std::borrow::Borrow;
use std::cell::RefCell;
use std::str::FromStr;

use gtk::gio;
use gtk::glib::subclass::InitializingObject;
use gtk::glib::{self, clone, Variant};
use gtk::prelude::*;
use gtk::subclass::prelude::*;
use gtk::{Button, CompositeTemplate};

use crate::portal::frontend::{self, Device};

#[derive(CompositeTemplate, Default)]
#[template(resource = "/xyz/iinuwa/CredentialManager/device_chooser.ui")]
pub struct DeviceChooser {
    transports: RefCell<Vec<Device>>,
}

#[glib::object_subclass]
impl ObjectSubclass for DeviceChooser {
    const NAME: &'static str = "CredentialManagerDeviceChooser";
    type Type = super::DeviceChooser;
    type ParentType = gtk::Box;

    fn class_init(klass: &mut Self::Class) {
        klass.bind_template();
        klass.bind_template_callbacks();
    }

    fn instance_init(obj: &InitializingObject<Self>) {
        obj.init_template();
    }
}

#[gtk::template_callbacks]
impl DeviceChooser {
    #[template_callback]
    fn handle_internal_authenticator_selected(button: &Button) {
        let target = Variant::from_str("'internal-authenticator-start'").expect("from_str to work");
        button
            .activate_action("navigation.push", Some(&target))
            .expect("The action to exist");
    }

    #[template_callback]
    fn handle_hybrid_qr_selected(button: &Button) {
        let target = Variant::from_str("'qr-start'").expect("from_str to work");
        button
            .activate_action("navigation.push", Some(&target))
            .expect("The action to exist");
    }

    #[template_callback]
    fn handle_hybrid_linked_device_selected(button: &Button) {
        let target = Variant::from_str("'linked-start'").expect("from_str to work");
        button
            .activate_action("navigation.push", Some(&target))
            .expect("The action to exist");
    }

    #[template_callback]
    fn handle_security_key_selected(button: &Button) {
        let target = Variant::from_str("'security-key-start'").expect("from_str to work");
        button
            .activate_action("navigation.push", Some(&target))
            .expect("The action to exist");
    }
}

impl ObjectImpl for DeviceChooser {
    fn constructed(&self) {
        // Call "constructed" on parent
        self.parent_constructed();

        // let obj = self.obj();
        // obj.setup_tasks();
        // obj.setup_callbacks();
        // obj.setup_factory();

        let transports = self.transports;
        glib::spawn_future_local(clone!(@weak transports =>  async move {
            transports.borrow() = frontend::get_available_devices().await;
        }));
    }
}

// Trait shared by all widgets
impl WidgetImpl for DeviceChooser {}

impl BoxImpl for DeviceChooser {}
