
use gtk::glib::subclass::InitializingObject;
use gtk::glib;
use gtk::subclass::prelude::*;
use gtk::{Box, CompositeTemplate};

#[derive(CompositeTemplate, Default)]
#[template(resource = "/xyz/iinuwa/CredentialManager/device_chooser.ui")]
pub struct DeviceChooser {
    #[template_child]
    pub device_container: TemplateChild<Box>,
}

#[glib::object_subclass]
impl ObjectSubclass for DeviceChooser {
    const NAME: &'static str = "CredentialManagerDeviceChooser";
    type Type = super::DeviceChooser;
    type ParentType = gtk::Box;

    fn class_init(klass: &mut Self::Class) {
        klass.bind_template();
    }

    fn instance_init(obj: &InitializingObject<Self>) {
        obj.init_template();
    }
}

impl ObjectImpl for DeviceChooser {
    fn constructed(&self) {
        // Call "constructed" on parent
        self.parent_constructed();
    }
}

// Trait shared by all widgets
impl WidgetImpl for DeviceChooser {}

impl BoxImpl for DeviceChooser {}
