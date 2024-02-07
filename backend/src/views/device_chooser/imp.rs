use gtk::glib::subclass::InitializingObject;
use gtk::glib::{self, GString};
use gtk::prelude::*;
use gtk::subclass::prelude::*;
use gtk::{Button, CompositeTemplate};

#[derive(CompositeTemplate, Default)]
#[template(resource = "/xyz/iinuwa/CredentialManager/device_chooser.ui")]
pub struct DeviceChooser {}

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
    fn handle_device_selected(button: &Button) {
        let content = button
            .child()
            .expect("child to exist")
            .property::<GString>("label")
            .to_string();
        println!("{}", content);
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
    }
}

// Trait shared by all widgets
impl WidgetImpl for DeviceChooser {}

impl BoxImpl for DeviceChooser {}
