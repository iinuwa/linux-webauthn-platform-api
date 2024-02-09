mod imp;

use std::str::FromStr;

use adw::{Application, ButtonContent};
use gtk::gio;
use gtk::glib;
use gtk::glib::Object;
use gtk::glib::Variant;
use gtk::prelude::*;
use gtk::subclass::prelude::*;
use gtk::Button;

use crate::portal::frontend;
use crate::portal::frontend::DeviceTransport;

glib::wrapper! {
    pub struct Window(ObjectSubclass<imp::Window>)
    @extends gtk::ApplicationWindow, gtk::Window, gtk::Widget,
    @implements gio::ActionGroup, gio::ActionMap, gtk::Accessible, gtk::Buildable,
                gtk::ConstraintTarget, gtk::Native, gtk::Root, gtk::ShortcutManager;

}

impl Window {
    pub fn new(app: &Application) -> Self {
        Object::builder().property("application", app).build()
    }

    pub fn setup_devices(&self) {
        let mut devices = self.imp().devices.borrow_mut();
        (*devices).extend(frontend::get_available_public_key_devices());
        let container = self.imp()
            .device_chooser
            .get();

        for device in (*devices).iter() {
            if let Some((icon_name, label, name, target)) = match &device.transport {
                DeviceTransport::Internal => Some(("computer-symbolic", "This device", None::<&str>, "'internal-authenticator-start'")),
                DeviceTransport::HybridQr => Some(("phone-symbolic", "A mobile device", None, "'qr-start'")),
                DeviceTransport::HybridLinked(name) => Some(("phone-symbolic", name.as_ref(), Some(name.as_ref()), "'linked-start'")),
                DeviceTransport::USB => Some(("media-removable-symbolic", "A security key", None, "'security-key-start'")),
                _ => None,
            } {
                let content = if let Some(name) = name {
                    ButtonContent::builder()
                        .icon_name(icon_name)
                        .label(label)
                        .name(name)
                        .build()
                } else {
                    ButtonContent::builder()
                        .icon_name(icon_name)
                        .label(label)
                        .build()
                };

                let button = Button::builder()
                    .child(&content)
                    .build();
                button.connect_clicked(move |button| {
                    let target = Variant::from_str(target).expect("from_str to work");
                    button.activate_action("navigation.push", Some(&target))
                        .expect("navigation.push action to exist");
                });
                container.append(&button);
            }
        }
    }
}
