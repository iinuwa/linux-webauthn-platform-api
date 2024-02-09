mod imp;

use std::str::FromStr;

use adw::prelude::NavigationPageExt;
use adw::StatusPage;
use adw::{Application, ButtonContent};
use gtk::gdk::Texture;
use gtk::gdk_pixbuf::Pixbuf;
use gtk::gio::{self, Cancellable, MemoryInputStream};
use gtk::glib::{self, clone, Bytes, Object, Variant};
use gtk::prelude::*;
use gtk::subclass::prelude::*;
use gtk::Picture;
use gtk::{Box, Button};
use qrcode::render::svg;
use qrcode::QrCode;

use crate::portal::frontend::DeviceTransport;
use crate::portal::frontend::{self, start_device_discovery_hybrid_qr};

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
        let container = self.imp().device_chooser.get();
        if let Ok(available_devices) = frontend::get_available_public_key_devices() {
            (*devices).extend(available_devices);
        } else {
            let widget = StatusPage::builder()
                .icon_name("dialog-error-symbolic")
                .title("There was an error loading devices.")
                .build();
            container.append(&widget);
            return;
        }

        for device in (*devices).iter() {
            if let Some((icon_name, label, name, target)) = match &device.transport {
                DeviceTransport::Internal => Some((
                    "computer-symbolic",
                    "This device",
                    None::<&str>,
                    "'internal-authenticator-start'",
                )),
                DeviceTransport::HybridQr => {
                    Some(("phone-symbolic", "A mobile device", None, "'qr-start'"))
                }
                DeviceTransport::HybridLinked(name) => Some((
                    "phone-symbolic",
                    name.as_ref(),
                    Some(name.as_ref()),
                    "'linked-start'",
                )),
                DeviceTransport::Usb => Some((
                    "media-removable-symbolic",
                    "A security key",
                    None,
                    "'security-key-start'",
                )),
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

                let button = Button::builder().child(&content).build();
                button.connect_clicked(clone!(@weak self as window => move |button| {
                    let t = Variant::from_str(target).expect("from_str to work");
                    match target {
                        "'qr-start'" => {
                            let picture = window.imp().qr_code_img.get();
                            init_qr_start(&picture);
                        },
                        _ => {},
                    }
                    button.activate_action("navigation.push", Some(&t))
                        .expect("navigation.push action to exist");
                }));
                container.append(&button);
            }
        }
    }

}

fn init_qr_start(picture: &Picture) {
    let qr_data = start_device_discovery_hybrid_qr().unwrap_or(String::from("Could not show QR code"));
    let qr_code = QrCode::new(qr_data).expect("QR code to be valid");
    let svg_xml = qr_code.render::<svg::Color>().build();
    let stream = MemoryInputStream::from_bytes(&Bytes::from(svg_xml.as_bytes()));
    let pixbuf = Pixbuf::from_stream_at_scale(&stream, 450, 450, true, None::<&Cancellable>).expect("SVG to render");
    let texture = Texture::for_pixbuf(&pixbuf);
    picture.set_paintable(Some(&texture));
}