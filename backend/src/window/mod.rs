mod imp;

use std::str::FromStr;
use std::thread;
use std::time::Duration;

use adw::prelude::NavigationPageExt;
use adw::{Application, ButtonContent};
use adw::{NavigationPage, StatusPage};
use gtk::gdk::Texture;
use gtk::gdk_pixbuf::Pixbuf;
use gtk::gio::{self, Cancellable, MemoryInputStream};
use gtk::glib::{self, clone, Bytes, Object, Variant};
use gtk::subclass::prelude::*;
use gtk::Button;
use gtk::Picture;
use gtk::{prelude::*, Label, Spinner};
use qrcode::render::svg;
use qrcode::QrCode;

use crate::portal::frontend::{
    self, cancel_device_discovery_hybrid_qr, start_device_discovery_hybrid_qr, HybridQrPollResponse,
};
use crate::portal::frontend::{poll_device_discovery_hybrid_qr, DeviceTransport};

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
                    // let receiver = window.imp().backend_notifications.borrow().as_ref().expect("receiver to be set up").clone();
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
    let (mut request, qr_data) = start_device_discovery_hybrid_qr().unwrap();
    let qr_code = QrCode::new(qr_data).expect("QR code to be valid");
    let svg_xml = qr_code.render::<svg::Color>().build();
    let stream = MemoryInputStream::from_bytes(&Bytes::from(svg_xml.as_bytes()));
    let pixbuf = Pixbuf::from_stream_at_scale(&stream, 450, 450, true, None::<&Cancellable>)
        .expect("SVG to render");
    let texture = Texture::for_pixbuf(&pixbuf);
    picture.set_paintable(Some(&texture));
    picture
        .prev_sibling()
        .and_downcast_ref::<Label>()
        .expect("sibling to be label")
        .set_label("Scan the QR code below with your mobile device");
    let (sender, receiver) = async_channel::bounded(2);
    let s1 = sender.clone();
    picture
        .parent()
        .and_then(|b| b.parent())
        .and_downcast_ref::<NavigationPage>()
        .expect("parent to be a NavigationPage")
        .connect_hiding(move |_| {
            if !s1.is_closed() {
                s1.send_blocking(HybridQrPollResponse::UserCancelled)
                    .expect("channel to be open");
                cancel_device_discovery_hybrid_qr(&request);
            }
        });
    gio::spawn_blocking(move || {
        let mut state = HybridQrPollResponse::Waiting;
        while let Ok(notification) = poll_device_discovery_hybrid_qr(&mut request) {
            if sender.is_closed() {
                break;
            }
            match (state, notification) {
                (HybridQrPollResponse::Waiting, HybridQrPollResponse::Connecting) => {
                    sender
                        .send_blocking(notification)
                        .expect("The channel to be open");
                }
                (_, HybridQrPollResponse::Completed) => {
                    sender
                        .send_blocking(notification)
                        .expect("The channel to be open");
                }
                (_, HybridQrPollResponse::UserCancelled) => {
                    sender.close();
                    break;
                }
                _ => {}
            }
            state = notification;

            thread::sleep(Duration::from_millis(500));
        }
    });

    glib::spawn_future_local(clone!(@weak picture => async move {
        while let Ok(notification) = receiver.recv().await {
            if receiver.is_closed() {
                break;
            }
            match notification {
                HybridQrPollResponse::UserCancelled => {
                    println!("backend: Cancelled QR code");
                    picture.set_paintable(None::<&Texture>);
                    picture.next_sibling()
                        .expect("Sibling to exist")
                        .set_visible(false);
                    receiver.close();
                    break;
                }
                HybridQrPollResponse::Connecting => {
                    picture.set_paintable(None::<&Texture>);
                    picture
                        .prev_sibling()
                        .and_downcast_ref::<Label>()
                        .expect("sibling to be label")
                        .set_label("Connecting to your device...");
                    let spinner = picture.next_sibling()
                        .expect("Sibling to exist");
                    spinner.downcast_ref::<Spinner>()
                        .expect("sibling to be Spinner")
                        .set_spinning(true);
                    spinner.set_visible(true);
                },
                HybridQrPollResponse::Completed => {
                    println!("backend: Got credential!");
                    picture.activate_action("window.close", None).expect("Window to close");
                }
                _ => {},
            }
        }
    }));
}
