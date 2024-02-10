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
use gtk::prelude::*;
use gtk::subclass::prelude::*;
use gtk::{Box, Button, Label, Picture, Spinner};
use qrcode::render::svg;
use qrcode::QrCode;

use crate::portal::frontend::{
    self, cancel_device_discovery_hybrid, cancel_device_discovery_usb, poll_device_discovery_usb,
    start_device_discovery_hybrid, start_device_discovery_usb, HybridPollResponse, UsbPollResponse,
};
use crate::portal::frontend::{poll_device_discovery_hybrid, DeviceTransport};

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

                let name = name.unwrap_or("").to_owned();
                let button = Button::builder().child(&content).build();
                button.connect_clicked(clone!(@weak self as window => move |button| {
                    let t = Variant::from_str(target).expect("from_str to work");
                    match target {
                        "'internal-authenticator-start'" => {},
                        "'qr-start'" => {
                            let picture = window.imp().qr_code_img.get();
                            start_qr_flow(&picture);
                        },
                        "'security-key-start'" => {
                            let usb_page = window.imp().usb_page.get();
                            start_usb_flow(&usb_page);
                        }
                        "'linked-start'" => {
                            // TODO: Maybe the hybrid ones can share a page
                            let linked_page = window.imp().linked_device_page.get();
                            start_linked_device_flow(&linked_page, name.clone());
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

fn start_qr_flow(picture: &Picture) {
    let (mut request, qr_data) = start_device_discovery_hybrid(None).unwrap();
    if let Some(qr_data) = qr_data {
        let qr_code = QrCode::new(qr_data).expect("QR code to be valid");
        let svg_xml = qr_code.render::<svg::Color>().build();
        let stream = MemoryInputStream::from_bytes(&Bytes::from(svg_xml.as_bytes()));
        let pixbuf = Pixbuf::from_stream_at_scale(&stream, 450, 450, true, None::<&Cancellable>)
            .expect("SVG to render");
        let texture = Texture::for_pixbuf(&pixbuf);
        picture.set_paintable(Some(&texture));
    } else {
        // TODO: Error handling
        println!("backend: Failed to get QR data to start flow");
        return;
    }

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
                s1.send_blocking(HybridPollResponse::UserCancelled)
                    .expect("channel to be open");
                cancel_device_discovery_hybrid(&request);
            }
        });
    gio::spawn_blocking(move || {
        let mut state = HybridPollResponse::Waiting;
        while let Ok(notification) = poll_device_discovery_hybrid(&mut request) {
            if sender.is_closed() {
                break;
            }
            match (state, notification) {
                (HybridPollResponse::Waiting, HybridPollResponse::Connecting) => {
                    sender
                        .send_blocking(notification)
                        .expect("The channel to be open");
                }
                (_, HybridPollResponse::Completed) => {
                    sender
                        .send_blocking(notification)
                        .expect("The channel to be open");
                }
                (_, HybridPollResponse::UserCancelled) => {
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
                HybridPollResponse::UserCancelled => {
                    println!("backend: Cancelled hybrid flow");
                    picture.set_paintable(None::<&Texture>);
                    picture.next_sibling()
                        .expect("Sibling to exist")
                        .set_visible(false);
                    receiver.close();
                    break;
                }
                HybridPollResponse::Connecting => {
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
                HybridPollResponse::Completed => {
                    println!("backend: Got credential!");
                    picture
                        .activate_action("navigation.push", Some(&"finish".into()))
                        .expect("navigation.push action to exist");
                }
                _ => {},
            }
        }
    }));
}

fn start_linked_device_flow(page: &NavigationPage, device: String) {
    // This is almost exactly the same as hybrid, except we send a device selection and don't display the QR code.
    let b = page.child();
    let container = b.and_downcast_ref::<Box>().expect("child to be box");
    let label = container
        .first_child()
        .expect("child to exist")
        .next_sibling();
    let label = label
        .and_downcast_ref::<Label>()
        .expect("sibling to be Label");
    label.set_text(format!("Connecting to your `{}` device", device).as_str());
    let spinner = label.next_sibling().expect("Sibling to exist");
    spinner
        .downcast_ref::<Spinner>()
        .expect("sibling to be Spinner")
        .set_spinning(true);
    spinner.set_visible(true);

    let (mut request, _) = start_device_discovery_hybrid(Some(device.to_string())).unwrap();
    let (sender, receiver) = async_channel::bounded(2);
    let s1 = sender.clone();
    page.connect_hiding(move |_| {
        if !s1.is_closed() {
            s1.send_blocking(HybridPollResponse::UserCancelled)
                .expect("channel to be open");
            cancel_device_discovery_hybrid(&request);
        }
    });
    gio::spawn_blocking(move || {
        let mut state = HybridPollResponse::Connecting;
        while let Ok(notification) = poll_device_discovery_hybrid(&mut request) {
            if sender.is_closed() {
                break;
            }
            match (state, notification) {
                (HybridPollResponse::Waiting, HybridPollResponse::Connecting) => {
                    sender
                        .send_blocking(notification)
                        .expect("The channel to be open");
                }
                (_, HybridPollResponse::Completed) => {
                    sender
                        .send_blocking(notification)
                        .expect("The channel to be open");
                }
                (_, HybridPollResponse::UserCancelled) => {
                    sender.close();
                    break;
                }
                _ => {}
            }
            state = notification;

            thread::sleep(Duration::from_millis(500));
        }
    });

    glib::spawn_future_local(
        clone!(@weak page, @weak label, @weak spinner => async move {
            while let Ok(notification) = receiver.recv().await {
                if receiver.is_closed() {
                    break;
                }
                match notification {
                    HybridPollResponse::UserCancelled => {
                        println!("backend: Cancelled hybrid flow");
                        label.set_label("");
                        spinner.set_visible(false);
                        receiver.close();
                        break;
                    }
                    HybridPollResponse::Completed => {
                        println!("backend: Got credential!");
                        page
                            .activate_action("navigation.push", Some(&"finish".into()))
                            .expect("navigation.push action to exist");
                    }
                    _ => {},
                }
            }
        }),
    );
}

fn start_usb_flow(page: &NavigationPage) {
    let b = page.child();
    let container = b.and_downcast_ref::<Box>().expect("child to be box");
    let label = container
        .first_child()
        .expect("child to exist")
        .next_sibling();
    let label = label
        .and_downcast_ref::<Label>()
        .expect("sibling to be Label");
    label.set_text("Insert your security key");
    let spinner = label.next_sibling().expect("Sibling to exist");
    spinner
        .downcast_ref::<Spinner>()
        .expect("sibling to be Spinner")
        .set_spinning(true);
    spinner.set_visible(true);

    let mut request = start_device_discovery_usb().unwrap();
    let (sender, receiver) = async_channel::bounded(2);
    let s1 = sender.clone();
    page.connect_hiding(move |_| {
        if !s1.is_closed() {
            s1.send_blocking(UsbPollResponse::UserCancelled)
                .expect("channel to be open");
            cancel_device_discovery_usb(&request);
        }
    });
    gio::spawn_blocking(move || {
        let mut state = UsbPollResponse::Waiting;
        while let Ok(notification) = poll_device_discovery_usb(&mut request) {
            if sender.is_closed() {
                break;
            }
            match (state, notification) {
                (UsbPollResponse::Waiting, UsbPollResponse::Connected) => {
                    sender
                        .send_blocking(notification)
                        .expect("The channel to be open");
                }
                (_, UsbPollResponse::Completed) => {
                    sender
                        .send_blocking(notification)
                        .expect("The channel to be open");
                }
                (_, UsbPollResponse::UserCancelled) => {
                    sender.close();
                    break;
                }
                _ => {}
            }
            state = notification;

            thread::sleep(Duration::from_millis(500));
        }
    });

    glib::spawn_future_local(clone!(@weak label => async move {
        while let Ok(notification) = receiver.recv().await {
            if receiver.is_closed() {
                break;
            }
            match notification {
                UsbPollResponse::UserCancelled => {
                    println!("backend: Cancelled USB key flow");
                    label.set_label("");
                    let spinner = label.next_sibling()
                        .expect("Sibling to exist");
                    spinner.set_visible(false);
                    receiver.close();
                    break;
                }
                UsbPollResponse::Connected => {
                    label.set_label("Press your device to release the credential");
                    let spinner = label.next_sibling()
                        .expect("Sibling to exist");
                    spinner.downcast_ref::<Spinner>()
                        .expect("sibling to be Spinner")
                        .set_spinning(true);
                    spinner.set_visible(true);
                },
                UsbPollResponse::Completed => {
                    println!("backend: Got credential!");
                    label
                        .activate_action("navigation.push", Some(&"finish".into()))
                        .expect("navigation.push action to exist");
                }
                _ => {},
            }
        }
    }));
}
