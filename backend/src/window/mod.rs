mod imp;

use std::str::FromStr;
use std::thread;
use std::time::Duration;

use adw::prelude::NavigationPageExt;
use adw::{Application, ButtonContent};
use adw::{NavigationPage, StatusPage};
use async_channel::{Receiver, Sender};
use gtk::gdk::Texture;
use gtk::gdk_pixbuf::Pixbuf;
use gtk::gio::{self, Cancellable, MemoryInputStream};
use gtk::glib::{self, clone, Bytes, Object, Variant};
use gtk::{prelude::*, StackPage, ToggleButton};
use gtk::subclass::prelude::*;
use gtk::{Box, Button, Label, Picture, Spinner};
use qrcode::render::svg;
use qrcode::QrCode;

use crate::portal::frontend::{
    self, cancel_device_discovery_fingerprint, cancel_device_discovery_hybrid, cancel_device_discovery_usb, get_available_platform_user_verification_methods, poll_device_discovery_fingerprint, poll_device_discovery_passkey_provider, poll_device_discovery_usb, start_device_discovery_fingerprint, start_device_discovery_hybrid, start_device_discovery_passkey_provider, start_device_discovery_usb, FingerprintPollResponse, FingerprintRequest, HybridPollResponse, PasskeyProviderResponse, UsbPollResponse, UserVerificationMethod
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

        let methods = self.imp()
            .internal_auth_switchers
            .get();
        let views = self.imp()
            .internal_auth_views
            .get();
        let pin_button = ToggleButton::builder()
            .icon_name("dialpad-symbolic")
            .css_classes(["large-icons"])
            .build();

        {
            let views = views.clone();
            pin_button.set_active(true);
            pin_button.connect_clicked(move |_| {
                let pin_view = views.child_by_name("pin").unwrap();
                views.set_visible_child(&pin_view);
            });
        }
        methods.append(&pin_button);

        let uv_methods = get_available_platform_user_verification_methods();
        if uv_methods.contains(&UserVerificationMethod::FingerprintInternal) {
            let fingerprint_button = ToggleButton::builder()
                .icon_name("fingerprint-symbolic")
                .css_classes(["large-icons"])
                .build();
            let (sender, receiver) = async_channel::bounded(2);
            let stack_page = self.imp()
                .fingerprint_stack_page
                .get();
            let fingerprint_view = stack_page.child();
            let fingerprint_view = fingerprint_view
                .downcast_ref::<Box>()
                .expect("child to be Box");
            start_fingerprint_flow(&fingerprint_view, sender.clone(), receiver);
            views.connect_notify(Some("visible-child"), move |w, _| {
                if let Some(name) = w.visible_child_name() {
                    if name.as_str() == "fingerprint" {
                        if !sender.is_closed() {
                            sender.send_blocking(FingerprintPollResponse::Start)
                            .expect("channel to be open");
                        }

                        

                    } else {
                        sender.send_blocking(FingerprintPollResponse::UserCancelled)
                        .expect("channel to be open");
                    }
                }
            });
            let views = views.clone();
            fingerprint_button.connect_clicked(move |_| {
                views.set_visible_child_name("fingerprint");
            });
            pin_button.set_group(Some(&fingerprint_button));
            methods.append(&fingerprint_button);
            methods.set_visible(true);
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
                DeviceTransport::PasskeyProvider => Some((
                    "symbolic-link-symbolic",
                    "ACME Password Manager",
                    None,
                    "'passkey-provider-start'",
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
                        "'internal-authenticator-start'" => {

                        },
                        "'qr-start'" => {
                            let picture = window.imp().qr_code_img.get();
                            start_qr_flow(&picture);
                        },
                        "'security-key-start'" => {
                            let usb_page = window.imp().usb_page.get();
                            start_usb_flow(&usb_page);
                        },
                        "'linked-start'" => {
                            // TODO: Maybe the hybrid ones can share a page
                            let linked_page = window.imp().linked_device_page.get();
                            start_linked_device_flow(&linked_page, name.clone());
                        },
                        "'passkey-provider-start'" => {
                            let provider_page = window.imp().provider_page.get();
                            start_provider_page_flow(&provider_page);
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
        .last_child()
        .expect("child to exist")
        .prev_sibling();
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
            if state == notification {
                continue;
            }
            if notification == UsbPollResponse::UserCancelled {
                sender.close();
                break;
            }
            sender
                .send_blocking(notification)
                .expect("The channel to be open");
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
                UsbPollResponse::NeedsPin => {
                    let entry = label.prev_sibling()
                        .expect("Sibling to exist");
                    entry.set_visible(true);
                    label.set_label("Enter your device pin");
                    let spinner = label.next_sibling()
                        .expect("Sibling to exist");
                    spinner.downcast_ref::<Spinner>()
                        .expect("sibling to be Spinner")
                        .set_spinning(false);
                    spinner.set_visible(false);
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

fn start_fingerprint_flow(container: &Box, sender: Sender<FingerprintPollResponse>, receiver: Receiver<FingerprintPollResponse>) {
    // TODO: This is broken (cannot start the flow more than once), but this
    // will be fixed in the real implementation.
    let mut request: Option<FingerprintRequest> = None;
    glib::spawn_future_local(clone!(@weak container => async move {
        let status_page = container
            .first_child()
            .expect("child to exist");
        let status_page = status_page
            .downcast_ref::<StatusPage>()
            .expect("sibling to be Label");
        while let Ok(notification) = receiver.recv().await {
            if receiver.is_closed() {
                break;
            }
            let sender = sender.clone();
            match notification {
                FingerprintPollResponse::Start => {
                    status_page.set_description(Some("Touch fingerprint"));
                    let spinner = status_page.next_sibling().expect("Sibling to exist");
                    spinner
                        .downcast_ref::<Spinner>()
                        .expect("sibling to be Spinner")
                        .set_spinning(true);
                    spinner.set_visible(true);
                    request = Some(start_device_discovery_fingerprint().unwrap());
                    gio::spawn_blocking(move || {
                        let sender = sender;
                        let mut state = FingerprintPollResponse::Waiting;
                        while let Ok(notification) = poll_device_discovery_fingerprint(&mut request.unwrap()) {
                            if sender.is_closed() {
                                break;
                            }
                            match (state, notification.clone()) {
                                (FingerprintPollResponse::Waiting, FingerprintPollResponse::Retry) => {
                                    sender
                                        .send_blocking(notification.clone())
                                        .expect("The channel to be open");
                                },
                                (FingerprintPollResponse::Retry, FingerprintPollResponse::Waiting) => {
                                    sender
                                        .send_blocking(notification.clone())
                                        .expect("The channel to be open");
                                },
                                (_, FingerprintPollResponse::Completed) => {
                                    sender
                                        .send_blocking(notification.clone())
                                        .expect("The channel to be open");
                                },
                                (_, FingerprintPollResponse::UserCancelled) => {
                                    // sender.close();
                                    break;
                                },
                                _ => {}
                            }
                            state = notification;

                            thread::sleep(Duration::from_millis(500));
                        }
                    });
                },
                FingerprintPollResponse::UserCancelled => {
                    println!("backend: Cancelled fingerprint flow");
                    status_page.set_description(None);
                    // let spinner = status_page.next_sibling()
                    //     .expect("Sibling to exist");
                    // spinner.set_visible(false);
                    // receiver.close();
                    cancel_device_discovery_fingerprint(&request.unwrap()).unwrap();
                    break;
                }
                FingerprintPollResponse::Retry => {
                    status_page.set_description(Some("Fingerprint not read, try again."));
                    let spinner = status_page.next_sibling()
                        .expect("Sibling to exist");
                    spinner.downcast_ref::<Spinner>()
                        .expect("sibling to be Spinner")
                        .set_spinning(true);
                    spinner.set_visible(true);
                },
                FingerprintPollResponse::Completed => {
                    println!("backend: Got credential!");
                    status_page
                        .activate_action("navigation.push", Some(&"finish".into()))
                        .expect("navigation.push action to exist");
                }
                _ => {},
            }
        }
    }));
}

fn start_provider_page_flow(provider_page: &NavigationPage) {
    let mut request = start_device_discovery_passkey_provider().unwrap();
    let (sender, receiver) = async_channel::bounded(1);
    glib::spawn_future_local(clone!(@weak provider_page => async move {
        while let Ok(notification) = receiver.recv().await {
            if notification == PasskeyProviderResponse::Completed {
                provider_page
                    .activate_action("navigation.push", Some(&"finish".into()))
                    .expect("navigation.push action to exist");
                break;
            }
        }
    }));
    gio::spawn_blocking(move || {
        let mut state = PasskeyProviderResponse::Waiting;
        let sender = sender.clone();
        while let Ok(notification) = poll_device_discovery_passkey_provider(&mut request) {
            if state == notification {
            } else if notification == PasskeyProviderResponse::Completed {
                sender.send_blocking(notification)
                    .expect("channel to be open");
                break;
            }
            state = notification;

            thread::sleep(Duration::from_millis(500));
        }
    });
}