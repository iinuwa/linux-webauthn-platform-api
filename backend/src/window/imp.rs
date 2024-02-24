use std::cell::RefCell;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use adw::{NavigationPage, PasswordEntryRow};
use gtk::{gio, StackPage};
use gtk::glib;
use gtk::glib::clone;
use gtk::glib::subclass::InitializingObject;
use gtk::prelude::*;
use gtk::subclass::prelude::*;
use gtk::{Box, Button, CompositeTemplate, Label, Picture, Stack};

use crate::portal::frontend::{validate_device_pin, Device, PinResponse};
use crate::views::device_chooser::DeviceChooser;

#[derive(CompositeTemplate, Default)]
#[template(resource = "/xyz/iinuwa/CredentialManager/window.ui")]
pub struct Window {
    #[template_child]
    pub cancel_button: TemplateChild<Button>,

    #[template_child]
    pub device_chooser: TemplateChild<DeviceChooser>,

    #[template_child]
    pub internal_auth_switchers: TemplateChild<Box>,

    #[template_child]
    pub internal_auth_views: TemplateChild<Stack>,

    #[template_child]
    pub internal_authenticator_page: TemplateChild<NavigationPage>,

    #[template_child]
    pub fingerprint_stack_page: TemplateChild<StackPage>,

    #[template_child]
    pub linked_device_page: TemplateChild<NavigationPage>,

    #[template_child]
    pub qr_page: TemplateChild<NavigationPage>,

    #[template_child]
    pub qr_code_img: TemplateChild<Picture>,

    #[template_child]
    pub usb_page: TemplateChild<NavigationPage>,

    pub(crate) devices: RefCell<Vec<Device>>,
}

#[gtk::template_callbacks]
impl Window {
    #[template_callback]
    fn handle_cancel_button_clicked(button: &Button) {
        button
            .activate_action("window.close", None)
            .expect("window to close");
    }

    #[template_callback]
    fn handle_finish_page_shown(page: &NavigationPage) {
        glib::spawn_future_local(clone!(@weak page => async move {
            gio::spawn_blocking(move || {
                thread::sleep(Duration::from_secs(1));
            }).await
            .expect("the Task to finish successfully");
            page.activate_action("window.close", None).unwrap();
        }));
    }

    #[template_callback]
    fn handle_device_pin_activated(entry: &PasswordEntryRow) {
        let text = entry.text();
        let pin = text.as_str();
        let now = SystemTime::now();
        if let Ok(pin_response) = validate_device_pin(pin) {
            match pin_response {
                PinResponse::Correct => {
                    entry
                        .activate_action("navigation.push", Some(&"finish".into()))
                        .expect("navigation.push action to exist.");
                }
                PinResponse::Incorrect(attempts_left) => {
                    let label = entry.next_sibling();
                    let label = label
                        .and_downcast_ref::<Label>()
                        .expect("sibling to be a label");
                    if attempts_left <= 3 {
                        label.set_label(
                            format!("PIN incorrect. {attempts_left} attempt(s) left until lockout")
                                .as_str(),
                        );
                    } else {
                        label.set_label("PIN incorrect.")
                    }
                }
                PinResponse::Locked(lockout_time) => {
                    entry.set_editable(false);
                    glib::spawn_future_local(clone!(@weak entry => async move {
                        let lockout_duration = lockout_time - now.duration_since(UNIX_EPOCH).unwrap();
                        // TODO: Add cancellation
                        glib::timeout_future(lockout_duration).await;
                        entry.set_editable(true);
                        entry
                            .next_sibling()
                            .and_downcast_ref::<Label>()
                            .expect("sibling to be a label")
                            .set_label(format!("Device locked out. Try again in {} seconds", lockout_duration.as_secs()).as_str());
                    }));
                }
            }
        }
    }
}

#[glib::object_subclass]
impl ObjectSubclass for Window {
    const NAME: &'static str = "CredentialManagerWindow";
    type Type = super::Window;
    type ParentType = gtk::ApplicationWindow;

    fn class_init(klass: &mut Self::Class) {
        klass.bind_template();
        klass.bind_template_callbacks();
    }

    fn instance_init(obj: &InitializingObject<Self>) {
        obj.init_template();
    }
}

impl ObjectImpl for Window {
    fn constructed(&self) {
        // Call "constructed" on parent
        self.parent_constructed();

        let obj = self.obj();
        obj.setup_devices();
    }
}

// Trait shared by all widgets
impl WidgetImpl for Window {}

// Trait shared by all windows
impl WindowImpl for Window {}

// Trait shared by all application windows
impl ApplicationWindowImpl for Window {}
