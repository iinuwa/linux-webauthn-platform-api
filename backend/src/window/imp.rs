use std::cell::RefCell;

use adw::NavigationPage;
use gtk::{glib, Picture};
use gtk::glib::subclass::InitializingObject;
use gtk::prelude::*;
use gtk::subclass::prelude::*;
use gtk::{Button, CompositeTemplate};

use crate::portal::frontend::Device;
use crate::views::device_chooser::DeviceChooser;

#[derive(CompositeTemplate, Default)]
#[template(resource = "/xyz/iinuwa/CredentialManager/window.ui")]
pub struct Window {
    #[template_child]
    pub cancel_button: TemplateChild<Button>,

    #[template_child]
    pub device_chooser: TemplateChild<DeviceChooser>,

    #[template_child]
    pub qr_page: TemplateChild<NavigationPage>,

    #[template_child]
    pub qr_code_img: TemplateChild<Picture>,

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
