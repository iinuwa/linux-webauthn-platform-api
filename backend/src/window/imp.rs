use gtk::glib;
use gtk::glib::subclass::InitializingObject;
use gtk::subclass::prelude::*;
use gtk::CompositeTemplate;

#[derive(CompositeTemplate, Default)]
#[template(resource = "/xyz/iinuwa/CredentialManager/window.ui")]
pub struct Window {}

#[glib::object_subclass]
impl ObjectSubclass for Window {
    const NAME: &'static str = "CredentialManagerWindow";
    type Type = super::Window;
    type ParentType = gtk::ApplicationWindow;

    fn class_init(klass: &mut Self::Class) {
        klass.bind_template();
        // klass.bind_template_callbacks();
    }

    fn instance_init(obj: &InitializingObject<Self>) {
        obj.init_template();
    }
}

impl ObjectImpl for Window {
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
impl WidgetImpl for Window {}

// Trait shared by all windows
impl WindowImpl for Window {}

// Trait shared by all application windows
impl ApplicationWindowImpl for Window {}
