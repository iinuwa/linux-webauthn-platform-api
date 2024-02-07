mod imp;

use gtk::glib;
use gtk::glib::Object;

glib::wrapper! {
    pub struct DeviceChooser(ObjectSubclass<imp::DeviceChooser>)
    @extends gtk::Box, gtk::Widget,
    @implements gtk::Accessible, gtk::Buildable, gtk::ConstraintTarget, gtk::Orientable;

}

impl DeviceChooser {
    pub fn new() -> Self {
        Object::new()
    }
}

impl Default for DeviceChooser {
    fn default() -> Self {
        Self::new()
    }
}
