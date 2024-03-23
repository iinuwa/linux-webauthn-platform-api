use gtk::glib;

use gtk::prelude::*;
use gtk::subclass::prelude::*;



mod imp {
    use std::cell::RefCell;

    use super::*;

    #[derive(Debug, Default, glib::Properties)]
    #[properties(wrapper_type = super::ViewModel)]
    pub struct ViewModel {
        #[property(get, set)]
        pub title: RefCell<String>,
        // hybrid_qr_state: HybridState,
        // hybrid_qr_code_data: Option<Vec<u8>>,
    }

    // The central trait for subclassing a GObject
    #[glib::object_subclass]
    impl ObjectSubclass for ViewModel {
        const NAME: &'static str = "CredentialManagerViewModel";
        type Type = super::ViewModel;
    }

    // Trait shared by all GObjects
    #[glib::derived_properties]
    impl ObjectImpl for ViewModel {}
}

glib::wrapper! {
    pub struct ViewModel(ObjectSubclass<imp::ViewModel>);
}

impl ViewModel {
    pub fn new(title: &str) -> Self {
        glib::Object::builder().property("title", title).build()
    }
}

impl Default for ViewModel {
    fn default() -> Self {
        Self::new("")
    }
}
