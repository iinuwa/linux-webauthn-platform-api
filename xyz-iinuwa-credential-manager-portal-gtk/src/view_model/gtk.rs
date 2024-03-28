use async_std::channel::{Receiver, Sender};
use gtk::glib;
use gtk::glib::clone;
use gtk::prelude::*;
use gtk::subclass::prelude::*;
use tracing::debug;

use super::{ViewEvent, ViewUpdate};

mod imp {
    use std::cell::RefCell;

    use super::*;

    #[derive(Debug, Default, glib::Properties)]
    #[properties(wrapper_type = super::ViewModel)]
    pub struct ViewModel {
        #[property(get, set)]
        pub title: RefCell<String>,
        pub(super) rx: RefCell<Option<Receiver<ViewUpdate>>>,
        pub(super) tx: RefCell<Option<Sender<ViewEvent>>>,
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
    impl ObjectImpl for ViewModel { }
}

glib::wrapper! {
    pub struct ViewModel(ObjectSubclass<imp::ViewModel>);
}

impl ViewModel {
    pub fn new(title: &str, tx: Sender<ViewEvent>, rx: Receiver<ViewUpdate>) -> Self {
        let view_model: Self = glib::Object::builder().property("title", title).build();
        view_model.setup_channel(tx, rx);
        view_model
    }

    fn setup_channel(&self, tx: Sender<ViewEvent>, rx: Receiver<ViewUpdate>) {
        self.imp().tx.replace(Some(tx.clone()));
        self.imp().rx.replace(Some(rx.clone()));
        glib::spawn_future_local(clone!(@weak self as view_model => async move {
            loop {
                match rx.recv().await {
                    Ok(update) => {
                        match update {
                            ViewUpdate::SetTitle(title) => { view_model.set_title(title) },
                        }
                    },
                    Err(e) => {
                        debug!("ViewModel event listener interrupted: {}", e);
                        break;
                    }
                }
            }
        }));
    }

    pub async fn send_thingy(&self) {
        let tx = self.imp().tx.borrow();
        let tx = tx.as_ref().expect("channel to exist");
        tx.send(ViewEvent::ButtonClicked).await.unwrap();
    }
}
