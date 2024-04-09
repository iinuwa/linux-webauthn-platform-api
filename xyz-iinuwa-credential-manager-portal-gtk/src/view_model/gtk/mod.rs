mod device;

use async_std::channel::{Receiver, Sender};
use gtk::gio;
use gtk::glib;
use glib::clone;
use gtk::prelude::*;
use gtk::subclass::prelude::*;
use tracing::debug;

use self::device::DeviceObject;

use super::Device;
use super::Operation;
use super::Transport;
use super::{ViewEvent, ViewUpdate};

mod imp {
    use std::cell::RefCell;

    use super::*;

    #[derive(Debug, Default, glib::Properties)]
    #[properties(wrapper_type = super::ViewModel)]
    pub struct ViewModel {
        #[property(get, set)]
        pub title: RefCell<String>,

        #[property(get, set)]
        pub devices: RefCell<gtk::ListBox>,

        // pub(super) vm: RefCell<Option<crate::view_model::ViewModel>>,
        pub(super) rx: RefCell<Option<Receiver<ViewUpdate>>>,
        pub(super) tx: RefCell<Option<Sender<ViewEvent>>>,
        // hybrid_qr_state: HybridState,
        // hybrid_qr_code_data: Option<Vec<u8>>,
    }

    // The central trait for subclassing a GObject
    #[glib::object_subclass]
    impl ObjectSubclass for ViewModel {
        const NAME: &'static str = "CredentialManagerViewModel";
        type Type =super::ViewModel;
    }

    // Trait shared by all GObjects
    #[glib::derived_properties]
    impl ObjectImpl for ViewModel { }
}

glib::wrapper! {
    pub struct ViewModel(ObjectSubclass<imp::ViewModel>);
}

impl ViewModel {
    pub(crate) fn new(vm: crate::view_model::ViewModel, tx: Sender<ViewEvent>, rx: Receiver<ViewUpdate>) -> Self {
        let title = match vm.operation {
            Operation::Create{ .. } => "Create new credential",
            Operation::Get { .. } => "Use a credential",
        };
        let view_model: Self = glib::Object::builder().property("title", title).build();
        // view_model.imp().vm.replace(Some(vm));
        view_model.setup_channel(tx, rx);

        let devices: &Vec<Device> = vm.devices.as_ref();
        let vec: Vec<DeviceObject> = devices.iter().map(|d| {
            let name = match d.transport {
                Transport::Ble => "A Bluetooth device",
                Transport::Internal => "This device",
                Transport::HybridQr => "A mobile device",
                Transport::HybridLinked => "TODO: Linked Device",
                Transport::Nfc => "An NFC device",
                Transport::Usb => "A security key",
                // Transport::PasskeyProvider => ("symbolic-link-symbolic", "ACME Password Manager"),
            };
            DeviceObject::new(&d.id, &d.transport, name)
        }).collect();
        let model = gio::ListStore::new::<DeviceObject>();
        // let entries: Device = vec.map(|(d, _, _)| d).collect();
        model.extend_from_slice(&vec);
        view_model.devices().bind_model(Some(&model), |item| -> gtk::Widget {
            let device = item.downcast_ref::<DeviceObject>().unwrap();
            let icon_name = match device.transport().as_ref() {
                "BLE" => "bluetooth-symbolic",
                "Internal" => "computer-symbolic",
                "HybridQr" => "phone-symbolic",
                "HybridLinked" => "phone-symbolic",
                "NFC" => "nfc-symbolic",
                "USB" => "media-removable-symbolic",
                // Transport::PasskeyProvider => ("symbolic-link-symbolic", "ACME Password Manager"),
                _ => "question-symbolic",
            };

            gtk::Button::builder()
                .icon_name(icon_name)
                .label(device.name())
                .name(device.id())
                .build()
                .into()
        });
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
        let tx: Sender<ViewEvent>;
        {
            let tx_tmp = self.imp().tx.borrow();
            tx = tx_tmp.as_ref().expect("channel to exist").clone();
        }
        tx.send(ViewEvent::ButtonClicked).await.unwrap();
    }
}
