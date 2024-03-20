
pub struct ViewModel {
    title: String,
    operation: Operation,

    // This includes devices like platform authenticator, USB, hybrid
    devices: Vec<Device>,
    selected_device: Device,
    providers: Vec<Provider>,

    internal_uv_methods: Vec<UserVerificationMethod>,
    internal_device_credentials: ,
    internal_selected_uv_method: ,
    internal_device_pin_state: ,
    fingerprint_sensor_state: FingerprintSensorState,

    usb_device_state: ,
    usb_device_pin_state: ,

    hybrid_qr_state: ,
    hybrid_qr_code_img: Vec<u8>,

    hybrid_linked_state: ,

}

impl ViewModel {
    fn start_authentication(); // open page
    fn cancel_authentication();

    fn start_fingerprint_authentication();
    fn cancel_fingerprint_authentication();

    fn start_hybrid_qr_authentication();
    fn cancel_hybrid_qr_authentication();

    fn start_hybrid_linked_authentication();
    fn cancel_hybrid_linked_authentication();

    // Can this be used for internal uv method too?
    fn start_usb_authentication();
    fn cancel_usb_authentication();
    fn send_usb_device_pin();

    fn select_uv_method();
    fn send_internal_device_pin();

    fn finish_authentication();

    fn select_device();
}

pub struct UserVerificationMethod;
pub enum FingerprintSensorState { }
pub enum Transport {
    Ble,
    HybridLinked,
    HybridQr,
    Internal,
    Nfc,
    Usb,
}
pub struct Device {
    transport: Transport,
}
pub struct Provider;

pub enum CredentialType {
    Passkey,
    Password,
}
pub enum Operation {
    Create { cred_type: CredentialType },
    Get { cred_types: Vec<CredentialType> },
}
