mod window;

use gtk::gio;
use gtk::glib;
use gtk::prelude::*;
use adw::Application;

use window::Window;

const APP_ID: &str = "xyz.iinuwa.CredentialManager1";

fn main() -> glib::ExitCode {
    gio::resources_register_include!("compiled.gresource").expect("Resource file to be compiled.");

    // Create a new application
    let app = Application::builder().application_id(APP_ID).build();

    // Connect to "activate" signal of `app`
    app.connect_activate(build_ui);

    // Run the application
    app.run()
}

fn build_ui(app: &Application) {
    // Create a window
    let window = Window::new(app);

    // Present window
    window.present();
}