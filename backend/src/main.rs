mod portal;
mod views;
mod window;

use adw::Application;
use gtk::gdk::Display;
use gtk::gio;
use gtk::glib;
use gtk::prelude::*;

use window::Window;

const APP_ID: &str = "xyz.iinuwa.CredentialManager1";

fn main() -> glib::ExitCode {
    gio::resources_register_include!("compiled.gresource").expect("Resource file to be compiled.");

    // Create a new application
    let app = Application::builder().application_id(APP_ID).build();

    // Connect to "activate" signal of `app`
    app.connect_startup(|_| load_css());
    app.connect_activate(build_ui);

    // Run the application
    app.run()
}

fn load_css() {
    // Load the CSS file and add it to the provider
    let provider = gtk::CssProvider::new();
    provider.load_from_resource("/xyz/iinuwa/CredentialManager1/styles/custom.css");

    // Add the provider to the default screen
    gtk::style_context_add_provider_for_display(
        &Display::default().expect("Could not connect to a display."),
        &provider,
        gtk::STYLE_PROVIDER_PRIORITY_APPLICATION,
    );
}

fn build_ui(app: &Application) {
    // Create a window
    let window = Window::new(app);

    // Present window
    window.present();
}
