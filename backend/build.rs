use std::path::PathBuf;
use std::process::Command;
use std::env;
use std::fs;
fn main() {
    
    let mut paths = Vec::new();
    for entry in fs::read_dir("resources").unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.is_file() {
            if let Some(extension) = path.extension() {
                if extension == "blp" {
                    paths.push(path.to_str().unwrap().to_owned());
                }
            }
            println!("cargo:rerun-if-changed={}", path.to_str().unwrap());
        }
    }
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let resources_path = &out_dir.join("resources");

    let blueprint_files = paths.iter().map(|p| p.as_ref()).collect();
    let args = [vec!["batch-compile", resources_path.to_str().unwrap(), "resources"], blueprint_files].concat();
    Command::new("blueprint-compiler")
        .args(args)
        .output()
        .expect("blueprint-compiler to work");

    fs::create_dir_all(resources_path).unwrap();
    let resource_file = resources_path.join("resources.gresource.xml");
    fs::copy("resources/resources.gresource.xml", &resource_file).unwrap();

    glib_build_tools::compile_resources(
        &[resources_path],
        &resource_file.to_str().unwrap(),
        "compiled.gresource",
    );
}