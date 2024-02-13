use std::env;
use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

use walkdir::WalkDir;

fn main() -> Result<(), Box<dyn Error>> {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let resources_path = &out_dir.join("resources");
    let icons_path = &resources_path.join("icons");

    fs::create_dir_all(resources_path).unwrap();
    fs::create_dir_all(icons_path).unwrap();
    let resource_file = resources_path.join("resources.gresource.xml");
    fs::copy("resources/resources.gresource.xml", &resource_file).unwrap();
    let mut paths = Vec::new();
    for entry in WalkDir::new("resources") {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.is_file() {
            if let Some(extension) = path.extension() {
                if extension == "blp" {
                    paths.push(path.to_str().unwrap().to_owned());
                } else {
                    fs::copy(path, &out_dir.join(path)).unwrap();
                }
            }
            println!("cargo:rerun-if-changed={}", path.to_str().unwrap());
        }
    }

    let blueprint_files = paths.iter().map(|p| p.as_ref()).collect();
    let args = [
        vec![
            "batch-compile",
            resources_path.to_str().unwrap(),
            "resources",
        ],
        blueprint_files,
    ]
    .concat();
    Command::new("blueprint-compiler")
        .args(args)
        .output()
        .expect("blueprint-compiler to work");

    glib_build_tools::compile_resources(
        &[resources_path],
        resource_file.to_str().unwrap(),
        "compiled.gresource",
    );
    Ok(())
}
