use proc_macro2::TokenStream;

use std::env;
use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;

fn main() {
    let pkg_name = env::var("CARGO_PKG_NAME").unwrap();
    let manifest_path = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());

    // TODO: Use root path to force re-run during development
    if std::path::Path::new(".git/HEAD").exists() {
        println!("cargo:rerun-if-changed=.git/HEAD");
    }

    let target_dir = if let Ok(v) = env::var("BUILD_DIR") {
        PathBuf::from(v)
    } else {
        manifest_path.clone()
    };
    println!("BUILD_DIR: {:?}", target_dir);
    std::fs::create_dir_all(&target_dir).unwrap();

    let lib_path = &manifest_path.join("src").join("lib.rs");
    println!("cargo:rerun-if-changed={}", lib_path.as_path().display());

    let mut content = String::new();
    File::open(lib_path)
        .unwrap()
        .read_to_string(&mut content)
        .unwrap();

    let pkg_name_underscored = pkg_name.replace("-", "_");
    let header_file_path = String::from(pkg_name_underscored.clone() + ".h");
    let source_file_path = String::from(pkg_name_underscored.clone() + ".cpp");

    let tt: TokenStream = content.parse().unwrap();
    let mut opt = cxx_gen::Opt::default();
    opt.include.push(cxx_gen::Include {
        path: header_file_path.clone(),
        kind: cxx_gen::IncludeKind::Bracketed,
    });

    let codegen = cxx_gen::generate_header_and_cc(tt, &opt).unwrap();
    let cpp_stuff = String::from_utf8(codegen.implementation).unwrap();

    File::create(target_dir.join(header_file_path))
        .unwrap()
        .write_all(&codegen.header)
        .unwrap();
    File::create(target_dir.join(source_file_path))
        .unwrap()
        .write_all(cpp_stuff.as_bytes())
        .unwrap();
}