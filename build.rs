use std::path::Path;

fn main() {
    built::write_built_file_with_opts(
        &built::Options::default(),
        Path::new("."),
        &Path::new(&std::env::var("OUT_DIR").unwrap()).join("built.rs"),
    )
    .unwrap();
}
