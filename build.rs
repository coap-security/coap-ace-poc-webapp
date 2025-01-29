// SPDX-FileCopyrightText: Copyright 2022-2024 EDF (Électricité de France S.A.)
// SPDX-License-Identifier: BSD-3-Clause
// See README for all details on copyright, authorship and license.
use std::path::Path;

fn main() {
    built::write_built_file_with_opts(
        &built::Options::default(),
        Path::new("."),
        &Path::new(&std::env::var("OUT_DIR").unwrap()).join("built.rs"),
    )
    .unwrap();
}
