// SPDX-FileCopyrightText: Copyright 2022 EDF (Électricité de France S.A.)
// SPDX-License-Identifier: BSD-3-Clause
// See README for all details on copyright, authorship and license.
//! Tools for using yew more easily

/// Helper trait to run `Into<JsFuture>` in a chained style
pub trait PromiseExt {
    fn js2rs(self) -> wasm_bindgen_futures::JsFuture;
}

impl PromiseExt for js_sys::Promise {
    fn js2rs(self) -> wasm_bindgen_futures::JsFuture {
        self.into()
    }
}
