// SPDX-FileCopyrightText: Copyright 2022-2024 EDF (Électricité de France S.A.)
// SPDX-License-Identifier: BSD-3-Clause
// See README for all details on copyright, authorship and license.
//! Tools for using yew more easily

use yew::prelude::*;

/// Helper trait to run `Into<JsFuture>` in a chained style
pub trait PromiseExt {
    fn js2rs(self) -> wasm_bindgen_futures::JsFuture;
}

impl PromiseExt for js_sys::Promise {
    fn js2rs(self) -> wasm_bindgen_futures::JsFuture {
        self.into()
    }
}

/// Views any [`openidconnect::LocalizedClaim<T>`] for text-based `T`.
///
/// This produces an HTML version of the localized claim's content, and annotates it with its
/// language if that is present. Future versions may also selecte the text by evaluating the HTML
/// context's configured language.
// Implementation for https://github.com/ctron/yew-oauth2/issues/41
#[function_component(ViewLocalizedClaim)]
pub fn view_claim<T: PartialEq + core::ops::Deref<Target = String>>(
    props: &LocalizedClaimProps<T>,
) -> Html {
    let Some((lang, val)) = props.claim.iter().next() else {
        return html!();
    };
    if let Some(lang) = lang {
        html!(<span lang={ lang.as_str().to_owned() }>{ val.to_string() }</span>)
    } else {
        html!({ val.to_string() })
    }
}

/// Helper for [`view_claim`]
#[derive(PartialEq, Properties)]
// PartialEq is required to derive Properties; the fn has more requirements
pub struct LocalizedClaimProps<T: PartialEq> {
    // Rc implements ImplicitClone
    pub claim: std::rc::Rc<openidconnect::LocalizedClaim<T>>,
}
