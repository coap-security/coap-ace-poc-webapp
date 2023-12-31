// SPDX-FileCopyrightText: Copyright 2022 EDF (Électricité de France S.A.)
// SPDX-License-Identifier: BSD-3-Clause
// See README for all details on copyright, authorship and license.
//! This module manages a list of HTTP Authorization tokens placed plainly in the fragment part of
//! the URI.
//!
//! This is unsuitable for real-world applications (as these tokens are bearer tokens), but highly
//! convenient for demos.
//!
//! The protocol is a vast simplification of the OAuth protocol (with no actual security
//! properties) custom to the demo. It works as follows:
//!
//! The login process is started by the app calculating the login page as "./" of the token URI of
//! a failed attempt to obtain a token from the AS token endpoint. (This used to utilize the
//! Location header of the failed request, but that was a remnant of when logins were envisioned to
//! be based on cookies -- as the login protocol is bespoke to the demo anyway, going the simple
//! path is acceptable). It then assumes that that location supports this protocol, and sends the
//! user there, with an added query parameter of `append_and_redirect=` the current URI, already
//! pre-populated with the token endpoint URI and a semicolon. The login site, on successful
//! "login", will then append some bearer token (usable in the Authentication header), and
//! optionally a semicolon and the name of the role (or user) chosen.
//!
//! Authorizations are stored in the fragment identifier as follows:
//!
//! * The known ASes are stored in the fragment identifier, separated by '#' characters.
//! * For each AS, its token endpoint URI, the authentication string, and optionally a description
//!   of the logged-in user or role are stored. These componentes are separated by the ';'
//!   character.
//! * If no authentication string is given, the AS is treated as "logged out" but still available
//!   for later log-in.

/// Produce a list of currently available URIs and the Authentication values used with it
pub fn current_authorizations() -> Vec<(String, String, Option<String>)> {
    let hash = web_sys::window()
        .expect("This is running inside a web browser")
        .location()
        .hash()
        .unwrap()
        .to_string();
    hash.split('#')
        .filter(|part| !part.is_empty())
        // Silently discarding erroneous components
        .filter_map(|part| {
            let mut components = part.split(';');
            let part_token_uri = components.next()?;
            let part_authorization = components.next()?;
            let part_description = components.next();

            // FIXME: Do full escaping (but this precise handling is suitable only for the
            // demo anyway)
            Some((
                part_token_uri.to_string(),
                part_authorization.replace("%20", " "),
                part_description.map(|s| s.replace("%20", " ")),
            ))
        })
        .collect()
}

/// Produce a list of URIs that are known to be useful token endpoints but there is no current
/// login
pub fn known_as_not_logged_in() -> Vec<String> {
    let hash = web_sys::window()
        .expect("This is running inside a web browser")
        .location()
        .hash()
        .unwrap()
        .to_string();
    let mut result: Vec<_> = hash
        .split('#')
        .filter(|part| !part.is_empty())
        // Silently discarding erroneous components
        .filter_map(|part| {
            let mut components = part.split(';');
            let part_token_uri = components.next()?;
            match components.next() {
                None => Some(part_token_uri.to_string()),
                // It's really a current authorization and not a non-logged-in AS
                Some(_) => None,
            }
        })
        .collect();

    if hash == "" {
        result.push(crate::DEMO_AS.to_string());
    }

    result
}

/// New fragment part when removing the token URI given as `without`.
fn fragment_for_state(without: &str) -> String {
    let mut result = String::new();
    for (u, a, d) in current_authorizations().iter() {
        if u == without {
            continue;
        }
        result.push_str("#");
        result.push_str(u);
        result.push_str(";");
        result.push_str(a);
        if let Some(d) = d {
            result.push_str(";");
            result.push_str(d);
        }
    }
    for u in known_as_not_logged_in().iter() {
        if u == without {
            continue;
        }
        result.push_str("#");
        result.push_str(u);
    }

    result
}

/// Local link that can be followed to log out of uri.
///
/// Incidentally, if uri is not in the list, it adds it to the list of not-logged-in ASes.
pub fn link_for_logout(uri: &str) -> String {
    let mut result = fragment_for_state(uri);
    result.push_str("#");
    result.push_str(uri);
    result
}

pub fn link_for_removal(uri: &str) -> String {
    let mut result = fragment_for_state(uri);
    if result.is_empty() {
        // So it doesn't result in a refresh
        result.push_str("#");
    }
    result
}

#[derive(Debug, Copy, Clone)]
/// Error type indicating that a login URI is somehow not conforming to the custom login
/// append_and_redirect mechanism. (Currently, there are no requirements other than that it's a
/// valid URI).
pub struct InvalidLoginUri;

/// Turn a token URI into a login URI usable to follow to log in using this module's protocol.
/// (That is, strip off the typical `/token` part by resolving `./`, and then set the query
/// append_and_redirect parameter so that the login form returns to this page).
///
/// Returns two forms of the login URI: The regularly usable one, and a variety without the query
/// string (which is not expected to be useful on its own, but quite practical for display purposes)
pub fn build_login_uri(token_uri: &str) -> Result<(String, String), InvalidLoginUri> {
    if let Ok(login_uri) = url::Url::parse(token_uri) {
        let mut login_uri = login_uri
            .join("./")
            // url can't do relative resolution on URN-style URIs
            .map_err(|_| InvalidLoginUri)?;
        let without_query = login_uri.to_string();

        // current URI, but make sure that if we get into a double-login situation, the current one
        // is discarded
        let current_address = web_sys::window().unwrap().location().href().unwrap();
        let current_address = url::Url::parse(&current_address).unwrap();
        let current_address = current_address.join(&link_for_removal(token_uri)).unwrap();

        login_uri.set_query(Some(&format!(
            "append_and_redirect={}#{};",
            current_address, token_uri
        )));
        Ok((login_uri.to_string(), without_query))
    } else {
        Err(InvalidLoginUri)
    }
}
