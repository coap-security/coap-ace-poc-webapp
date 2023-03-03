//! This module manages a list of HTTP Authorization tokens placed plainly in the fragment part of
//! the URI.
//!
//! This is unsuitable for real-world applications (as these tokens are bearer tokens), but highly
//! convenient for demos.
//!
//! The protocol is a vast simplification of the OAuth protocol (with no actual security
//! properties) custom to the demo. It works as follows:
//!
//! The login process is started by the app discovering the login page through the Location header
//! of a failed attempt to obtain a token from the AS token endpoint. It then assumes that that
//! location supports this protocol, and sends the user there, with an added query parameter of
//! `append_and_redirect=` the current URI, already pre-populated with the token endpoint URI and a
//! semicolon. The login site, on successful "login", will then append some bearer token (usable in
//! the Authentication header), and optionally a semicolon and the name of the role (or user)
//! chosen.
//!
//! Authorizations are stored in the fragment identifier as follows:
//!
//! * The known ASes are stored in the fragment identifier, separated by '#' characters.
//! * For each AS, its token endpoint URI, the authentication string, and optionally a description
//!   of the logged-in user or role are stored. These componentes are separated by the ';'
//!   character.

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

pub fn link_for_removal(uri: &str) -> String {
    let mut result = String::new();
    for (u, a, d) in current_authorizations().iter() {
        if u == uri {
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
    if result.is_empty() {
        // So it doesn't result in a refresh
        result.push_str("#");
    }
    result
}
