//! This module manages a list of HTTP Authorization tokens placed plainly in the fragment part of
//! the URI.
//!
//! This is unsuitable for real-world applications (as these tokens are bearer tokens), but highly
//! convenient for demos.

/// Produce a list of currently available URIs and the Authentication values used with it
pub fn current_authorizations() -> Vec<(String, String)> {
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

            // FIXME: Do full escaping (but this precise handling is suitable only for the
            // demo anyway)
            Some((
                part_token_uri.to_string(),
                part_authorization.replace("%20", " "),
            ))
        })
        .collect()
}

pub fn link_for_removal(uri: &str) -> String {
    let mut result = String::new();
    for (u, a) in current_authorizations().iter() {
        if u == uri {
            continue;
        }
        result.push_str("#");
        result.push_str(u);
        result.push_str(";");
        result.push_str(a);
    }
    if result.is_empty() {
        // So it doesn't result in a refresh
        result.push_str("#");
    }
    result
}
