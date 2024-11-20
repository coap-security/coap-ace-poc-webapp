// SPDX-FileCopyrightText: Copyright 2022 EDF (Électricité de France S.A.)
// SPDX-License-Identifier: BSD-3-Clause
// See README for all details on copyright, authorship and license.
//! CoAP/ACE PoC: Web application
//!
//! This application is a user interface for embedded devices offering CoAP services over
//! Bluetooth, typically running the [CoAP/ACE PoC demo firmware]. As directed by the user, it
//! connects to a device, reads the device's temperature or configures it, after obtaining suitable
//! credentials through an ACE authroization server.
//!
//! It is built using the [yew] framework, and thus is compiled into WASM code that executes inside
//! a browser as a web application.
//!
//! [CoAP/ACE PoC demo firmware]: https://gitlab.com/oscore/coap-ace-poc-firmware
//! [yew]: https://yew.rs/
//!
//! Building
//! --------
//!
//! Code in this module is compiled with cargo, and needs its WASM bindings generated through
//! wasm-bindgen into the `public/` directory in an extra step. The
//! `RUSTFLAGS=--cfg=web_sys_unstable_apis` environment variable needs to be set during building
//! because web-sys' Bluetooth APIs are not considered stable yet; the forced version in Cargo.toml
//! takes care of any future incompatibilities. It is recommended to set that variable also before
//! invoking any source code editor, as this allows any integrated linters to recognize functions
//! that are only present when that flag is set.
//!
//! The service worker used for making the web site usable as a PWA is shipped as
//! `public/service_worker.js.in` and represents a template into which a build ID should be
//! populated for easy updating of the installed PWA.
//!
//! The file `./.gitlab-ci` contains concrete commands for all these steps.

use yew::prelude::*;
use yew_oauth2::openid::OAuth2;

mod ble;
mod helpers;
use helpers::ViewLocalizedClaim;

use ble::DeviceId;

pub mod built_info {
    include!(concat!(env!("OUT_DIR"), "/built.rs"));
}

/// Convert the /token endpoint of an ACE AS (which issues tokens for CoAP) into the OAuth endtry
/// URI the user needs to be logged in to in order to interact with it.
///
/// This is currently a string processing function, which is bad, but to we'll need error response
/// feedback from talking to the ACE AS which it currently does not provide. (The function will
/// need to change because it'll need access to some storage and different lifetimes, but having
/// the function enables finding where it'll be needed).
///
/// Resolving this depends on
/// <https://gitlab.com/ace-oauth-poc-prerelease/keycloak-ace-extension/-/issues/1>
pub(crate) fn ace_as_to_oauth_entry(ace_as: &str) -> Option<&str> {
    ace_as.strip_suffix("/ace-oauth/token")
}

const DEMO_AS: &str = "http://localhost:1103/realms/edf/ace-oauth/token";

/// Main application component
///
/// This renders to the full application view, and hooks up its UI and network elements to receive
/// [Message]s.
struct Model {
    blepool: Option<ble::BlePool>,

    // FIXME: The verbosity around these is sad (this is really a simple form), hints appreciated
    // as to how to simplify them.
    manual_device_as_uri: String,
    manual_device_audience: String,

    oauth_configs: std::collections::HashMap<std::rc::Rc<str>, yew_oauth2::openid::Config>,

    /// Shall we pretend the browser was offline?
    force_offline: bool,
    /// Cached state of window.on_line()
    browser_is_online: bool,
}

/// Events that the main [Model] receives
enum Message {
    /// User request to scan for new BLE devices
    ScanBle,
    /// User request to read a device's temperature
    ReadTemperature(String),
    /// User request to make a device blink
    Identify(String),
    /// User request to set a device's number of idle LEDs
    SetIdle(String, u8),
    /// User request to close BLE connection to a device
    Disconnect(DeviceId),

    /// Message from the BLE task. The message is passed on to the [Model::blepool] which can
    /// actually make sense of it. See [Model::link_ble_queue] for why the Receiver is there.
    SomethingBleChanged(
        futures::channel::mpsc::Receiver<ble::BackToFrontMessage>,
        ble::BackToFrontMessage,
    ),

    BrowserOnlineChanged(bool),
    NoOp,

    /// For a given OIDC endpoint .0, an OAuth login component has found a token .1
    AsTokenAvailable((String, Option<String>)),

    SetManualDeviceAsUri(String),
    SetManualDeviceAudience(String),
    /// Add a device to the BLE list even though it was not discovered there yet, based on the AS
    /// URI and audience values manually entered using the [SetManualDeviceAsUri] and
    /// [SetManualDeviceAudience] events. This also removes any tokens or security associations for
    /// that device.
    ManualDeviceRequest,

    ToggleForceOffline,
}
use Message::*;

impl Model {
    /// An always-running yew "send_future" that waits for changes from the Bluetooth side, and
    /// passes them on as events. It also passes on the queue, so that when the model reacts to the
    /// message, it can start the cycle anew.
    fn link_ble_queue(
        ctx: &Context<Self>,
        mut queue: futures::channel::mpsc::Receiver<ble::BackToFrontMessage>,
    ) {
        ctx.link().send_future(async move {
            use futures::stream::StreamExt;
            let message = queue.next().await;

            match message {
                Some(message) => SomethingBleChanged(queue, message),
                None => {
                    log::error!(
                        "BLE pool ceased sending messages, won't try listening for them any more."
                    );
                    NoOp
                }
            }
        });
    }
}

impl Component for Model {
    type Message = Message;
    type Properties = ();

    fn create(ctx: &Context<Self>) -> Self {
        let (blepool, blepool_notifications) = match ble::BlePool::new() {
            Err(e) => {
                log::error!("Bluetooth can not be used: {:?}", e);
                (None, None)
            }
            Ok((blepool, blepool_notifications)) => (Some(blepool), Some(blepool_notifications)),
        };

        if let Some(blepool_notifications) = blepool_notifications {
            Self::link_ble_queue(ctx, blepool_notifications);
        }

        let window = web_sys::window().expect("Running in a browser");
        let callback = ctx.link().callback(|b| BrowserOnlineChanged(b));
        let callback2 = callback.clone();
        Box::leak(Box::new(gloo_events::EventListener::new(
            &window,
            "online",
            move |_| {
                callback.emit(true);
            },
        )));
        Box::leak(Box::new(gloo_events::EventListener::new(
            &window,
            "offline",
            move |_| {
                callback2.emit(false);
            },
        )));

        let mut oauth_configs = std::collections::HashMap::default();
        // URIs for keycloak as running with yew-oauth2's docker compose setup
        //
        // In case of trouble with logging in in the first place, this is a good fallback to
        // explore; won't get far beyond login because it's not an ACE AS.
        //
        // This is currently disabled becasue of <https://github.com/ctron/yew-oauth2/issues/43> --
        // having more than one in breaks things occasionally.
        // oauth_configs.insert(
        //     "http://localhost:8081/realms/master".into(),
        //     yew_oauth2::openid::Config::new("example", "http://localhost:8081/realms/master"),
        // );
        // URIs for keycloak as running the keycloak-ace-extensions/playground with the
        // ace_as container configured with `ports:` / `- "1103:8080"`
        oauth_configs.insert(
            ace_as_to_oauth_entry(DEMO_AS).unwrap().into(),
            yew_oauth2::openid::Config::new("webapp-dev", ace_as_to_oauth_entry(DEMO_AS).unwrap()),
        );

        Model {
            blepool,
            manual_device_as_uri: DEMO_AS.to_string(),
            manual_device_audience: "d01".to_string(),
            force_offline: false,
            browser_is_online: web_sys::window().unwrap().navigator().on_line(),
            oauth_configs,
        }
    }

    fn update(&mut self, ctx: &Context<Self>, message: Self::Message) -> bool {
        match message {
            ScanBle => {
                self.blepool.as_mut().unwrap().connect();
                false
            }

            SomethingBleChanged(queue, message) => {
                self.blepool
                    .as_mut()
                    .expect("Queue was created, so the pool should be here as well")
                    .notify(message);
                Self::link_ble_queue(ctx, queue);
                true
            }

            ReadTemperature(id) => {
                self.blepool
                    .as_mut()
                    .expect("Items were shown, so the pool should be here as well")
                    .read_temperature(id);
                false
            }

            Identify(id) => {
                self.blepool
                    .as_mut()
                    .expect("Items were shown, so the pool should be here as well")
                    .identify(id);
                false
            }

            SetIdle(id, level) => {
                self.blepool
                    .as_mut()
                    .expect("Items were shown, so the pool should be here as well")
                    .set_idle(id, level);
                false
            }

            Disconnect(id) => {
                self.blepool
                    .as_mut()
                    .expect("Items were shown, so the pool should be here as well")
                    .disconnect(id);
                false
            }

            SetManualDeviceAsUri(s) => {
                self.manual_device_as_uri = s;
                false
            }
            SetManualDeviceAudience(s) => {
                self.manual_device_audience = s;
                false
            }
            ManualDeviceRequest => {
                if let Some(pool) = self.blepool.as_mut() {
                    // FIXME: Here it becomes weird that so much is running through the BLE pool -- but
                    // given how large a threshold there is to cross between the async and the yew
                    // world, it's the easiest way.
                    let rch = ace_oscore_helpers::request_creation_hints::RequestCreationHints {
                        as_uri: self.manual_device_as_uri.clone(),
                        audience: self.manual_device_audience.clone(),
                    };
                    pool.add_device_manually(rch);
                }
                false
            }

            ToggleForceOffline => {
                self.force_offline = !self.force_offline;
                if let Some(pool) = self.blepool.as_mut() {
                    pool.set_force_offline(self.force_offline);
                }
                true
            }
            BrowserOnlineChanged(state) => {
                self.browser_is_online = state;
                true
            }

            AsTokenAvailable(details) => {
                // FIXME should we spool those in case?
                if let Some(pool) = self.blepool.as_mut() {
                    pool.request(ble::FrontToBackMessage::AsTokenAvailable(details));
                }
                false
            }

            NoOp => false,
        }
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let link = ctx.link();

        let has_bluetooth = self.blepool.is_some();

        let bluetooth_button = match has_bluetooth {
            true => {
                html! { <button onclick={link.callback(|_| ScanBle)}>{ "Search nearby devices" }</button> }
            }
            false => {
                html! { <button disabled=true title="Bluetooth not available in this browser">{ "Search nearby devices" }</button> }
            }
        };

        let netclass = if let Some(pool) = self.blepool.as_ref() {
            match (
                pool.last_network_was_success,
                pool.network_successes % 2,
                pool.network_failures % 2,
            ) {
                (Some(true), 0, _) => classes!["network", "allowed"],
                (Some(true), _, _) => classes!["network", "allowed2"],
                (Some(false), _, 0) => classes!["network", "blocked"],
                (Some(false), _, _) => classes!["network", "blocked2"],
                (None, _, _) => classes!["network"],
            }
        } else {
            classes!["network"]
        };

        html! {
            <div>
                <h1>{ "CoAP ACE PoC: The App" }</h1>
                <p id="crashreport" style="display:none">{ "This application has crashed, this is a bug. Additional details are available in the browser's console, please report them at " }<a href={built_info::PKG_REPOSITORY}>{ "the application's source" }</a>{ "." } </p>
                <h2>{ "Devices" }</h2>
                { bluetooth_button }
                { self.view_bluetooth_list(ctx) }
                <details><summary>{ "Request token manually" }</summary>
                // The "action" is a workaround for submit link callbacks apparently not being
                // cancellable through yew
                <form onsubmit={ link.callback(|_| ManualDeviceRequest ) } action="javascript:;">
                    <fieldset>
                    <p>
                        <label for="input_as_uri">{ "AS URI:" }</label>{ " " }
                        <input type="url" id="input_as_uri" value={ self.manual_device_as_uri.clone() } onchange={ link.callback(|e: Event| SetManualDeviceAsUri(e.target_unchecked_into::<web_sys::HtmlInputElement>().value())) } />
                    </p>
                    <p>
                        <label for="input_audience">{ "Audience:" }</label>{ " " }
                        <input type="text" id="input_audience" value={ self.manual_device_audience.clone() } onchange={ link.callback(|e: Event| SetManualDeviceAudience(e.target_unchecked_into::<web_sys::HtmlInputElement>().value())) } />
                    </p>
                    </fieldset>
                    <p><input type="submit" value="Request token manually" /></p>
                </form>
                </details>
                <h2>{ "Logins" }</h2>
                    // We could have multiple of them conceptually, because we send the tokens out
                    // anyway (from this model's PoV it's inner either way, don't need to go
                    // top-level in there), but until we dan do OAuth in popups, we can't have
                    // multiple ASs.
                    { for self.oauth_configs.iter().map(|(key, config)| {
                        html! { <li key={key.clone()}>
                            <OAuth2 config={config.clone()}>
                                <LoginView uri={key.clone()} on_access_token_available={ link.callback(Message::AsTokenAvailable) } />
                            </OAuth2>
                        </li> }
                    })}
                <footer>
                    <p class={ netclass }>{ "Internet connection " }{ if self.browser_is_online { "available, " } else { "unavailable, " }}<label><input type="checkbox" checked={ self.force_offline } onchange={ ctx.link().callback(|_| ToggleForceOffline) } />{ " force offline mode" }</label></p>
                    <p>
                        {"This is "}
                        <a href={built_info::PKG_REPOSITORY}>{ built_info::PKG_NAME }</a>
                        { format!(
                            " version {} (git {}{}).",
                            built_info::PKG_VERSION,
                            built_info::GIT_VERSION.unwrap_or("unknown"),
                            built_info::GIT_DIRTY.and_then(|dirty| dirty.then_some("-dirty")).unwrap_or(""),
                            ) }
                    </p>
                </footer>
            </div>
        }
    }
}

#[derive(PartialEq, Properties)]
struct LoginViewProps {
    uri: std::rc::Rc<str>,
    on_access_token_available: Callback<(String, Option<String>)>,
}

#[function_component(LoginView)]
fn login_view(props: &LoginViewProps) -> Html {
    use yew_oauth2::openid::use_auth_agent;
    use yew_oauth2::prelude::{
        Authenticated, Authentication, Failure, FailureMessage, NotAuthenticated, OAuth2Context,
        OAuth2Operations,
    };

    // Reminder to readers unfamiliar with yew's function_component: The macro rewrites every
    // top-level function call to `use_` into a wrapper that allows that function to access the
    // context and otherwise do more.
    let agent = use_auth_agent().expect("Must be nested inside an OAuth2 component");
    let auth = use_context::<OAuth2Context>().expect("Must be nested inside an OAuth2 context");

    props
        .on_access_token_available
        .emit((props.uri.to_string(), auth.access_token().map(String::from)));

    // Events prevent default to be usable with <a> links that are still accessible as links
    let login = use_callback(agent.clone(), |event: MouseEvent, agent| {
        event.prevent_default();
        if let Err(e) = agent.start_login() {
            log::error!("Error logging in: {e:?}");
        }
    });
    let logout = use_callback(agent, |event: MouseEvent, agent| {
        event.prevent_default();
        if let Err(e) = agent.logout() {
            log::error!("Error logging out: {e:?}");
        }
    });

    html!(
        <>
        // Using Failure/Authenticated/... for simplicity, but we could probably also juste as well work on auth
        <Authenticated>
          {"Logged in as "}
          if let OAuth2Context::Authenticated(Authentication { claims: Some(claims), .. }) = &auth {
              <>if let Some(name) = claims.name() {
                  <ViewLocalizedClaim<openidconnect::EndUserName> claim={std::rc::Rc::new(name.to_owned())} />
              }
              if let Some(nickname) = claims.nickname() {
                  // Showing nickname name because unlike full name we can make keycloak publish
                  // them localized, eg. if we claim all our nicknames are German by setting
                  // Client scopes / profile / mappers / nickname / TokenClaim Name to
                  // "nickname#de" -- mainly this demos that ViewLocalizedClaim really does
                  // something useful.
                  {" ("}<ViewLocalizedClaim<openidconnect::EndUserNickname> claim={std::rc::Rc::new(nickname.to_owned())} />{")"}
              }
              </>
          } else {
              { "… well actually not logged in (please report how this happened)" }
          }
          { format!(" at {}; ", props.uri) }
          <a onclick={logout} href="#prevent_me">{ "Logout" }</a>
        </Authenticated>
        <NotAuthenticated>
          <a onclick={login} href="#prevent_me">{ "Login" }</a>{ format!(" to {} ", props.uri) }
        </NotAuthenticated>
        // Not repeating the URI because this is typically shown when also NotAuthenticated is
        // shown, and creates an own paragraph.
        <Failure>{ "Login failure: " }<FailureMessage/></Failure>
        </>
    )
}

impl Model {
    fn view_bluetooth_list(&self, ctx: &Context<Self>) -> Html {
        let link = ctx.link();

        match &self.blepool {
            Some(p) => html! { <ul class="devices">
            { for p.active_connections().map(|con| {
                let name = con.name.as_deref().unwrap_or("(unnamed)");
                let operative = if con.is_connected {
                    let id = con.id.as_ref().expect("Connected devices must have an ID");

                    let temp = p.latest_temperature(id)
                        .map(|t| format!("{t} °C"))
                        .unwrap_or_else(|| "unknown".to_string());
                    let read_temp = link.callback({let id = id.to_string(); move |_| ReadTemperature(id.clone())});
                    let identify = link.callback({let id = id.to_string(); move |_| Identify(id.clone())});
                    let idle_dark = link.callback({let id = id.to_string(); move |_| SetIdle(id.clone(), 0)});
                    let idle_half = link.callback({let id = id.to_string(); move |_| SetIdle(id.clone(), 2)});
                    let idle_bright = link.callback({let id = id.to_string(); move |_| SetIdle(id.clone(), 4)});
                    let disconnect = link.callback({let id = id.to_string(); move |_| Disconnect(id.clone())});
                    html! {
                        <>
                            <p>
                                <span class="name">{ &name }</span>
                                { " " }<button onclick={ identify }>{ "Find" }</button>
                            </p>
                            <p>
                                { "Temperature: " }{ &temp }{ " " }<button onclick={ read_temp }>{ "Read" }</button>
                            </p>
                            <p>{ "Idle LED state: " }
                                <button onclick={ idle_dark }>{ "dark" }</button>
                                <button onclick={ idle_half }>{ "half" }</button>
                                <button onclick={ idle_bright }>{ "bright" }</button>
                            </p>
                            <p><button onclick={ disconnect }>{ "Disconnect" }</button></p>
                        </>
                    }
                } else {
                    html! { <p>{ "Device currently not connected." }</p> }
                };

                let mut sec_assoc = html! { <p>{ "No security identity known" }</p> };

                if let Some(rs_identity) = &con.rs_identity {
                    sec_assoc = html! { <p>{ "Security association: " }{ &rs_identity.audience }{ " at " }{ &rs_identity.as_uri }</p> };
                }

                html! {
                    <li>
                        { operative }
                        { sec_assoc }
                        <p>{ "Token: " }{ if let Some((token, when)) = &con.access_token {
                            let class = if instant::SystemTime::now().duration_since(*when).unwrap().as_secs() < 10 {
                                classes!["new"]
                            } else {
                                classes![]
                            };
                            html! { <span class={ class }><tt>{ token }</tt></span> }
                        } else {
                            match con.why_no_token {
                                // We've already had the special treatment for Unauthorized above
                                Some(ble::MissingTokenReason::Unauthorized) => {
                                    if let Some(rs_identity) = &con.rs_identity {
                                        // FIXME: Populate into known-AS list, possibly with
                                        // pre-processing (ACE token endpoint -> OpenID path), or
                                        // can we even have a login button directly here?
                                        html! { <b>{ format!("Login required through {:?}", rs_identity) }</b> }
                                    } else {
                                        "none available (AS not yet known)".into()
                                    }
                                },
                                None => "none available".into(),
                                Some(reason) => format!("none available ({:?})", reason).into(),
                            }
                        } }</p>
                        <p>{ "OSCORE: " }{ if con.oscore_established { "established" } else { "not established" } }</p>
                    </li>
                }
            }) }
            </ul> },
            None => html! { <p>{ "Bluetooth not available in this browser" }</p> },
        }
    }
}

#[wasm_bindgen::prelude::wasm_bindgen]
extern "C" {
    /// Show an HTML element that makes it visible to the user that the application just crashed.
    fn indicate_panic_happened();
}

/// Run the default panic handler, but also fan out to [indicate_panic_happened].
fn panic<'a, 'b>(info: &'a std::panic::PanicHookInfo<'b>) {
    indicate_panic_happened();
    console_error_panic_hook::hook(info);
}

pub fn main() {
    fern::Dispatch::new()
        .level(log::LevelFilter::Debug)
        // yew_oauth2 is *very* verbose, let's keep that out by default
        .level_for("yew_oauth2", log::LevelFilter::Info)
        .chain(fern::Output::call(console_log::log))
        .apply()
        .expect("Logging setup failed");

    // Note that panics before this line would not be caugt, but it's not worth the confusion to
    // pull in console_error_panic_hook just to get that feature one line earlier.
    yew::Renderer::<Model>::new().render();
    let panic_hook: Box<
        dyn for<'a, 'b> Fn(&'a std::panic::PanicHookInfo<'b>) + Send + Sync + 'static,
    > = Box::new(panic);
    yew::set_custom_panic_hook(panic_hook);

    log::info!("App started.");

    do_oscore_test().unwrap();
    log::info!("OSCORE self-tests passed");
}

/// A self test for OSCORE (adjusted from libOSCORE sources)
pub fn do_oscore_test() -> Result<(), &'static str> {
    use core::mem::MaybeUninit;

    use coap_message::{MessageOption, MinimalWritableMessage, ReadableMessage};

    use liboscore::raw;

    // From OSCORE plug test, security context A
    let immutables = liboscore::PrimitiveImmutables::derive(
        liboscore::HkdfAlg::from_number(5).unwrap(),
        b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10",
        b"\x9e\x7c\xa9\x22\x23\x78\x63\x40",
        None,
        liboscore::AeadAlg::from_number(24).unwrap(),
        b"\x01",
        b"",
    )
    .unwrap();

    let mut primitive = liboscore::PrimitiveContext::new_from_fresh_material(immutables);

    let mut msg = coap_message_implementations::heap::HeapMessage::new();
    let oscopt = b"\x09\x00";
    msg.add_option(9, oscopt)
        .expect("Heap message operations are infallible");
    msg
        .set_payload(b"\x5c\x94\xc1\x29\x80\xfd\x93\x68\x4f\x37\x1e\xb2\xf5\x25\xa2\x69\x3b\x47\x4d\x5e\x37\x16\x45\x67\x63\x74\xe6\x8d\x4c\x20\x4a\xdb")
        .expect("Heap message operations are infallible");

    liboscore_msgbackend::with_heapmessage_as_msg_native(msg, |msg| {
        unsafe {
            let header = liboscore::OscoreOption::parse(oscopt).unwrap();

            let mut unprotected = MaybeUninit::uninit();
            let mut request_id = MaybeUninit::uninit();
            let ret = raw::oscore_unprotect_request(
                msg,
                unprotected.as_mut_ptr(),
                &header.into_inner(),
                primitive.as_mut(),
                request_id.as_mut_ptr(),
            );
            assert!(ret == raw::oscore_unprotect_request_result_OSCORE_UNPROTECT_REQUEST_OK);
            let unprotected = unprotected.assume_init();

            let unprotected = liboscore::ProtectedMessage::new(unprotected);
            assert!(unprotected.code() == 1);

            let mut message_options = unprotected.options().fuse();
            let mut ref_options = [(11, "oscore"), (11, "hello"), (11, "1")]
                .into_iter()
                .fuse();
            for (msg_o, ref_o) in (&mut message_options).zip(&mut ref_options) {
                assert!(msg_o.number() == ref_o.0);
                assert!(msg_o.value() == ref_o.1.as_bytes());
            }
            assert!(
                message_options.next().is_none(),
                "Message contained extra options"
            );
            assert!(
                ref_options.next().is_none(),
                "Message didn't contain the reference options"
            );
            assert!(unprotected.payload() == b"");
        };
    });

    // We've taken a *mut of it, let's make sure it lives to the end
    drop(primitive);

    Ok(())
}
