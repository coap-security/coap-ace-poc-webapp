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

use yew::prelude::*;

mod authorizations;
mod ble;

pub mod built_info {
    include!(concat!(env!("OUT_DIR"), "/built.rs"));
}

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

    /// Message from the BLE task. The message is passed on to the [Model::blepool] which can
    /// actually make sense of it. See [Model::link_ble_queue] for why the Receiver is there.
    SomethingBleChanged(
        futures::channel::mpsc::Receiver<ble::BackToFrontMessage>,
        ble::BackToFrontMessage,
    ),
    NoOp,

    /// Remove a URI from the list of currently logged-in-to ASes
    LogoutFrom(String),

    SetManualDeviceAsUri(String),
    SetManualDeviceAudience(String),
    ManualDeviceRequest,
}
use Message::*;

impl Model {
    /// An allways-running yew "send_future" that waits for changes from the Bluetooth side, and
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

        Model {
            blepool,
            manual_device_as_uri: "https://as.coap.amsuess.com/token".to_string(),
            manual_device_audience: "d01".to_string(),
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

            LogoutFrom(uri) => {
                web_sys::window()
                    .unwrap()
                    .location()
                    .set_href(&authorizations::link_for_removal(&uri))
                    .unwrap();
                true
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

            NoOp => false,
        }
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let link = ctx.link();

        let has_bluetooth = self.blepool.is_some();

        let bluetooth_button = match has_bluetooth {
            true => {
                html! { <button onclick={link.callback(|_| ScanBle)}>{ "Add device" }</button> }
            }
            false => {
                html! { <button disabled=true title="Bluetooth not available in this browser">{ "Add device" }</button> }
            }
        };

        html! {
            <div>
                <h1>{ "CoAP ACE PoC: The App" }</h1>
                <p id="crashreport" style="display:none">{ "This application has crashed, this is a bug. Additional details are available in the browser's console, please report them at " }<a href={built_info::PKG_REPOSITORY}>{ "the application's source" }</a>{ "." } </p>
                <h2>{ "Devices" }</h2>
                { bluetooth_button }
                { self.view_bluetooth_list(ctx) }
                <details><summary>{ "Add device manually" }</summary>
                // The "action" is a workaround for submit link callbacks apparently not being
                // cancellable through yew
                <form onsubmit={ link.callback(|_| ManualDeviceRequest ) } action="javascript:;">
                    <p>
                        <label for="input_as_uri">{ "AS URI:" }</label>{ " " }
                        <input type="url" id="input_as_uri" value={ self.manual_device_as_uri.clone() } onchange={ link.callback(|e: Event| SetManualDeviceAsUri(e.target_unchecked_into::<web_sys::HtmlInputElement>().value())) } />
                    </p>
                    <p>
                        <label for="input_audience">{ "Audience:" }</label>{ " " }
                        <input type="text" id="input_audience" value={ self.manual_device_audience.clone() } onchange={ link.callback(|e: Event| SetManualDeviceAudience(e.target_unchecked_into::<web_sys::HtmlInputElement>().value())) } />
                    </p>
                    <p><input type="submit" value="Add device manually" /></p>
                </form>
                </details>
                <h2>{ "Logins" }</h2>
                { self.view_login_list(ctx) }
                <footer>
                    {"This is "}
                    <a href={built_info::PKG_REPOSITORY}>{ built_info::PKG_NAME }</a>
                    { format!(
                        " version {} (git {}{}).",
                        built_info::PKG_VERSION,
                        built_info::GIT_VERSION.unwrap_or("unknown"),
                        built_info::GIT_DIRTY.and_then(|dirty| dirty.then_some("-dirty")).unwrap_or(""),
                        ) }</footer>
            </div>
        }
    }
}

impl Model {
    fn view_login_list(&self, ctx: &Context<Self>) -> Html {
        let link = ctx.link();
        let list = authorizations::current_authorizations();
        if list.is_empty() {
            html! { <p>{ "Logins will be added automatically as required to obtain tokens." }</p> }
        } else {
            html! { <ul>{
                for list.iter().map(|(uri, _)| {
                    // FIXME Some of this cloning is necessary due to link.callback taking a Fn
                    // rather than a FnOnce, but some might be avoided
                    let uri2 = uri.clone();
                    html! { <li>{ uri.clone() }{ " " }<button onclick={link.callback(move |_| LogoutFrom(uri2.clone()))}>{ "Logout" }</button></li> }
                })
            }</ul> }
        }
    }

    fn view_bluetooth_list(&self, ctx: &Context<Self>) -> Html {
        let link = ctx.link();
        let current_address = web_sys::window().unwrap().location().href().unwrap();

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
                    let idle_bright = link.callback({let id = id.to_string(); move |_| SetIdle(id.clone(), 4)});
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
                                <button onclick={ idle_bright }>{ "bright" }</button>
                            </p>
                        </>
                    }
                } else {
                    html! { <p>{ "Device currently not connected." }</p> }
                };

                let mut sec_assoc = html! { <p>{ "No security identity known" }</p> };

                if let Some(rs_identity) = &con.rs_identity {
                    sec_assoc = html! { <p>{ "Security association: " }{ &rs_identity.audience }{ " at " }{ &rs_identity.as_uri }</p> };

                    if let Some(login_uri) = &con.login_uri {
                        if let Ok(mut login_uri) = url::Url::parse(login_uri) {
                            login_uri.set_query(Some(&format!("append_and_redirect={}#{};", current_address, rs_identity.as_uri)));
                            sec_assoc = html! { <> { sec_assoc } <p><b>{ "Login required through " }<a href={ login_uri.to_string() }>{ con.login_uri.as_ref().unwrap() }</a></b></p></> };
                        }
                    }
                    // else, we'd need to take the as_uri and strip it out from our fragment to log
                    // out
                }

                if let Some(token) = &con.access_token {
                    sec_assoc = html! { <> { sec_assoc } <p>{ "Token: " }<tt>{ token }</tt></p> </> };
                }

                html! {
                    <li>
                        { operative }
                        { sec_assoc }
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
fn panic(info: &core::panic::PanicInfo<'_>) {
    indicate_panic_happened();
    console_error_panic_hook::hook(info);
}

pub fn main() {
    console_log::init_with_level(log::Level::Debug).expect("Console not available for logging");

    // Note that panics before this line would not be caugt, but it's not worth the confusion to
    // pull in console_error_panic_hook just to get that feature one line earlier.
    yew::Renderer::<Model>::new().render();
    yew::set_custom_panic_hook(Box::new(panic));

    log::info!("App started.");

    do_oscore_test().unwrap();
    log::info!("OSCORE tests passed");
}

pub fn do_oscore_test() -> Result<(), &'static str> {
    use core::mem::MaybeUninit;

    use coap_message::{MessageOption, MinimalWritableMessage, ReadableMessage};

    use liboscore::raw;

    // From OSCORE plug test, security context A
    let immutables = liboscore::PrimitiveImmutables::derive(
        liboscore::HkdfAlg::from_number(5).unwrap(),
        b"\x9e\x7c\xa9\x22\x23\x78\x63\x40",
        b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10",
        None,
        liboscore::AeadAlg::from_number(24).unwrap(),
        b"\x01",
        b"",
    )
    .unwrap();

    let mut primitive = liboscore::PrimitiveContext::new_from_fresh_material(immutables);

    let mut msg = coap_message::heapmessage::HeapMessage::new();
    let oscopt = b"\x09\x00";
    msg.add_option(9, oscopt);
    msg.set_payload(b"\x5c\x94\xc1\x29\x80\xfd\x93\x68\x4f\x37\x1e\xb2\xf5\x25\xa2\x69\x3b\x47\x4d\x5e\x37\x16\x45\x67\x63\x74\xe6\x8d\x4c\x20\x4a\xdb");

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

#[no_mangle]
pub unsafe extern "C" fn abort() {
    panic!("Abort called from C");
}

#[no_mangle]
pub unsafe extern "C" fn __assert_fail(_: i32, _: i32, _: i32, _: i32) {
    panic!("Assert failed in C");
}
