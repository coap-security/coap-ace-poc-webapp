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

mod ble;

/// Main application component
///
/// This renders to the full application view, and hooks up its UI and network elements to receive
/// [Message]s.
struct Model {
    blepool: Option<ble::BlePool>,
    //
    // Not storing some pool for running async functions in -- rather trusting wasm_bindgen_futures
    // that its spawn_local is efficient (the implementation does look like it's running on a
    // single big global executor) -- or is it really ctx.link().send_future that is the way to go?

    tokens: std::vec::Vec<dcaf::AccessTokenResponse>,
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
    SomethingBleChanged(futures::channel::mpsc::Receiver<ble::BackToFrontMessage>, ble::BackToFrontMessage),
    NoOp,
}
use Message::*;

impl Model {
    /// An allways-running yew "send_future" that waits for changes from the Bluetooth side, and
    /// passes them on as events. It also passes on the queue, so that when the model reacts to the
    /// message, it can start the cycle anew.
    fn link_ble_queue(ctx: &Context<Self>, mut queue: futures::channel::mpsc::Receiver<ble::BackToFrontMessage>) {
        ctx.link().send_future(async move {
            use futures::stream::StreamExt;
            let message = queue.next().await;

            match message {
                Some(message) => SomethingBleChanged(queue, message),
                None => {
                    log::error!("BLE pool ceased sending messages, won't try listening for them any more.");
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
        let mut tokens: std::vec::Vec<dcaf::AccessTokenResponse> = Default::default();
        let response_from_ace_java = hex_literal::hex!("
        a2 01 58 65 d0 83 44 a1  01 18 1f a1 05 4d 67 d8
        13 d2 cd bc 28 59 f0 c2  e9 f3 30 58 4c f3 0b 8f
        55 a8 af 8d 1d d2 0d c0  db 44 68 50 e6 45 39 39
        6b 0f ac fd 8b ea ef fd  9b 03 93 98 6e f9 d2 f8
        e7 18 a3 72 ef 4c 4f b9  a6 7e f2 d2 40 26 02 34
        5a 76 71 d4 23 08 5f f3  14 48 5a 8a f1 fd e4 1f
        10 dc 17 20 d0 23 64 d5  0b 08 a1 04 a4 00 41 02
        02 50 a4 ac 59 1b d4 1c  d6 21 ef a7 92 53 6a 4e
        e5 e0 05 41 8c 06 41 02
        ");
        use dcaf::ToCborMap;
        tokens.push(dcaf::AccessTokenResponse::deserialize_from(response_from_ace_java.as_slice()).unwrap());

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
            tokens,
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

            NoOp => {
                false
            }
        }
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let link = ctx.link();

        let has_bluetooth = self.blepool.is_some();

        let bluetooth_button = match has_bluetooth {
            true => html! { <button onclick={link.callback(|_| ScanBle)}>{ "Add device" }</button> },
            false => html! { <button disabled=true title="Bluetooth not available in this browser">{ "Add device" }</button> }
        };

        let bluetooth_list = match &self.blepool {
            Some(p) => html! { <ul class="devices">
                { for p.active_connections().map(|(id, name)| {
                    let name = name.unwrap_or("(unnamed)");
                    let temp = p.latest_temperature(id)
                        .map(|t| format!("{t} °C"))
                        .unwrap_or_else(|| "temperature unknown".to_string());
                    let read_temp = link.callback({let id = id.to_string(); move |_| ReadTemperature(id.clone())});
                    let identify = link.callback({let id = id.to_string(); move |_| Identify(id.clone())});
                    let idle_dark = link.callback({let id = id.to_string(); move |_| SetIdle(id.clone(), 0)});
                    let idle_bright = link.callback({let id = id.to_string(); move |_| SetIdle(id.clone(), 4)});
                    html! {
                        <li>
                            <span class="name">{ &name }</span>{ ": " }
                            { &temp }<button onclick={ read_temp }>{ "Read temp." }</button>
                            <button onclick={ identify }>{ "Identify" }</button>
                            <button onclick={ idle_dark }>{ "Idle dark" }</button>
                            <button onclick={ idle_bright }>{ "Idle bright" }</button>
                        </li>
                    }
                }) }
                </ul> },
            None => html! { <p>{ "Bluetooth not available in this browser" }</p> },
        };

        let token_list = html! { <ul class="tokens">
            { for self.tokens.iter().map(|t| html! {
                <li>{ format!("{:?}", t) }</li>
            })}
            </ul>
        };

        html! {
            <div>
                <h1>{ "CoAP ACE PoC: The App" }</h1>
                <h2>{ "Devices" }</h2>
                { bluetooth_button }
                { bluetooth_list }

                <h2>{ "Tokens" }</h2>
                { token_list }
            </div>
        }
    }
}

pub fn main() {
    std::panic::set_hook(Box::new(console_error_panic_hook::hook));

    console_log::init_with_level(log::Level::Debug)
        .expect("Console not available for logging");

    yew::start_app::<Model>();

    log::info!("App started.");

    do_oscore_test().unwrap();
    log::info!("OSCORE tests passed");
}

pub fn do_oscore_test() -> Result<(), &'static str> {
    use core::mem::MaybeUninit;

    use coap_message::{ReadableMessage, MinimalWritableMessage, MessageOption};

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
            let ret = raw::oscore_unprotect_request(msg, unprotected.as_mut_ptr(), &header.into_inner(), primitive.as_mut(), request_id.as_mut_ptr());
            assert!(ret == raw::oscore_unprotect_request_result_OSCORE_UNPROTECT_REQUEST_OK);
            let unprotected = unprotected.assume_init();

            let unprotected = liboscore::ProtectedMessage::new(unprotected);
            assert!(unprotected.code() == 1);

            let mut message_options = unprotected.options().fuse();
            let mut ref_options = [(11, "oscore"), (11, "hello"), (11, "1")].into_iter().fuse();
            for (msg_o, ref_o) in (&mut message_options).zip(&mut ref_options) {
                assert!(msg_o.number() == ref_o.0);
                assert!(msg_o.value() == ref_o.1.as_bytes());
            }
            assert!(message_options.next().is_none(), "Message contained extra options");
            assert!(ref_options.next().is_none(), "Message didn't contain the reference options");
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
