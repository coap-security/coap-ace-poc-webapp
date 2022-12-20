//! Implementation fo CoAP-over-GATT and the application specific requests.
//!
//! This module is split in two main structs:
//!
//! * [BlePool] is owned by the front end, and has synchronous methods as well as a notificaiton
//!   channel into yew.
//!
//! * [BlePoolBackend] runs itself in a dedicated task, and is independend of yew or (ideally) the
//!   application. It deals in asyncs.
//!
//! FIXME: Split the pure CoAP-over-GATT from application specifics, and possibly even the
//! application specifics from the yew-specific async adapter

// From CoAP-over-GATT draft
const UUID_US: &'static str = "8df804b7-3300-496d-9dfa-f8fb40a236bc";
const UUID_UC: &'static str = "2a58fc3f-3c62-4ecc-8167-d66d4d9410c2";



/// Helper trait to run `Into<JsFuture>` in a chained style
trait PromiseExt {
    fn js2rs(self) -> wasm_bindgen_futures::JsFuture;
}

impl PromiseExt for js_sys::Promise {
    fn js2rs(self) -> wasm_bindgen_futures::JsFuture {
        self.into()
    }
}

type DeviceId = String;

#[derive(Debug)]
pub enum FrontToBackMessage {
    /// Probe for any available device
    FindAnyDevice,
    /// Read temperature. Results in a ReceivedTemperature on success.
    ReadTemperature(DeviceId),
    /// Make the device blink. Does not cause a response.
    Identify(DeviceId),
    /// Set the number of LEDs active when identify is not running
    SetIdle(DeviceId, u8),
}
use FrontToBackMessage::*;

#[derive(Debug)]
pub enum BackToFrontMessage {
    /// The list of devices has changed
    ///
    /// (Alternatively, this could be expressed in a series of removals and and additions)
    UpdateDeviceList(Vec<(DeviceId, Option<String>)>),
    /// A temperature reading was obtained from a device
    ReceivedTemperature(DeviceId, Option<f32>),
}
use BackToFrontMessage::*;

/// The yew-side part of the BLE pool. It is owned by the front end task, and keeps copies of
/// everything it can't synchronously obtain from the backend. It has synchronous accessors (which
/// reflect the current state), and sends messages asynchronously processed by a [BlePoolBackend].
///
/// Rather than processing the back2front messages on its own, it produces the queue on startup, so
/// that yew can await that owned queue, and pass back2front down while still having the struct
/// available all the time.
pub struct BlePool {
    front2back: futures::channel::mpsc::Sender<FrontToBackMessage>,
    most_recent_connections: Vec<(DeviceId, Option<String>)>,
    most_recent_temperatures: std::collections::HashMap<DeviceId, f32>,
}

#[derive(Debug)]
pub struct NoWebBluetoothSupport;

/// The parts of the BlePool that are runin their own task
struct BlePoolBackend {
    front2back: futures::channel::mpsc::Receiver<FrontToBackMessage>,
    back2front: futures::channel::mpsc::Sender<BackToFrontMessage>,
    connections: std::collections::HashMap<DeviceId, BleConnection>,
    security_contexts: std::collections::HashMap<String, liboscore::PrimitiveContext>,
}

struct BleConnection {
    name: Option<String>,
    characteristic: web_sys::BluetoothRemoteGattCharacteristic,
}

impl BlePool {
    /// Create a new BLE pool.
    ///
    /// On success, along with the pool, a receiver is passed: Keep receiving messages from there,
    /// and pass them in through the notify function.
    pub fn new() -> Result<(Self, futures::channel::mpsc::Receiver<BackToFrontMessage>), NoWebBluetoothSupport> {
        let navigator = web_sys::window().expect("This is running inside a web browser")
            .navigator();

        let bluetooth = navigator.bluetooth()
            .ok_or(NoWebBluetoothSupport)?;

        // This can overflow; ideally, the front-end will disable its buttons while full
        let front2back = futures::channel::mpsc::channel(1);
        // This won't overflow realistically: everything that pushes in here can just wait
        let back2front = futures::channel::mpsc::channel(1);

        wasm_bindgen_futures::spawn_local(BlePoolBackend::run(
                bluetooth,
                front2back.1,
                back2front.0,
                ));

        Ok((BlePool {
                front2back: front2back.0,
                most_recent_connections: Default::default(),
                most_recent_temperatures: Default::default(),
            },
            back2front.1,
        ))
    }

    pub fn connect(&mut self) {
        self.request(FindAnyDevice);
    }

    pub fn read_temperature(&mut self, device: DeviceId) {
        self.request(ReadTemperature(device));
    }

    pub fn identify(&mut self, device: DeviceId) {
        self.request(Identify(device));
    }

    pub fn set_idle(&mut self, device: DeviceId, level: u8) {
        self.request(SetIdle(device, level));
    }

    pub fn latest_temperature(&self, device: &str) -> Option<f32> {
        self.most_recent_temperatures.get(device).copied()
    }

    pub fn active_connections(&self) -> impl Iterator<Item=(&str, Option<&str>)> {
        self.most_recent_connections.iter().map(|(i, n)| (i.as_ref(), n.as_ref().map(|n| n.as_ref())))
    }

    /// Request an action asynchronously from the backend.
    ///
    /// The backend will probably send notifications back at some point.
    fn request(&mut self, message: FrontToBackMessage) {
        self.front2back.try_send(message)
            .unwrap_or_else(|_| {
                log::error!("Can not enqueue request: queue full. Proper queue management that disables buttons when the queue is full would circumvent that.");
            });
    }

    pub fn notify(&mut self, message: BackToFrontMessage) {
        match message {
            UpdateDeviceList(list) => {
                self.most_recent_connections = list;
            }
            ReceivedTemperature(id, Some(temp)) => {
                self.most_recent_temperatures.insert(id, temp);
            }
            ReceivedTemperature(id, None) => {
                self.most_recent_temperatures.remove(&id);
            }
        }
    }
}

impl BlePoolBackend {
    // In a sense it's suboptimal for this be blocked on by .run(), but it makes general state
    // handling easier; could be revisited, though.
    async fn try_connect(&mut self, bluetooth: &web_sys::Bluetooth) -> Result<DeviceId, &'static str> {
        use web_sys::{RequestDeviceOptions, BluetoothLeScanFilterInit, BluetoothRemoteGattServer, BluetoothRemoteGattService, BluetoothRemoteGattCharacteristic};

        let device = wasm_bindgen_futures::JsFuture::from(bluetooth
            .request_device(
                RequestDeviceOptions::new().filters(
                    &[BluetoothLeScanFilterInit::new().services(
                        &[wasm_bindgen::JsValue::from(UUID_US)].iter().collect::<js_sys::Array>())
                    ].iter().collect::<js_sys::Array>()
            ))
            ).await
            .map_err(|_| "No device actually selected")?;

        let device: web_sys::BluetoothDevice = device.into();
        log::info!("New device: {:?}, {:?}...", device.id(), device.name());

        // FIXME: do all the "device goes away" stuff properly (but right now we don't need it for
        // the essential demo)
//         let changed = |evt: web_sys::Event| { log::info!("Event: {:?}", evt); };
//         let changed = wasm_bindgen::closure::Closure::<dyn FnMut(web_sys::Event)>::new(changed);
//         let changed = Box::new(changed);
//         // FIXME CONTINUE HERE: Things work fine as long as that closure is kept around, we'll just
//         // make that box (probably doesn't even need boxing, given nobody asks for pinning here)
//         // part of our "connection".
//         let changed = Box::leak(changed);
//         use wasm_bindgen::JsCast;
//         device.set_ongattserverdisconnected(Some(changed.as_ref().unchecked_ref()));

        let server: BluetoothRemoteGattServer = device.gatt()
            .ok_or("No GATT found on device")?
            .connect()
            .js2rs().await
            .map_err(|_| "Failed to connect to GATT")?
            .into();

        let service: BluetoothRemoteGattService = server
            .get_primary_service_with_str(UUID_US)
            .js2rs().await
            .map_err(|_| "No CoAP service")?
            .into();

        let mut characteristic: BluetoothRemoteGattCharacteristic = service
            .get_characteristic_with_str(UUID_UC)
            .js2rs().await
            .map_err(|_| "No CoAP service")?
            .into();

        if let Ok(c) = characteristic
            .start_notifications()
            .js2rs().await {
            characteristic = c.into();
        } else {
            // FIXME: A more elaborate GATT client implementation might keep notifications off as
            // long as it's neither providing a CoAP server nor currently observing.
            log::info!("Device does not suport notification / indication. That's fine, it won't be sending requests or support observations anyway.");
        }

        log::info!("... actually made it through");

        let id = device.id();

        self.connections.insert(id.clone(), BleConnection {
            characteristic,
            name: device.name(),
        });

        Ok(id)
    }

    /// Send a message to the front end
    ///
    /// This silently discards sending errors: If this direction of the connection goes away,
    /// front2back will go away as well, and there we can handle clean shutdown better.
    async fn notify(&mut self, msg: BackToFrontMessage) {
        use futures::sink::SinkExt;
        let _ = self.back2front.send(msg).await;
    }

    async fn notify_device_list(&mut self) {
        let new_list = self.connections
            .iter()
            .map(|(id, con)| (id.clone(), con.name.as_ref().map(|n| n.clone())))
            .collect();

        self.notify(UpdateDeviceList(new_list)).await;
    }

    async fn run(
        bluetooth: web_sys::Bluetooth,
        front2back: futures::channel::mpsc::Receiver<FrontToBackMessage>,
        back2front: futures::channel::mpsc::Sender<BackToFrontMessage>,
        ) {

        let mut self_ = Self {
            front2back,
            back2front,
            connections: Default::default(),
            security_contexts: Default::default(),
        };

        loop {
            use futures::stream::StreamExt;
            let message = self_.front2back.next().await;

            match message
            {
                Some(FindAnyDevice) => {
                    match self_.try_connect(&bluetooth).await {
                        Ok(id) => {
                            self_.notify_device_list().await;
                            self_.write_time(&id).await;

                            let token_response = hex_literal::hex!("
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
                            let token_response = dcaf::AccessTokenResponse::deserialize_from(token_response.as_slice())
                                .unwrap();
                            dbg!(&token_response);
                            let material = match token_response.cnf {
                                Some(dcaf::ProofOfPossessionKey::OscoreInputMaterial(mat)) => mat,
                                _ => panic!("Token response was not for ACE OSCORE profile")
                            };

                            let token = token_response.access_token;

                            // "The use of a 64-bit long random number is RECOMMENDED"
                            let nonce1 = &rand::random::<[u8; 8]>();
                            // Picking an arbitrary long one that's not even unique: We're only a
                            // server with this peer, so this gets never sent, and we always know
                            // from context when to use this one.
                            let client_recipient_id = b"1234";
                            log::warn!("My recipient ID is {:?}", client_recipient_id);

                            match self_.write_authzinfo(&id, nonce1, client_recipient_id, &token).await {
                                Ok((nonce2, server_recipient_id)) => {
                                    log::info!("Should derive using {nonce2:?} and {server_recipient_id:?}");

                                    let context = ace_oscore_helpers::oscore_claims::derive(
                                        material,
                                        nonce1,
                                        &nonce2,
                                        &server_recipient_id,
                                        client_recipient_id,
                                        ).unwrap();

                                    log::info!("Derived context {:?} now to be used with {:?}", &context, &id);
                                    self_.security_contexts.insert(id.clone(), context);
                                }
                                Err(e) => {
                                    log::error!("Error occurred attempting to send a token: {:?}", e);
                                }
                            }
                        },
                        Err(e) => {
                            log::error!("Could not connect: {e}");
                            continue;
                        }
                    };
                },
                Some(ReadTemperature(id)) => {
                    let temp = self_.read_temperature(&id).await;
                    self_.notify(ReceivedTemperature(id, temp.ok())).await;
                }
                Some(Identify(id)) => {
                    self_.identify(&id).await;
                }
                Some(SetIdle(id, level)) => {
                    self_.set_idle(&id, level).await;
                }
                // Whatever spawned us doesn't want us any more
                None => break
            }
        }
    }

    // Note that we hand out a &mut ReadMessage as that also implements (some small parts of)
    // MutableWritableMessage
    async fn send_request<R, CARRY>(
        &mut self,
        id: &str,
        write_request: impl FnOnce(&mut coap_gatt_utils::WriteMessage<'_>) -> CARRY,
        read_response: impl FnOnce(&mut coap_gatt_utils::ReadWriteMessage<'_>, CARRY) -> R,
    ) -> R {
        let connection = &self.connections[id];

        let mut carry = None;
        let mut request = coap_gatt_utils::write::<400>(|msg| {carry = Some(write_request(msg));});
        // FIXME: Maybe change coap_gatt_utils so this nees less patching?
        let carry = carry.expect("write always invokes the writer");

        log::debug!("Writing to charcteristic with length {}", request.len());
        
        connection.characteristic.write_value_with_u8_array(&mut request)
            .js2rs()
            .await
            // FIXME: How can we do better here? Can this be discovered in advance, and then made
            // usable by the application in `.available_len()`?
            .expect("Request exceeds length the device can accept");

        let mut response = loop {
            let response: js_sys::DataView = connection.characteristic.read_value()
                .js2rs()
                .await
                .unwrap()
                .into();
            // FIXME I'd rather not allocate here
            let response = js_sys::Uint8Array::new(&response.buffer()).to_vec();

            if response.len() > 0 {
                break response;
            }

            // FIXME exponential backoff, eventually fail
            log::info!("Read was zero-length, trying again...");
        };

        let mut coap_response = coap_gatt_utils::parse_mut(&mut response)
            .unwrap();

        read_response(&mut coap_response, carry)
    }

    async fn send_request_protected<R, CARRY>(
        &mut self,
        id: &str,
        write_request: impl FnOnce(&mut liboscore::ProtectedMessage) -> CARRY,
        read_response: impl FnOnce(&liboscore::ProtectedMessage, CARRY) -> R,
    ) -> R {
        // While we process this, no other access to the context is possible. That's kind of
        // sub-optimal, but a) a practical simplification for tossing it around between to
        // closures, and b) kind of a consequence of PrimitiveContext only being usable &mut rather
        // than being usable through the more elaborate means provided by liboscore.
        let mut ctx = self.security_contexts.remove(id)
            .unwrap();

        let (ctx, user_response) = self.send_request(
            id,
            |request| {
                let (correlation, user_carry) = liboscore::protect_request(
                    request,
                    &mut ctx,
                    |request| {
                        write_request(request)
                    }
                );
                (correlation, ctx, user_carry)
            },
            |response, (mut correlation, mut ctx, user_carry)| {
                use coap_message::{MessageOption, ReadableMessage};
                // FIXME: We need to copy things out because ReadableMessage by design only hands out
                // short-lived values (so they can be built in the iterator if need be). On the
                // plus side, this means that we're not running into the lifetime trouble one'd
                // expect when passing unprotect_response both a mutable message *and* an option
                // that references data inside it.
                let mut oscore_option: Option<Vec<u8>> = None;
                for o in response.options() {
                    if o.number() == coap_numbers::option::OSCORE {
                        oscore_option = Some(o.value().into());
                        break;
                    }
                }
                let oscore_option = liboscore::OscoreOption::parse(
                        oscore_option.as_ref().expect("No OSCORE option") // FIXME error handling
                    )
                    .expect("Unparsable OSCORE option");

                let user_response = liboscore::unprotect_response(
                    response,
                    &mut ctx,
                    oscore_option,
                    &mut correlation,
                    |response| read_response(response, user_carry),
                );
                (ctx, user_response)
            }).await;

        self.security_contexts.insert(id.to_string(), ctx);

        user_response
    }

    async fn write_time(&mut self, id: &str) {
        let time_now: u32 = instant::SystemTime::now().duration_since(instant::SystemTime::UNIX_EPOCH).unwrap().as_secs().try_into().expect("Code not used beyond 2076");
        // This would be moderately smoother if a WindowedInfinityWithETag writer could ve
        // constructed easily for a message when we don't expect blockwising and are in a request
        let mut time_now_buffer = Vec::with_capacity(5);
        ciborium::ser::into_writer(&time_now, &mut time_now_buffer).expect("Time can be encoded");
        self.send_request(id,
                     |request| {
                        use coap_message::MinimalWritableMessage;
                        request.set_code(coap_numbers::code::PUT.try_into().unwrap());
                        request.add_option(coap_numbers::option::URI_PATH.try_into().unwrap(), b"time");
                        request.set_payload(&time_now_buffer);
                     },
                     |response, ()| {
                        use coap_message::ReadableMessage;
                        log::info!("Time written, code {:?}", response.code());
                     }).await;
    }

    async fn read_temperature(&mut self, id: &str) -> Result<f32, &'static str> {
        self.send_request_protected(&id,
             |request| {
                use coap_message::MinimalWritableMessage;
                request.set_code(coap_numbers::code::GET.try_into().unwrap());
                request.add_option(coap_numbers::option::URI_PATH.try_into().unwrap(), b"temp");
                request.set_payload(&[]);
             },
             |response, ()| {
                use coap_message::ReadableMessage;
                if u8::from(response.code()) != coap_numbers::code::CONTENT {
                    Err("Unsuccessful request")
                } else {
                    Ok(ciborium::de::from_reader(response.payload()))
                }
             }).await?
           .map_err(|_| "CBOR parsing error")
           .and_then(|v: ciborium::value::Value| {
               // Copied from my coap-handler demos
               //
               // See also https://github.com/enarx/ciborium/issues/21
               use ciborium::value::Value::{Tag, Array, Integer};
               match v {
                   Tag(5, b) => {
                       match b.as_ref() {
                           Array(v) => match v.as_slice() {
                               [Integer(v1), Integer(v2)] => {
                                   let exponent = i32::try_from(*v1)
                                       .map_err(|_| "Exponent exceeds i32 range")?;
                                   let mantissa = i32::try_from(*v2)
                                       .map_err(|_| "Mantissa exceeds i32 range")?
                                        as f32;
                                   Ok((2.0f32).powi(exponent) * mantissa)
                               },
                               _ => Err("Bigfloat tags array of wrong length"),
                           }
                           _ => Err("Bigfloat should tag array"),
                       }
                   }
                   _ => Err("Parsed but not a bigfloat"),
               }
           })
    }

    async fn identify(&mut self, id: &str) {
        // No error handling because this resource returns success anyway (and the success is
        // indicated remotely)
        self.send_request_protected(&id,
             |request| {
                use coap_message::MinimalWritableMessage;
                request.set_code(coap_numbers::code::POST.try_into().unwrap());
                request.add_option(coap_numbers::option::URI_PATH.try_into().unwrap(), b"identify");
                request.set_payload(&[]);
             },
             |_, ()| {}).await
    }

    async fn set_idle(&mut self, id: &str, level: u8) {
        // This would be moderately smoother if a WindowedInfinityWithETag writer could ve
        // constructed easily for a message when we don't expect blockwising and are in a request
        let mut level_buffer = Vec::with_capacity(2);
        ciborium::ser::into_writer(&level, &mut level_buffer).expect("Level can be encoded");
        // No error handling because this resource returns success anyway (and the success is
        // indicated remotely)
        self.send_request_protected(&id,
             |request| {
                use coap_message::MinimalWritableMessage;
                request.set_code(coap_numbers::code::PUT.try_into().unwrap());
                request.add_option(coap_numbers::option::URI_PATH.try_into().unwrap(), b"leds");
                request.set_payload(&level_buffer);
             },
             |_, ()| {}).await
    }

    // FIXME actually token plus local nonce1 and id1
    /// Write a given `token` to the `/autz-info` endpoint of the device identified by `id`, with
    /// the given `nonce` and `id1` (client recipient ID).
    ///
    /// Returns `(nonce2, id2)` on success, where the latter is the server's chosen recipient ID.
    async fn write_authzinfo(&mut self, id: &str, nonce1: &[u8], id1: &[u8], token: &[u8]) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
        use ciborium_ll::{Encoder, Header};
        let mut payload = Vec::with_capacity(token.len() + 15);
        let mut encoder = Encoder::from(&mut payload);

        encoder.push(Header::Map(Some(3))).unwrap();
        encoder.push(Header::Positive(ace_oscore_helpers::ACCESS_TOKEN)).unwrap();
        encoder.bytes(&token, None).unwrap();
        encoder.push(Header::Positive(ace_oscore_helpers::NONCE1)).unwrap();
        encoder.bytes(nonce1, None).unwrap();
        encoder.push(Header::Positive(ace_oscore_helpers::ACE_CLIENT_RECIPIENTID)).unwrap();
        encoder.bytes(id1, None).unwrap();

        self.send_request(id,
                |request| {
                   use coap_message::MinimalWritableMessage;
                   request.set_code(coap_numbers::code::POST.try_into().unwrap());
                   request.add_option(coap_numbers::option::URI_PATH.try_into().unwrap(), b"authz-info");
                   request.set_payload(&payload);
                },
                |response, ()| {
                    use coap_message::ReadableMessage;
                    if response.code() == coap_numbers::code::CHANGED {
                        let response = response.payload();
                        extern crate alloc;
                        let mut response: alloc::collections::BTreeMap<u64, serde_bytes::ByteBuf> = ciborium::de::from_reader(response)
                            .map_err(|_| "Wrong response structure")?;
                        let nonce2 = response.remove(&ace_oscore_helpers::NONCE2)
                            .ok_or("Nonce2 missing")?;
                        let server_recipient_id = response.remove(&ace_oscore_helpers::ACE_SERVER_RECIPIENTID)
                            .ok_or("Server recipient ID missing")?;
                        if !response.is_empty() {
                            return Err("Left-over elements");
                        }

                        log::info!("authz-info response {:?}", response);

                        Ok((nonce2.into_vec(), server_recipient_id.into_vec()))
                    } else {
                        Err("Unsuccessful code")
                    }
                 }).await
    }
}
