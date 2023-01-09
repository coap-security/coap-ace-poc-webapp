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
type RequestCreationHints =
    ace_oscore_helpers::request_creation_hints::RequestCreationHints<String>;

/// Data exposed by teh BLE module toward the front end
#[derive(Debug)]
pub struct DeviceDetails {
    /// ID needed to do actions on the device.
    ///
    /// Absence indicates that the device is not connected.
    pub id: Option<DeviceId>,
    /// User-visible name if provided at BLE level
    pub name: Option<String>,
    /// Claimed cryptographic identity
    pub rs_identity: Option<RequestCreationHints>,
    /// URI a failed attempt to abtain an OSCORE token from this RCH redirected to
    pub login_uri: Option<String>,
    pub oscore_established: bool,
}

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
    UpdateDeviceList(Vec<DeviceDetails>, Vec<(RequestCreationHints, String)>),
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
    most_recent_connections: Vec<DeviceDetails>,
    most_recent_temperatures: std::collections::HashMap<DeviceId, f32>,
    recent_tokens: Vec<(RequestCreationHints, String)>,
}

#[derive(Debug)]
pub struct NoWebBluetoothSupport;

/// The parts of the BlePool that are runin their own task
struct BlePoolBackend {
    front2back: futures::channel::mpsc::Receiver<FrontToBackMessage>,
    back2front: futures::channel::mpsc::Sender<BackToFrontMessage>,
    /// BLE connections
    connections: std::collections::HashMap<DeviceId, BleConnection>,
    /// Most recent request creation hint obtained from the device with the given ID
    rs_identities: std::collections::HashMap<DeviceId, RequestCreationHints>,
    /// Login URIs that we were redirected to
    login_uris: std::collections::HashMap<String, String>,
    /// Tokens requested from the AS
    tokens: std::collections::HashMap<RequestCreationHints, dcaf::AccessTokenResponse>,
    /// Established security contexts
    security_contexts: std::collections::HashMap<DeviceId, liboscore::PrimitiveContext>,
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
    pub fn new(
    ) -> Result<(Self, futures::channel::mpsc::Receiver<BackToFrontMessage>), NoWebBluetoothSupport>
    {
        let navigator = web_sys::window()
            .expect("This is running inside a web browser")
            .navigator();

        let bluetooth = navigator.bluetooth().ok_or(NoWebBluetoothSupport)?;

        // This can overflow; ideally, the front-end will disable its buttons while full
        let front2back = futures::channel::mpsc::channel(1);
        // This won't overflow realistically: everything that pushes in here can just wait
        let back2front = futures::channel::mpsc::channel(1);

        wasm_bindgen_futures::spawn_local(BlePoolBackend::run(
            bluetooth,
            front2back.1,
            back2front.0,
        ));

        Ok((
            BlePool {
                front2back: front2back.0,
                most_recent_connections: Default::default(),
                most_recent_temperatures: Default::default(),
                recent_tokens: Default::default(),
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

    pub fn active_connections(&self) -> impl Iterator<Item = &DeviceDetails> {
        self.most_recent_connections.iter()
    }

    pub fn tokens(&self) -> impl Iterator<Item = &(RequestCreationHints, String)> {
        self.recent_tokens.iter()
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
            UpdateDeviceList(list, tokens) => {
                self.most_recent_connections = list;
                self.recent_tokens = tokens;
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
    async fn try_connect(
        &mut self,
        bluetooth: &web_sys::Bluetooth,
    ) -> Result<DeviceId, &'static str> {
        use web_sys::{
            BluetoothLeScanFilterInit, BluetoothRemoteGattCharacteristic,
            BluetoothRemoteGattServer, BluetoothRemoteGattService, RequestDeviceOptions,
        };

        let device = wasm_bindgen_futures::JsFuture::from(
            bluetooth.request_device(
                RequestDeviceOptions::new().filters(
                    &[BluetoothLeScanFilterInit::new().services(
                        &[wasm_bindgen::JsValue::from(UUID_US)]
                            .iter()
                            .collect::<js_sys::Array>(),
                    )]
                    .iter()
                    .collect::<js_sys::Array>(),
                ),
            ),
        )
        .await
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

        let server: BluetoothRemoteGattServer = device
            .gatt()
            .ok_or("No GATT found on device")?
            .connect()
            .js2rs()
            .await
            .map_err(|_| "Failed to connect to GATT")?
            .into();

        let service: BluetoothRemoteGattService = server
            .get_primary_service_with_str(UUID_US)
            .js2rs()
            .await
            .map_err(|_| "No CoAP service")?
            .into();

        let mut characteristic: BluetoothRemoteGattCharacteristic = service
            .get_characteristic_with_str(UUID_UC)
            .js2rs()
            .await
            .map_err(|_| "No CoAP service")?
            .into();

        if let Ok(c) = characteristic.start_notifications().js2rs().await {
            characteristic = c.into();
        } else {
            // FIXME: A more elaborate GATT client implementation might keep notifications off as
            // long as it's neither providing a CoAP server nor currently observing.
            log::info!("Device does not suport notification / indication. That's fine, it won't be sending requests or support observations anyway.");
        }

        log::info!("... actually made it through");

        let id = device.id();

        self.connections.insert(
            id.clone(),
            BleConnection {
                characteristic,
                name: device.name(),
            },
        );

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
        // Doing this through a new map is inefficient compared to making all things keyed by id be
        // a BTreeMap and mergesorting them, or to using a single map with many optional values.
        let mut ids = std::collections::HashSet::new();
        ids.extend(self.connections.keys());
        ids.extend(self.rs_identities.keys());

        let mut new_list: Vec<_> = ids
            .iter()
            .map(|id| {
                let id: &str = id.as_ref();
                let rs_identity = self.rs_identities.get(id);
                let con = self.connections.get(id);
                DeviceDetails {
                    id: Some(id.to_string()),
                    name: con.and_then(|c| Some(c.name.as_ref()?.clone())),
                    rs_identity: rs_identity.cloned(),
                    login_uri: rs_identity
                        .map(|i| &i.as_uri)
                        .and_then(|u| self.login_uris.get(u).map(|login| login.to_owned())),
                    oscore_established: self.security_contexts.contains_key(id),
                }
            })
            .collect();

        let tokens = self
            .tokens
            .iter()
            .map(|(rch, ath)| {
                (
                    rch.clone(),
                    format!(
                        "{}",
                        hex::encode(&ath.access_token[ath.access_token.len() - 4..])
                    ),
                )
            })
            .collect();

        self.notify(UpdateDeviceList(new_list, tokens)).await;
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
            rs_identities: Default::default(),
            login_uris: Default::default(),
            tokens: Default::default(),
            security_contexts: Default::default(),
        };

        loop {
            use futures::stream::StreamExt;
            let message = self_.front2back.next().await;

            match message {
                Some(FindAnyDevice) => {
                    match self_.try_connect(&bluetooth).await {
                        Ok(id) => {
                            self_.notify_device_list().await;
                            match self_.write_time(&id).await {
                                Ok(()) => (),
                                Err(e) => log::error!("Failed to write time: {}", e),
                            }

                            self_.try_get_rch(&id).await;
                            self_.try_get_token(&id).await;
                            self_.try_establish_security_context(&id).await;
                        }
                        Err(e) => {
                            log::error!("Could not connect: {e}");
                            continue;
                        }
                    };
                }
                Some(ReadTemperature(id)) => {
                    let temp = self_.read_temperature(&id).await;
                    self_.notify(ReceivedTemperature(id, temp.ok())).await;
                    if let Err(e) = temp {
                        log::error!("Failed to read temperature: {e}");
                    }
                }
                Some(Identify(id)) => {
                    if let Err(e) = self_.identify(&id).await {
                        log::error!("Failed to identify device: {e}");
                    }
                }
                Some(SetIdle(id, level)) => {
                    if let Err(e) = self_.set_idle(&id, level).await {
                        log::error!("Failed to identify device: {e}");
                    }
                }
                // Whatever spawned us doesn't want us any more
                None => break,
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
    ) -> Result<R, &'static str> {
        let connection = &self.connections[id];

        let mut carry = None;
        let mut request = coap_gatt_utils::write::<400>(|msg| {
            carry = Some(write_request(msg));
        });
        // FIXME: Maybe change coap_gatt_utils so this nees less patching?
        let carry = carry.expect("write always invokes the writer");

        log::debug!("Writing to charcteristic with length {}", request.len());

        let result = connection
            .characteristic
            .write_value_with_u8_array(&mut request)
            .js2rs()
            .await;

        match result {
            Ok(_) => (),
            Err(e) => {
                log::error!("Request could not be sent ({:?}), removing connection", e);
                self.connections.remove(id);
                self.notify_device_list().await;
                return Err("Failed to send request");
            }
        };

        let mut response = loop {
            let response = connection.characteristic.read_value().js2rs().await;
            let response: js_sys::DataView = match response {
                Ok(r) => r.into(),
                Err(e) => {
                    log::error!("Response could not be read ({:?}), removing connection", e);
                    self.connections.remove(id);
                    self.notify_device_list().await;
                    return Err("Failed to read response");
                }
            };
            // FIXME I'd rather not allocate here
            let response = js_sys::Uint8Array::new(&response.buffer()).to_vec();

            if response.len() > 0 {
                break response;
            }

            // FIXME exponential backoff, eventually fail
            log::info!("Read was zero-length, trying again...");
        };

        let mut coap_response = coap_gatt_utils::parse_mut(&mut response).unwrap();

        Ok(read_response(&mut coap_response, carry))
    }

    async fn send_request_protected<R, CARRY>(
        &mut self,
        id: &str,
        write_request: impl FnOnce(&mut liboscore::ProtectedMessage) -> CARRY,
        read_response: impl FnOnce(&liboscore::ProtectedMessage, CARRY) -> R,
    ) -> Result<R, &'static str> {
        self.try_get_rch(id).await;
        self.try_get_token(id).await;
        self.try_establish_security_context(id).await;

        // While we process this, no other access to the context is possible. That's kind of
        // sub-optimal, but a) a practical simplification for tossing it around between to
        // closures, and b) kind of a consequence of PrimitiveContext only being usable &mut rather
        // than being usable through the more elaborate means provided by liboscore.
        let mut ctx = self
            .security_contexts
            .remove(id)
            .ok_or("No security context available")?;

        let (ctx, user_response) = self
            .send_request(
                id,
                |request| {
                    let correlation_usercarry =
                        liboscore::protect_request(request, &mut ctx, |request| {
                            write_request(request)
                        });
                    (ctx, correlation_usercarry)
                },
                |response, (mut ctx, correlation_usercarry)| {
                    if let Ok((mut correlation, user_carry)) = correlation_usercarry {
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
                        let Some(oscore_option) = oscore_option.as_ref() else {
                            return (ctx, Err("No OSCORE option, server did not have a suitable context"))
                        };
                        let Ok(oscore_option) = liboscore::OscoreOption::parse(oscore_option) else {
                            return (ctx, Err("Server produced invalid OSCORE option"))
                        };

                        let user_response = liboscore::unprotect_response(
                            response,
                            &mut ctx,
                            oscore_option,
                            &mut correlation,
                            |response| read_response(response, user_carry),
                        )
                        .map_err(|_| "Error unprotecting the response");
                        (ctx, user_response)
                    } else {
                        (ctx, Err("Error encrypting the request"))
                    }
                },
            )
            .await?;

        if user_response.is_ok() {
            self.security_contexts.insert(id.to_string(), ctx);
        } else {
            // Let's not even put back the security context -- it just failed, so it's probably
            // broken. The token may or may not still be good.
            self.notify_device_list().await;
        }

        user_response
    }

    async fn write_time(&mut self, id: &str) -> Result<(), &'static str> {
        let time_now: u32 = instant::SystemTime::now()
            .duration_since(instant::SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .try_into()
            .expect("Code not used beyond 2076");
        // This would be moderately smoother if a WindowedInfinityWithETag writer could ve
        // constructed easily for a message when we don't expect blockwising and are in a request
        let mut time_now_buffer = Vec::with_capacity(5);
        ciborium::ser::into_writer(&time_now, &mut time_now_buffer).expect("Time can be encoded");
        self.send_request(
            id,
            |request| {
                use coap_message::MinimalWritableMessage;
                request.set_code(coap_numbers::code::PUT.try_into().unwrap());
                request.add_option(coap_numbers::option::URI_PATH.try_into().unwrap(), b"time");
                request.set_payload(&time_now_buffer);
            },
            |response, ()| {
                use coap_message::ReadableMessage;
                log::info!("Time written, code {:?}", response.code());
            },
        )
        .await
    }

    /// Try reading the temperature, but don't even try to do it through OSCORE
    ///
    /// This triggers a response that'll hopefully point us to the right AS and the RS's identity.
    async fn prod_temperature(&mut self, id: &str) -> Result<RequestCreationHints, &'static str> {
        self.send_request(
            &id,
            |request| {
                use coap_message::MinimalWritableMessage;
                request.set_code(coap_numbers::code::GET.try_into().unwrap());
                request.add_option(coap_numbers::option::URI_PATH.try_into().unwrap(), b"temp");
                request.set_payload(&[]);
            },
            |response, ()| {
                use coap_message::ReadableMessage;

                if u8::from(response.code()) != coap_numbers::code::UNAUTHORIZED {
                    return Err("Unprotected temeprature read yielded odd code");
                }

                RequestCreationHints::parse_cbor(response.payload())
            },
        )
        .await?
    }

    async fn read_temperature(&mut self, id: &str) -> Result<f32, &'static str> {
        self.send_request_protected(
            &id,
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
            },
        )
        .await??
        .map_err(|_| "CBOR parsing error")
        .and_then(|v: ciborium::value::Value| {
            // Copied from my coap-handler demos
            //
            // See also https://github.com/enarx/ciborium/issues/21
            use ciborium::value::Value::{Array, Integer, Tag};
            match v {
                Tag(5, b) => match b.as_ref() {
                    Array(v) => match v.as_slice() {
                        [Integer(v1), Integer(v2)] => {
                            let exponent =
                                i32::try_from(*v1).map_err(|_| "Exponent exceeds i32 range")?;
                            let mantissa = i32::try_from(*v2)
                                .map_err(|_| "Mantissa exceeds i32 range")?
                                as f32;
                            Ok((2.0f32).powi(exponent) * mantissa)
                        }
                        _ => Err("Bigfloat tags array of wrong length"),
                    },
                    _ => Err("Bigfloat should tag array"),
                },
                _ => Err("Parsed but not a bigfloat"),
            }
        })
    }

    async fn identify(&mut self, id: &str) -> Result<(), &'static str> {
        // No error handling because this resource returns success anyway (and the success is
        // indicated remotely)
        self.send_request_protected(
            &id,
            |request| {
                use coap_message::MinimalWritableMessage;
                request.set_code(coap_numbers::code::POST.try_into().unwrap());
                request.add_option(
                    coap_numbers::option::URI_PATH.try_into().unwrap(),
                    b"identify",
                );
                request.set_payload(&[]);
            },
            |_, ()| {},
        )
        .await
    }

    async fn set_idle(&mut self, id: &str, level: u8) -> Result<(), &'static str> {
        // This would be moderately smoother if a WindowedInfinityWithETag writer could ve
        // constructed easily for a message when we don't expect blockwising and are in a request
        let mut level_buffer = Vec::with_capacity(2);
        ciborium::ser::into_writer(&level, &mut level_buffer).expect("Level can be encoded");
        // No error handling because this resource returns success anyway (and the success is
        // indicated remotely)
        self.send_request_protected(
            &id,
            |request| {
                use coap_message::MinimalWritableMessage;
                request.set_code(coap_numbers::code::PUT.try_into().unwrap());
                request.add_option(coap_numbers::option::URI_PATH.try_into().unwrap(), b"leds");
                request.set_payload(&level_buffer);
            },
            |_, ()| {},
        )
        .await
    }

    // FIXME actually token plus local nonce1 and id1
    /// Write a given `token` to the `/autz-info` endpoint of the device identified by `id`, with
    /// the given `nonce` and `id1` (client recipient ID).
    ///
    /// Returns `(nonce2, id2)` on success, where the latter is the server's chosen recipient ID.
    async fn write_authzinfo(
        &mut self,
        id: &str,
        nonce1: &[u8],
        id1: &[u8],
        token: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
        use ciborium_ll::{Encoder, Header};
        let mut payload = Vec::with_capacity(token.len() + 15);
        let mut encoder = Encoder::from(&mut payload);

        encoder.push(Header::Map(Some(3))).unwrap();
        encoder
            .push(Header::Positive(ace_oscore_helpers::ACCESS_TOKEN))
            .unwrap();
        encoder.bytes(&token, None).unwrap();
        encoder
            .push(Header::Positive(ace_oscore_helpers::NONCE1))
            .unwrap();
        encoder.bytes(nonce1, None).unwrap();
        encoder
            .push(Header::Positive(ace_oscore_helpers::ACE_CLIENT_RECIPIENTID))
            .unwrap();
        encoder.bytes(id1, None).unwrap();

        self.send_request(
            id,
            |request| {
                use coap_message::MinimalWritableMessage;
                request.set_code(coap_numbers::code::POST.try_into().unwrap());
                request.add_option(
                    coap_numbers::option::URI_PATH.try_into().unwrap(),
                    b"authz-info",
                );
                request.set_payload(&payload);
            },
            |response, ()| {
                use coap_message::ReadableMessage;
                if response.code() == coap_numbers::code::CHANGED {
                    let response = response.payload();
                    extern crate alloc;
                    let mut response: alloc::collections::BTreeMap<u64, serde_bytes::ByteBuf> =
                        ciborium::de::from_reader(response)
                            .map_err(|_| "Wrong response structure")?;
                    let nonce2 = response
                        .remove(&ace_oscore_helpers::NONCE2)
                        .ok_or("Nonce2 missing")?;
                    let server_recipient_id = response
                        .remove(&ace_oscore_helpers::ACE_SERVER_RECIPIENTID)
                        .ok_or("Server recipient ID missing")?;
                    if !response.is_empty() {
                        return Err("Left-over elements");
                    }

                    log::info!("authz-info response {:?}", response);

                    Ok((nonce2.into_vec(), server_recipient_id.into_vec()))
                } else {
                    Err("Unsuccessful code")
                }
            },
        )
        .await?
    }

    /// Try to determine the audience value of a given peer.
    async fn try_get_rch(&mut self, id: &str) {
        if self.rs_identities.get(id).is_some() {
            // All is fine already
            return;
        }

        let response = self.prod_temperature(&id).await;
        if let Ok(rs_identity) = response {
            // If we don't get any, it's probably game over here, but no
            // reason to crash
            self.rs_identities.insert(id.to_string(), rs_identity);
            self.notify_device_list().await;
        }
    }

    /// For a given token path, find any Authorization value we have available
    fn http_authorization_for(&self, token_uri: &str) -> Option<String> {
        for (uri, authorization) in crate::authorizations::current_authorizations() {
            if token_uri == uri {
                return Some(authorization);
            }
        }
        None
    }

    /// Try to fetch a token from the AS for the audience the RS claimed to be
    ///
    /// Currently fails silently if there is no rs_identities entry.
    async fn try_get_token(&mut self, id: &str) {
        let Some(rch) = self.rs_identities.get(id) else {
            // Prerequisite missing, can't help it
            return;
        };
        if self.tokens.contains_key(rch) {
            // All is fine already
            return;
        };

        log::info!("Trying to get a token...");
        use web_sys::{Request, RequestCredentials, RequestInit, RequestMode, Response};

        let mut token_request = std::collections::HashMap::new();
        token_request.insert(5u8, &rch.audience);
        let mut request_buffer = Vec::with_capacity(50);
        ciborium::ser::into_writer(&token_request, &mut request_buffer)
            .expect("Map can be encoded");
        let body = js_sys::Uint8Array::from(request_buffer.as_slice());
        let mut opts = RequestInit::new();
        opts.method("POST")
            .mode(RequestMode::Cors)
            .credentials(RequestCredentials::Omit) // Third party cookies would be blocked
            // anyway
            .body(Some(&body));

        let Ok(request) = Request::new_with_str_and_init(&rch.as_uri, &opts) else { return };

        if let Some(authvalue) = self.http_authorization_for(&rch.as_uri) {
            request.headers().set("Authorization", &authvalue).unwrap();
        }

        let window = web_sys::window().expect("Running in a browser");
        let Ok(resp_value) = window.fetch_with_request(&request).js2rs().await else { return };

        let resp: Response = resp_value.try_into().unwrap();
        match resp.status() {
            401 => {
                if let Ok(Some(login_uri)) = resp.headers().get("Location") {
                    let Ok(login_uri) = url::Url::parse(&resp.url()).expect("We just requested from there")
                        .join(&login_uri)
                        else { log::error!("Provided URI reference is invalid"); return };
                    self.login_uris
                        .insert(rch.as_uri.to_owned(), login_uri.to_string());
                    self.notify_device_list().await;
                } else {
                    log::error!(
                        "Token endpoint reported Unauthorized but did not offer a better location"
                    );
                    return;
                }
            }
            201 => {
                let Ok(token_response) = resp.array_buffer() else { return };
                let Ok(token_response) = token_response.js2rs().await else { return };
                // There is a view method, but it's too unsafe
                let token_response = js_sys::Uint8Array::new(&token_response).to_vec();

                use dcaf::ToCborMap;
                let Ok(token_response) = dcaf::AccessTokenResponse::deserialize_from(token_response.as_slice()) else {
                        log::error!("Token response could not be parsed");
                        return
                    };

                self.tokens.insert(rch.clone(), token_response);
                self.notify_device_list().await;
                log::info!("Token obtained.");
            }
            _ => {
                log::error!("Token endpoint reported unexpected code");
                return;
            }
        }
    }

    /// Establish a security context for the given ID
    ///
    /// Currently fails silently if any pieces are missing
    async fn try_establish_security_context(&mut self, id: &str) {
        if self.security_contexts.contains_key(id) {
            // All is fine already
            return;
        }

        let Some(rs_identity) = self.rs_identities.get(id) else {
            // Prerequisite missing, can't help it
            return;
        };
        let Some(token_response) = self.tokens.get(rs_identity) else {
            // Prerequisite missing, can't help it
            return;
        };
        log::info!(
            "Trying to establish a security context with {:?} using token {:?}",
            rs_identity,
            token_response
        );
        // FIXME: This could be avoided if we didn't use &mut so often during requesting (but we do
        // need exclusvie access to one of the security contexts).
        let token_response = token_response.clone();
        let Some(dcaf::ProofOfPossessionKey::OscoreInputMaterial(material)) = &token_response.cnf.as_ref() else {
            // It's a token we can't use ... weird, but we can't help it.
            return;
        };

        // "The use of a 64-bit long random number is RECOMMENDED"
        let nonce1 = &rand::random::<[u8; 8]>();
        // Picking an arbitrary long one that's not even unique: We're only a
        // server with this peer, so this gets never sent, and we always know
        // from context when to use this one.
        let client_recipient_id = b"1234";

        match self
            .write_authzinfo(
                &id,
                nonce1,
                client_recipient_id,
                &token_response.access_token,
            )
            .await
        {
            Ok((nonce2, server_recipient_id)) => {
                log::info!("Should derive using {nonce2:?} and {server_recipient_id:?}");

                let context = ace_oscore_helpers::oscore_claims::derive(
                    material,
                    nonce1,
                    &nonce2,
                    &server_recipient_id,
                    client_recipient_id,
                )
                .unwrap();

                log::info!(
                    "Derived context {:?} now to be used with {:?}",
                    &context,
                    &id
                );
                self.security_contexts.insert(id.to_string(), context);
                self.notify_device_list().await;
            }
            Err(e) => {
                log::error!("Error occurred attempting to send a token, removing as unusable and staling RS identity data: {:?}", e);
                self.tokens
                    .remove(self.rs_identities.get(id).expect("We just had it"));
                // and for good measure
                self.rs_identities.remove(id);
                self.notify_device_list().await;
            }
        }
    }
}
