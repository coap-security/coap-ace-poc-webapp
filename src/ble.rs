//! Implementation fo CoAP-over-GATT and the application specific requests.
//!
//! This module is split in two main structs:
//!
//! * [BlePool] is owned by the front end, and has synchronous methods as well as a notificaiton
//!   channel into yew.
//!
//! * [BlePoolBackend] runs itself in a dedicated task, and is independend of yew or (ideally) the
//!   application. It deals in asyncs.
//
// FIXME: Split the pure CoAP-over-GATT from application specifics, and possibly even the
// application specifics from the yew-specific async adapter

use crate::helpers::PromiseExt;

// From CoAP-over-GATT draft
const UUID_US: &'static str = "8df804b7-3300-496d-9dfa-f8fb40a236bc";
const UUID_UC: &'static str = "2a58fc3f-3c62-4ecc-8167-d66d4d9410c2";

pub type DeviceId = String;
type RequestCreationHints =
    ace_oscore_helpers::request_creation_hints::RequestCreationHints<String>;

/// Data exposed by teh BLE module toward the front end
#[derive(Debug)]
pub struct DeviceDetails {
    /// ID needed to do actions on the device.
    ///
    /// Absence indicates that the device has never been connected.
    pub id: Option<DeviceId>,
    pub is_connected: bool,
    /// User-visible name if provided at BLE level
    pub name: Option<String>,
    /// Claimed cryptographic identity
    pub rs_identity: Option<RequestCreationHints>,
    /// There was a 401 last time a token retrieval was attempted
    pub authorization_missing: bool,
    /// Short form of the access token obtained for that connection, if any
    pub access_token: Option<String>,
    pub oscore_established: bool,
}

/// Messages emitted by yew through the [BlePool], directing the BLE main loop in the
/// [BlePoolBackend]
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

    /// Add a device based on request creation hints. Also removes security associations, if the
    /// device is already known.
    AddDeviceManually(RequestCreationHints),

    /// Remove a BLE device (but not any credentials associated with it) from the list, and
    /// ask the browser to disconnect it.
    Disconnect(DeviceId),
}
use FrontToBackMessage::*;

/// Messages produced by the [BlePoolBackend] updating the yew side
#[derive(Debug)]
pub enum BackToFrontMessage {
    /// The list of devices has changed
    ///
    /// (Alternatively, this could be expressed in a series of removals and and additions)
    UpdateDeviceList(Vec<DeviceDetails>),
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
}

/// Error type indicating browsers without WebBluetooth support
#[derive(Debug)]
pub struct NoWebBluetoothSupport;

#[derive(Debug)]
enum TokenStatus {
    Obtained(dcaf::AccessTokenResponse),
    Failed,
    // Not using a Result because we could have a Pending inbetween as well
}
use TokenStatus::*;

impl TokenStatus {
    fn get_obtained(&self) -> Option<&dcaf::AccessTokenResponse> {
        match self {
            Obtained(atr) => Some(atr),
            _ => None,
        }
    }
}

/// The parts of the BlePool that are runin their own task
struct BlePoolBackend {
    front2back: futures::channel::mpsc::Receiver<FrontToBackMessage>,
    back2front: futures::channel::mpsc::Sender<BackToFrontMessage>,
    /// BLE connections
    connections: std::collections::HashMap<DeviceId, BleConnection>,
    /// Most recent request creation hint obtained from the device with the given ID
    rs_identities: std::collections::HashMap<DeviceId, RequestCreationHints>,
    /// RCHs that were not found in any concrete BLE device, but are known from other sources
    /// (add_device_manually).
    ///
    /// Items in here are very similar to rs_identities entries, except that they've never seen a
    /// BLE device. Devices that vanish still have their DeviceId an can be kept in rs_identities
    /// even when the connections are gone.
    preseeded_rch: std::collections::HashSet<RequestCreationHints>,
    /// Tokens requested from the AS
    tokens: std::collections::HashMap<RequestCreationHints, TokenStatus>,
    /// Established security contexts
    security_contexts: std::collections::HashMap<DeviceId, liboscore::PrimitiveContext>,
}

/// A BLE characteristic (from which the device, GATT and other JavaScript components can be
/// restored), along with the name it was discovered under.
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

    pub fn disconnect(&mut self, device: DeviceId) {
        self.request(Disconnect(device));
    }

    pub fn add_device_manually(&mut self, rch: RequestCreationHints) {
        self.request(AddDeviceManually(rch));
    }

    pub fn latest_temperature(&self, device: &str) -> Option<f32> {
        self.most_recent_temperatures.get(device).copied()
    }

    pub fn active_connections(&self) -> impl Iterator<Item = &DeviceDetails> {
        self.most_recent_connections.iter()
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

    /// Change entry point for the backend.
    ///
    /// The user (usually a yew component) needs to send any messages emitted by the receiver
    /// created in `new()` into this function.
    pub fn notify(&mut self, message: BackToFrontMessage) {
        match message {
            UpdateDeviceList(mut list) => {
                fn key(i: &DeviceDetails) -> (Option<&String>, Option<&String>) {
                    (
                        i.id.as_ref(),
                        i.rs_identity.as_ref().map(|rch| &rch.audience),
                    )
                }
                list.sort_by(|a, b| key(a).cmp(&key(b)));
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
    /// Open the browser's BLE connect dialog, filtering for CoAP-over-GATT devices
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
        log::info!("New device: {:?} ({:?})", device.name(), device.id());

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

        log::info!("Device supports CoAP-over-GATT.");

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

        fn present_token(atr: &dcaf::AccessTokenResponse) -> String {
            format!(
                "{}",
                hex::encode(&atr.access_token[atr.access_token.len() - 4..])
            )
        }

        let mut new_list: Vec<_> = ids
            .iter()
            .map(|id| {
                let id: &str = id.as_ref();
                let rs_identity = self.rs_identities.get(id);
                let con = self.connections.get(id);
                let token = rs_identity.and_then(|rch| self.tokens.get(rch));
                DeviceDetails {
                    id: Some(id.to_string()),
                    is_connected: con.is_some(),
                    name: con.and_then(|c| Some(c.name.as_ref()?.clone())),
                    rs_identity: rs_identity.cloned(),
                    authorization_missing: matches!(&token, Some(Failed)),
                    access_token: token.and_then(|ts| ts.get_obtained()).map(present_token),
                    oscore_established: self.security_contexts.contains_key(id),
                }
            })
            .collect();

        new_list.extend(self.preseeded_rch.iter().map(|rch| {
            let token = self.tokens.get(rch);
            DeviceDetails {
                id: None,
                is_connected: false,
                name: None,
                rs_identity: Some(rch.clone()),
                authorization_missing: matches!(&token, Some(Failed)),
                access_token: token.and_then(|ts| ts.get_obtained()).map(present_token),
                oscore_established: false,
            }
        }));

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
            rs_identities: Default::default(),
            preseeded_rch: Default::default(),
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

                            let rch = self_.try_get_rch(&id).await;
                            if let Some(rch) = rch {
                                self_.try_get_token(&rch).await;
                            }
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
                Some(AddDeviceManually(rch)) => {
                    if let Some(id) = self_
                        .rs_identities
                        .iter()
                        .filter(|(_, item_rch)| item_rch == &&rch)
                        .map(|(id, _)| id)
                        .next()
                    {
                        // Device is present; AddDeviceManually doubles as "remove all credentials"
                        let _ = self_.security_contexts.remove(id);
                    } else {
                        // Just insert it if it's not present in rs_identities anyway
                        self_.preseeded_rch.insert(rch.clone());
                    };
                    let _ = self_.tokens.remove(&rch);
                    self_.notify_device_list().await;
                    self_.try_get_token(&rch).await;
                }
                Some(Disconnect(id)) => {
                    if let Some(con) = self_.connections.remove(&id) {
                        if let Some(gatt) = con.characteristic.service().device().gatt() {
                            gatt.disconnect();
                        }
                        self_.notify_device_list().await;
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

        log::debug!("Writing request: {} bytes", request.len());

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
                log::debug!("Read response: {} bytes", response.len());
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
        let rch = self.try_get_rch(id).await;
        if let Some(rch) = rch {
            self.try_get_token(&rch).await;
        };
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
            // broken. As we've received a response and it's really just the OSCORE layer that was
            // broken, it's likely that not only the OSCORE context is over, but the underlying
            // token as well. Removing that token because this makes a smoother experience
            // retry-wise because we have users who retry here. Leaving the rs_identity in place
            // because it'd only change if people start flashing different RSes onto the same BLE
            // MACs (which is weird enough to warrant some breakage, but on the upside this keeps
            // the device identity visible, and avoids switcharoos as the app won't try addressing
            // the previously known device with a different security context).

            // In real deployments, these would be much less relevant considerations, and there
            // could be a more defensive removal scheme coupled with eager reestablishments.
            let Some(rch) = self.rs_identities.get(id) else {
                panic!("There can't be a security context on an unknown device");
            };
            self.tokens.remove(&rch);
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
                log::info!(
                    "Time written, code {}.{:02}",
                    response.code() >> 5,
                    response.code() & 0x1f
                );
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

                    log::debug!("Response obtained from authz-info: server recipient ID {server_recipient_id:?}, nonce2 {nonce2:?}");

                    Ok((nonce2.into_vec(), server_recipient_id.into_vec()))
                } else {
                    Err("Unsuccessful code")
                }
            },
        )
        .await?
    }

    /// Try to determine the audience value of a given peer.
    ///
    /// FIXME: This should be less clone-y.
    async fn try_get_rch<'a>(&'a mut self, id: &'a str) -> Option<RequestCreationHints> {
        if let Some(rch) = self.rs_identities.get(id) {
            // All is fine already
            return Some(rch.clone());
        }

        let response = self.prod_temperature(&id).await;
        if let Ok(rs_identity) = response {
            // Remove them if they happened to be present without a BLE ID, even though that's
            // typically not the case
            let _ = self.preseeded_rch.remove(&rs_identity);

            // If we don't get any, it's probably game over here, but no
            // reason to crash
            self.rs_identities.insert(id.to_string(), rs_identity);
            self.notify_device_list().await;
        }

        self.rs_identities.get(id).cloned()
    }

    /// For a given token path, find any Authorization value we have available
    fn http_authorization_for(&self, token_uri: &str) -> Option<String> {
        for (uri, authorization, _) in crate::authorizations::current_authorizations() {
            if token_uri == uri {
                // which would be None where we're not logged in, and that's fine
                return Some(authorization);
            }
        }
        None
    }

    /// Try to fetch a token from the AS for the audience the RS claimed to be
    ///
    /// Currently fails silently if there is no rs_identities entry.
    async fn try_get_token(&mut self, rch: &RequestCreationHints) {
        if self
            .tokens
            .get(rch)
            .and_then(|ts| ts.get_obtained())
            .is_some()
        {
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
                self.tokens.insert(rch.clone(), Failed);
                self.notify_device_list().await;
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

                self.tokens.insert(rch.clone(), Obtained(token_response));
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
        let Some(Obtained(token_response)) = self.tokens.get(rs_identity) else {
            // Prerequisite missing, can't help it
            return;
        };
        log::info!("Trying to establish a security context.");
        log::debug!("Token: {token_response:?}");

        // FIXME: This could be avoided if we didn't use &mut so often during requesting (but we do
        // need exclusvie access to one of the security contexts).
        let token_response = token_response.clone();
        let Some(dcaf::ProofOfPossessionKey::OscoreInputMaterial(material)) = &token_response.cnf.as_ref() else {
            log::error!("Token is unusable for the ACE OSCORE profile");
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
                let context = ace_oscore_helpers::oscore_claims::derive(
                    material,
                    nonce1,
                    &nonce2,
                    &server_recipient_id,
                    client_recipient_id,
                )
                .unwrap();

                log::info!("Derived OSCORE context now to be used with {id:?}");
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
