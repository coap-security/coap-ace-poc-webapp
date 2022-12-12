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
                            let token_response = self_.write_authzinfo(&id, hex_literal::hex!("D08344A101181FA1054D67D813D2CDBC2859F0C2E9F330584CF30B8F55A8AF8D1DD20DC0DB446850E64539396B0FACFD8BEAEFFD9B0393986EF9D2F8E718A372EF4C4FB9A67EF2D2402602345A7671D423085FF314485A8AF1FDE41F10DC1720D02364D50B").as_slice()).await;
                            log::info!("Response to token request: {:?}", token_response);
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

    async fn send_request<R>(
        &mut self,
        id: &str,
        write_request: impl FnOnce(&mut coap_gatt_utils::WriteMessage<'_>),
        read_response: impl FnOnce(&coap_gatt_utils::ReadMessage<'_>) -> R,
    ) -> R {
        let connection = &self.connections[id];

        let mut request = coap_gatt_utils::write::<400>(write_request);

        log::debug!("Writing to charcteristic with length {}", request.len());
        
        connection.characteristic.write_value_with_u8_array(&mut request)
            .js2rs()
            .await
            .unwrap();

        let response = loop {
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

        let coap_response = coap_gatt_utils::parse(&response)
            .unwrap();

        read_response(&coap_response)
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
                     |response| {
                        use coap_message::ReadableMessage;
                        log::info!("Time written, code {:?}", response.code());
                     }).await;
    }

    async fn read_temperature(&mut self, id: &str) -> Result<f32, &'static str> {
        self.send_request(&id,
             |request| {
                use coap_message::MinimalWritableMessage;
                request.set_code(coap_numbers::code::GET.try_into().unwrap());
                request.add_option(coap_numbers::option::URI_PATH.try_into().unwrap(), b"temp");
                request.set_payload(&[]);
             },
             |response| {
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
        self.send_request(&id,
             |request| {
                use coap_message::MinimalWritableMessage;
                request.set_code(coap_numbers::code::POST.try_into().unwrap());
                request.add_option(coap_numbers::option::URI_PATH.try_into().unwrap(), b"identify");
                request.set_payload(&[]);
             },
             |_| {}).await
    }

    async fn set_idle(&mut self, id: &str, level: u8) {
        // This would be moderately smoother if a WindowedInfinityWithETag writer could ve
        // constructed easily for a message when we don't expect blockwising and are in a request
        let mut level_buffer = Vec::with_capacity(2);
        ciborium::ser::into_writer(&level, &mut level_buffer).expect("Level can be encoded");
        // No error handling because this resource returns success anyway (and the success is
        // indicated remotely)
        self.send_request(&id,
             |request| {
                use coap_message::MinimalWritableMessage;
                request.set_code(coap_numbers::code::PUT.try_into().unwrap());
                request.add_option(coap_numbers::option::URI_PATH.try_into().unwrap(), b"leds");
                request.set_payload(&level_buffer);
             },
             |_| {}).await
    }

    // FIXME actually token plus local nonce1 and id1
    async fn write_authzinfo(&mut self, id: &str, token: &[u8]) -> Result<(), u8> {
        let code = self.send_request(id,
                     |request| {
                        use coap_message::MinimalWritableMessage;
                        request.set_code(coap_numbers::code::POST.try_into().unwrap());
                        request.add_option(coap_numbers::option::URI_PATH.try_into().unwrap(), b"authz-info");
                        request.set_payload(&token);
                     },
                     |response| {
                         use coap_message::ReadableMessage;
                         response.code()
                     }).await;
        if code == coap_numbers::code::CHANGED {
            Ok(())
        } else {
            Err(code)
        }
    }
}
