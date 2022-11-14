use yew::prelude::*;

struct Model;

// From CoAP-over-GATT draft
const UUID_US: &'static str = "8df804b7-3300-496d-9dfa-f8fb40a236bc";

impl Component for Model {
    type Message = ();
    type Properties = ();

    fn create(_: &Context<Self>) -> Self {
        Self
    }

    fn update(&mut self, _: &Context<Self>, _: Self::Message) -> bool {
        // Can't have this in create because "Must be handling a user gesture to show a permission request."
        wasm_bindgen_futures::spawn_local(async {
            use web_sys::*;

            let navigator = window().expect("This is running inside a web browser")
                .navigator();

            let bluetooth = navigator.bluetooth()
                .expect("No Bluetooth available in this browser");

            let device = wasm_bindgen_futures::JsFuture::from(bluetooth
                .request_device(
                    RequestDeviceOptions::new().filters(
                        &[BluetoothLeScanFilterInit::new().services(
                            &[wasm_bindgen::JsValue::from(UUID_US)].iter().collect::<js_sys::Array>())
                        ].iter().collect::<js_sys::Array>()
                ))
                ).await;

            log::info!("Device: {:?}", device);
        });

        // Never re-render
        false
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let link = ctx.link();

        let navigator = web_sys::window().expect("This is running inside a web browser")
            .navigator();
        let has_bluetooth = navigator.bluetooth().is_some();

        let bluetooth_button = match has_bluetooth {
            true => html! { <button onclick={link.callback(|_| ())}>{ "Scan BLE for CoAP-over-GATT" }</button> },
            false => html! { <button disabled=true title="Bluetooth not available in this browser">{ "Scan BLE for CoAP-over-GATT" }</button> }
        };

        html! {
            <div>
                <h1>{ "Hello CoAP!" }</h1>
                <p>{ "This page currently just demonstrates that the browser is capable of executing WebAssembly, and that the build process is functional." }</p>
                <p>{ "Click the button below to show that the browser supports Web Bluetooth. If a CoAP-over-GATT capable device is within reach, it will show in this dialogue" }</p>
                { bluetooth_button }
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
}
