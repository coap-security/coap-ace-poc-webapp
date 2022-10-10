use yew::prelude::*;

struct Model;

impl Component for Model {
    type Message = ();
    type Properties = ();

    fn create(_: &Context<Self>) -> Self {
        Self
    }

    fn update(&mut self, _: &Context<Self>, _: Self::Message) -> bool {
        // Never re-render
        false
    }

    fn view(&self, _: &Context<Self>) -> Html {
        html! {
            <div>
                <h1>{ "Hello CoAP!" }</h1>
                <p>{ "This page currently just demonstrates that the browser is capable of executing WebAssembly, and that the build process is functional." }</p>
            </div>
        }
    }
}

pub fn main() {
    std::panic::set_hook(Box::new(console_error_panic_hook::hook));

    console_log::init_with_level(log::Level::Debug)
        .expect("Console not available for logging");

    yew::start_app::<Model>();
}
