/// Outgoing CoAP-over-WebSockets connections, for use as a client
///
/// The "pool" is a really bad pool -- it's zero-sized, and thus always creates connections that
/// are torn down, and worse yet, simultaneous requests do not share a single WebSocket.
///
/// It really doesn't deserve the term "pool", but the interface is here already to make this
/// purely an implementation detail. (The interface might change a bit for that, though: Currently
/// the request signature doesn't even allow for concurrent requests, and it may be that that's to
/// some extent the fault of requesting through a single async &mut self function. (Thing is: We
/// can't get a &self that lives long enough for async work from an .update() function any easier
/// than a self).
pub struct ClientPool {
}

impl ClientPool {
    pub fn new() -> Self {
        ClientPool { }
    }

    pub async fn request(&mut self, host: &str, msg: ()) -> () {
        let socket = gloo_net::websocket::futures::WebSocket::open_with_protocol(
            &format!("wss://{}/.well-known/coap", host),
            "coap",
            )
            .map_err(|e| log::error!("Error connecting: {:?}", e))
            .ok();
        log::info!("Socket proto {}", socket.as_ref().map(|s| s.protocol()).unwrap_or("unconnected".to_string()));

        let mut socket = socket.unwrap(); // for the time being

        use futures::stream::StreamExt;
        let csm = socket.next().await;
        log::info!("Got CSM {:?}", csm);

//         let next = socket.next().await;
//         log::info!("Got further message {:?}", next);
    }
}
