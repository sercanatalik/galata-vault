//! Bring your own transport: this one wraps the HTTP transport and logs each
//! request's method and path (never its headers or body) to stderr.
//!
//! ```text
//! GV_SERVER=https://vault.example GV_TOKEN=gvt1_… \
//!     cargo run -p galata-vault --example custom_transport
//! ```
//!
//! A `Transport` sees only the canonical request the protocol signs, already
//! signed by `Api`, and returns the answer unchanged: it can log, route
//! through a proxy of its own, or serve from an in-process backend, and it
//! never needs to know which operation a request is.

use galata_vault::{
    Api, ClientBuilder, HttpTransport, Request, Response, Transport, TransportError, Vault,
};
use zeroize::Zeroizing;

struct Logged(HttpTransport);

impl Transport for Logged {
    fn send(&self, request: Request<'_>) -> Result<Response, TransportError> {
        let result = self.0.send(request);
        match &result {
            Ok(response) => eprintln!(
                "{} {} -> {}",
                request.method, request.path_and_query, response.status
            ),
            Err(e) => eprintln!("{} {} -> {e}", request.method, request.path_and_query),
        }
        result
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let server = std::env::var("GV_SERVER").map_err(|_| "set GV_SERVER")?;
    let token = Zeroizing::new(std::env::var("GV_TOKEN").map_err(|_| "set GV_TOKEN")?);
    let api = Api::new(Logged(ClientBuilder::new(&server).build_transport()?));
    let vault = Vault::with_api(&token, &api)?;
    for entry in vault.list()? {
        println!("{}  v{}", entry.name, entry.version);
    }
    Ok(())
}
