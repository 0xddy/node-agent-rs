//! Control plane binary for the shoes dynamic engine.
//!
//! Unlike the `shoes` binary, this one takes **no proxy config**. It starts the
//! Tokio runtime, brings the engine up empty, and exposes a management API. Every
//! inbound is injected afterwards over that API.
//!
//! ```text
//! shoes-controller [--api-listen ADDR] [--log-level LEVEL]
//! ```

mod http;

use std::net::SocketAddr;

use log::{error, info};

use shoes::logging::{Directive, StderrWriter, init_multi_logger, parse_log_level, resolve_directives};
use shoes_engine::Engine;

use crate::http::ApiServer;

const DEFAULT_API_LISTEN: &str = "127.0.0.1:9090";

struct Args {
    api_listen: SocketAddr,
    log_level: Option<String>,
}

fn print_usage_and_exit(arg0: &str) -> ! {
    eprintln!(
        "\
usage: {arg0} [options]

options:
  --api-listen ADDR    management API listen address (default {DEFAULT_API_LISTEN})
  --log-level LEVEL    error | warn | info | debug | trace (default: RUST_LOG, else error)
  -h, --help           show this message

The engine starts with no inbounds and no users. Populate it over the API:

  GET    /status
  GET    /inbounds
  POST   /inbounds            {{\"tag\": \"...\", \"config\": {{ ...shoes server config... }}}}
  DELETE /inbounds/{{tag}}
"
    );
    std::process::exit(1);
}

fn parse_args() -> Args {
    let mut argv = std::env::args();
    let arg0 = argv.next().unwrap_or_else(|| "shoes-controller".to_string());

    let mut api_listen = None;
    let mut log_level = None;

    while let Some(arg) = argv.next() {
        match arg.as_str() {
            "--api-listen" => {
                let value = argv
                    .next()
                    .unwrap_or_else(|| print_usage_and_exit(&arg0));
                match value.parse::<SocketAddr>() {
                    Ok(addr) => api_listen = Some(addr),
                    Err(e) => {
                        eprintln!("invalid --api-listen value {value:?}: {e}\n");
                        print_usage_and_exit(&arg0);
                    }
                }
            }
            "--log-level" => {
                let value = argv
                    .next()
                    .unwrap_or_else(|| print_usage_and_exit(&arg0));
                if parse_log_level(&value).is_none() {
                    eprintln!("invalid --log-level value {value:?}\n");
                    print_usage_and_exit(&arg0);
                }
                log_level = Some(value);
            }
            "-h" | "--help" => print_usage_and_exit(&arg0),
            other => {
                eprintln!("unrecognized argument {other:?}\n");
                print_usage_and_exit(&arg0);
            }
        }
    }

    Args {
        api_listen: api_listen.unwrap_or_else(|| {
            DEFAULT_API_LISTEN
                .parse()
                .expect("default api listen address is valid")
        }),
        log_level,
    }
}

fn init_logging(log_level: Option<&str>) {
    let directives = match log_level.and_then(parse_log_level) {
        Some(level) => vec![Directive { name: None, level }],
        None => resolve_directives(),
    };
    init_multi_logger(vec![Box::new(StderrWriter)], directives);
}

#[tokio::main]
async fn main() {
    let args = parse_args();
    init_logging(args.log_level.as_deref());

    let engine = match Engine::bootstrap().await {
        Ok(engine) => engine,
        Err(e) => {
            error!("could not bootstrap engine: {e}");
            std::process::exit(1);
        }
    };

    println!("shoes-controller started with an empty configuration.");
    println!("management API: http://{}", args.api_listen);

    let api = ApiServer::new(engine, args.api_listen);

    tokio::select! {
        result = api.serve() => {
            if let Err(e) = result {
                error!("management API stopped: {e}");
                std::process::exit(1);
            }
        }
        result = tokio::signal::ctrl_c() => {
            match result {
                Ok(()) => info!("received interrupt, shutting down"),
                Err(e) => error!("could not listen for interrupt: {e}"),
            }
        }
    }
}
