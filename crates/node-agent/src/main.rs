use std::process::ExitCode;

use mimalloc::MiMalloc;
use node_agent::agent::Agent;
use node_agent::{cli, config, logging, shutdown};

// The agent is a long-running, allocation-heavy network process. mimalloc's
// per-thread free lists and eager page reclamation reduce allocator contention
// and fragmentation without affecting crates that embed `shoes` as a library.
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

const USAGE: &str = "usage: node-agent <config.toml> | node-agent version [--json]";

#[tokio::main]
async fn main() -> ExitCode {
    ExitCode::from(run_main().await)
}

async fn run_main() -> u8 {
    let args: Vec<String> = std::env::args().collect();
    match cli::run_version_command(&args, std::io::stdout()) {
        Ok(true) => return 0,
        Err(error) => {
            eprintln!("{error}");
            return 1;
        }
        Ok(false) => {}
    }

    logging::install_panic_hook("main");
    if let Err(error) = logging::configure(false, "") {
        eprintln!("配置默认日志失败：{error}");
    }
    let result = real_main(&args).await;
    if let Err(error) = &result {
        log::error!("node-agent 异常退出：{error}");
    }
    logging::close();
    u8::from(result.is_err())
}

async fn real_main(args: &[String]) -> Result<(), String> {
    let [_, config_path] = args else {
        return Err(USAGE.into());
    };
    let config = config::load(config_path).map_err(|error| format!("load config: {error}"))?;
    logging::configure(config.debug, &config.log_file_path)
        .map_err(|error| format!("configure logging: {error}"))?;
    log::info!(
        "node-agent 正在启动：机器={}，节点={}，面板={}",
        config.machine_id,
        config.node_id,
        config.panel_grpc_endpoint
    );

    let shutdown = shutdown::cancellation_token();
    let agent = Agent::bootstrap(config)
        .await
        .map_err(|error| error.to_string())?;
    agent.run(shutdown).await.map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn non_config_invocations_use_the_stable_usage() {
        let error = real_main(&["node-agent".into()]).await.unwrap_err();
        assert_eq!(error, USAGE);
        let error = real_main(&["node-agent".into(), "a".into(), "b".into()])
            .await
            .unwrap_err();
        assert_eq!(error, USAGE);
    }
}
