use super::errors::BackendResult;
use super::manager::Backend;
use super::plan::Plan;

/// Development-only no-op, matching the Go Windows backend.
pub(super) struct WindowsBackend {
    machine_id: String,
    warned: bool,
}

impl WindowsBackend {
    pub(super) fn new(machine_id: &str) -> Self {
        Self {
            machine_id: machine_id.to_owned(),
            warned: false,
        }
    }
}

impl Backend for WindowsBackend {
    fn apply(&mut self, desired: &Plan) -> BackendResult {
        if !desired.is_empty() && !self.warned {
            self.warned = true;
            log::warn!(
                "当前 Windows 平台不支持 Hysteria2 端口跳跃，已跳过 UDP 端口转发配置（开发期空实现）；节点服务将继续运行：机器={}，节点数={}，规则数={}",
                self.machine_id,
                desired.redirects.len(),
                desired.rule_count()
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::WindowsBackend;
    use crate::porthopping::manager::Backend as _;
    use crate::porthopping::{Plan, Redirect};

    #[test]
    fn windows_backend_accepts_empty_and_non_empty_plans() {
        let mut backend = WindowsBackend::new("machine-1");
        backend.apply(&Plan::default()).unwrap();
        backend
            .apply(&Plan {
                redirects: vec![Redirect {
                    node_id: "node-a".into(),
                    listen_port: 443,
                    ports: Vec::new(),
                }],
            })
            .unwrap();
        assert!(backend.warned);
    }
}
