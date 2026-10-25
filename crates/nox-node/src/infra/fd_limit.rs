//! Open-file budget checked at startup.
//!
//! Every tunnel holds one upstream socket, and P2P connections, ingress requests, HTTP
//! clients and the database hold more. Container runtimes often start processes with a
//! soft limit of 1,024 descriptors and a much higher hard limit, so the node first raises
//! its soft limit to the hard limit. It then refuses to start when `tunnel.max_sessions`
//! cannot fit: tunnels are opened by anonymous clients, and a tunnel table larger than the
//! descriptor budget would let them exhaust descriptors and break P2P, ingress and storage
//! with `EMFILE` errors far from the cause. P2P connections are limited by peer admission
//! (registry members), so a P2P budget above the limit is reported as a warning.

use crate::config::NoxConfig;
use thiserror::Error;
use tracing::{info, warn};

/// Descriptors kept for everything besides tunnels and P2P connections: listeners,
/// ingress and topology requests, HTTP client pools, the database, logs and the runtime.
/// An idle exit uses about 33.
pub const FD_RESERVE: u64 = 256;

/// Descriptors the configuration can use at full load.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FdDemand {
    /// `tunnel.max_sessions` on an exit with tunnels enabled, else 0.
    pub tunnel_sessions: u64,
    /// `network.max_connections`.
    pub p2p_connections: u64,
    /// [`FD_RESERVE`].
    pub reserve: u64,
}

impl FdDemand {
    #[must_use]
    pub fn from_config(config: &NoxConfig) -> Self {
        let tunnel_sessions = if config.tunnel.enabled && config.node_role.is_exit_capable() {
            u64::try_from(config.tunnel.max_sessions).unwrap_or(u64::MAX)
        } else {
            0
        };
        Self {
            tunnel_sessions,
            p2p_connections: u64::from(config.network.max_connections),
            reserve: FD_RESERVE,
        }
    }

    /// Descriptors for tunnels and the reserve.
    #[must_use]
    pub fn tunnel_budget(&self) -> u64 {
        self.tunnel_sessions.saturating_add(self.reserve)
    }

    /// Descriptors for tunnels, P2P connections and the reserve.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.tunnel_budget().saturating_add(self.p2p_connections)
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FdLimitError {
    #[error(
        "tunnel.max_sessions = {max_sessions} needs about {needed} open files (one socket per \
         tunnel plus {reserve} for the rest of the node), but this process may open only \
         {limit}. Lower [tunnel] max_sessions to at most {fits} (env NOX__TUNNEL__MAX_SESSIONS), \
         or raise the open-file limit to at least {needed}: `ulimits: nofile: {needed}` in \
         docker compose, `--ulimit nofile={needed}:{needed}` for docker run, or \
         `LimitNOFILE={needed}` for systemd"
    )]
    TunnelSessionsExceedLimit {
        max_sessions: u64,
        needed: u64,
        reserve: u64,
        limit: u64,
        fits: u64,
    },
}

/// Checks `demand` against the soft open-file `limit` (`None` = unlimited). Returns a
/// warning when only the P2P connection budget does not fit.
pub fn evaluate(demand: FdDemand, limit: Option<u64>) -> Result<Option<String>, FdLimitError> {
    let Some(limit) = limit else {
        return Ok(None);
    };
    if demand.tunnel_sessions > 0 && demand.tunnel_budget() > limit {
        return Err(FdLimitError::TunnelSessionsExceedLimit {
            max_sessions: demand.tunnel_sessions,
            needed: demand.tunnel_budget(),
            reserve: demand.reserve,
            limit,
            fits: limit.saturating_sub(demand.reserve),
        });
    }
    if demand.total() > limit {
        return Ok(Some(format!(
            "network.max_connections = {} with {} tunnel sessions and {} reserved needs about \
             {} open files at full load, above the open-file limit of {limit}; peer admission \
             keeps P2P connections near the registry size, so this only matters for a very \
             large registry. Lower network.max_connections or raise the open-file limit",
            demand.p2p_connections,
            demand.tunnel_sessions,
            demand.reserve,
            demand.total()
        )));
    }
    Ok(None)
}

/// The soft and hard open-file limits (`None` = unlimited).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NofileLimits {
    pub soft: Option<u64>,
    pub hard: Option<u64>,
}

/// The soft limit to request: the hard limit when it is finite, else enough for
/// `needed`. `None` keeps the current limit.
#[must_use]
pub fn raised_soft_limit(limits: NofileLimits, needed: u64) -> Option<u64> {
    let soft = limits.soft?;
    let target = limits.hard.unwrap_or(needed.max(soft));
    (target > soft).then_some(target)
}

#[cfg(unix)]
fn current_limits() -> NofileLimits {
    use rustix::process::{getrlimit, Resource};
    let limit = getrlimit(Resource::Nofile);
    NofileLimits {
        soft: limit.current,
        hard: limit.maximum,
    }
}

#[cfg(unix)]
fn set_soft_limit(soft: u64, hard: Option<u64>) -> std::io::Result<()> {
    use rustix::process::{setrlimit, Resource, Rlimit};
    setrlimit(
        Resource::Nofile,
        Rlimit {
            current: Some(soft),
            maximum: hard,
        },
    )
    .map_err(std::io::Error::from)
}

/// Raises the soft open-file limit to the hard limit, then checks the configuration's
/// descriptor budget against it.
#[cfg(unix)]
pub fn ensure_fd_budget(config: &NoxConfig) -> Result<(), FdLimitError> {
    let demand = FdDemand::from_config(config);
    let mut limits = current_limits();
    if let Some(target) = raised_soft_limit(limits, demand.total()) {
        match set_soft_limit(target, limits.hard) {
            Ok(()) => {
                info!(
                    from = ?limits.soft,
                    to = target,
                    "Raised the open-file soft limit to the hard limit"
                );
                limits = current_limits();
            }
            Err(error) => warn!(
                %error,
                soft = ?limits.soft,
                target,
                "Could not raise the open-file soft limit; checking against the current one"
            ),
        }
    }
    if let Some(warning) = evaluate(demand, limits.soft)? {
        warn!("{warning}");
    }
    info!(
        limit = ?limits.soft,
        tunnel_sessions = demand.tunnel_sessions,
        p2p_connections = demand.p2p_connections,
        reserve = demand.reserve,
        "Open-file budget checked"
    );
    Ok(())
}

/// Open-file limits are a Unix concept; other platforms skip the check.
#[cfg(not(unix))]
pub fn ensure_fd_budget(_config: &NoxConfig) -> Result<(), FdLimitError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::NodeRole;

    fn demand(tunnel_sessions: u64, p2p_connections: u64) -> FdDemand {
        FdDemand {
            tunnel_sessions,
            p2p_connections,
            reserve: FD_RESERVE,
        }
    }

    #[test]
    fn demand_counts_tunnels_only_on_exits_with_tunnels_enabled() {
        let mut config = NoxConfig::default();
        config.tunnel.max_sessions = 512;
        config.network.max_connections = 100;

        config.node_role = NodeRole::Exit;
        config.tunnel.enabled = false;
        assert_eq!(FdDemand::from_config(&config).tunnel_sessions, 0);

        config.tunnel.enabled = true;
        let exit = FdDemand::from_config(&config);
        assert_eq!(exit, demand(512, 100));
        assert_eq!(exit.tunnel_budget(), 512 + FD_RESERVE);
        assert_eq!(exit.total(), 512 + 100 + FD_RESERVE);

        config.node_role = NodeRole::Relay;
        assert_eq!(FdDemand::from_config(&config).tunnel_sessions, 0);
    }

    #[test]
    fn default_tunnel_table_does_not_fit_a_1024_descriptor_limit() {
        let error = evaluate(demand(4_096, 10), Some(1_024)).unwrap_err();
        assert_eq!(
            error,
            FdLimitError::TunnelSessionsExceedLimit {
                max_sessions: 4_096,
                needed: 4_096 + FD_RESERVE,
                reserve: FD_RESERVE,
                limit: 1_024,
                fits: 1_024 - FD_RESERVE,
            }
        );
        let message = error.to_string();
        assert!(message.contains("max_sessions to at most 768"), "{message}");
        assert!(message.contains("ulimits: nofile: 4352"), "{message}");
    }

    #[test]
    fn fleet_exit_fits_once_the_soft_limit_is_raised() {
        // Exits run max_sessions = 512 in containers with a 1,024 soft and 524,288 hard limit.
        let exit = demand(512, 1_000);
        assert!(
            evaluate(exit, Some(1_024)).unwrap().is_some(),
            "P2P budget warns"
        );
        assert_eq!(evaluate(exit, Some(524_288)), Ok(None));
        assert_eq!(evaluate(exit, None), Ok(None));
    }

    #[test]
    fn relays_only_warn() {
        let relay = demand(0, 1_000);
        let warning = evaluate(relay, Some(1_024)).unwrap().expect("warning");
        assert!(
            warning.contains("network.max_connections = 1000"),
            "{warning}"
        );
        assert_eq!(evaluate(demand(0, 100), Some(1_024)), Ok(None));
    }

    #[test]
    fn soft_limit_is_raised_to_a_finite_hard_limit() {
        let docker = NofileLimits {
            soft: Some(1_024),
            hard: Some(524_288),
        };
        assert_eq!(raised_soft_limit(docker, 2_000), Some(524_288));

        let at_hard = NofileLimits {
            soft: Some(4_096),
            hard: Some(4_096),
        };
        assert_eq!(raised_soft_limit(at_hard, 10_000), None);

        let unlimited_hard = NofileLimits {
            soft: Some(1_024),
            hard: None,
        };
        assert_eq!(raised_soft_limit(unlimited_hard, 5_000), Some(5_000));
        assert_eq!(raised_soft_limit(unlimited_hard, 100), None);

        let unlimited = NofileLimits {
            soft: None,
            hard: None,
        };
        assert_eq!(raised_soft_limit(unlimited, 5_000), None);
    }

    #[cfg(unix)]
    #[test]
    fn startup_check_passes_for_the_default_config() {
        let config = NoxConfig::default();
        assert_eq!(ensure_fd_budget(&config), Ok(()));
        let limits = current_limits();
        assert!(limits.soft.is_none_or(|soft| soft >= FD_RESERVE));
    }
}
