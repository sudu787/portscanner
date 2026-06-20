/// errors.rs — Typed error hierarchy for rustscan-rs
///
/// Uses `thiserror` to derive `std::error::Error` implementations cleanly.
/// All domain-specific errors are variants of `RustScanError`.
/// Callers that need ad-hoc context use `anyhow::Context` on top.

use thiserror::Error;

/// Top-level error type for rustscan-rs.
#[derive(Debug, Error)]
pub enum RustScanError {
    // ── CLI / Configuration ────────────────────────────────────────────────
    /// Emitted when `--start-port` is greater than `--end-port`.
    #[error("invalid port range: start port {start} is greater than end port {end}")]
    InvalidPortRange { start: u16, end: u16 },

    /// Emitted when a port number is out of the 1-65535 range.
    #[error("port value {port} is out of the valid range 1–65535")]
    PortOutOfRange { port: u32 },

    /// Emitted when the timeout value is zero or exceeds a safe ceiling.
    #[error("timeout value {ms}ms is invalid — must be between 1 ms and 300 000 ms (5 min)")]
    InvalidTimeout { ms: u64 },

    /// Emitted when concurrency is zero or absurdly large.
    #[error(
        "concurrency value {value} is invalid — must be between 1 and {max}"
    )]
    InvalidConcurrency { value: usize, max: usize },

    // ── I/O ───────────────────────────────────────────────────────────────
    /// Wraps any underlying I/O error that bubbles up.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    // ── Output / Serialization ────────────────────────────────────────────
    /// Wraps serde_json serialization failures.
    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    // ── Network / DNS ─────────────────────────────────────────────────────
    /// Emitted when a hostname cannot be resolved (Phase 3: async DNS).
    #[error("could not resolve hostname: {host}")]
    #[allow(dead_code)]
    DnsResolutionFailed { host: String },

    /// Emitted when a target string is neither a valid IP nor a hostname.
    #[error("invalid target '{target}': must be a valid IP address, CIDR range, or hostname")]
    InvalidTarget { target: String },

    // ── Target / CIDR ──────────────────────────────────────────────────────
    /// The CIDR string could not be parsed (e.g., "192.168.1.0/99").
    #[error("invalid CIDR notation '{input}': {reason}")]
    InvalidCidr { input: String, reason: String },

    /// The network prefix is so short that expansion would exceed the safety
    /// limit (e.g., specifying /4 would yield 268 million addresses).
    #[error(
        "CIDR range '{input}' has {count} addresses which exceeds the safety \
         limit of {max} — use a longer prefix (e.g., /16 or higher)"
    )]
    CidrTooLarge { input: String, count: u64, max: u64 },
}

/// Convenience `Result` alias that defaults the error type to [`RustScanError`].
pub type Result<T> = std::result::Result<T, RustScanError>;
