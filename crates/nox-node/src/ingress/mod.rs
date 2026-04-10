//! HTTP ingress for Sphinx packet injection and SURB response delivery.
//!
//! Production clients send Sphinx packets via HTTP POST instead of sharing
//! an in-process event bus. The entry node receives packets, publishes them
//! to the internal `TokioEventBus`, and buffers SURB responses for client retrieval.
//!
//! ## Endpoints
//! - `POST /api/v1/packets` -- Inject a raw Sphinx packet
//! - `GET /api/v1/responses/:request_id` -- Long-poll for a SURB response
//! - `GET /health` -- Health check

pub mod http_server;
pub mod response_buffer;
pub mod response_router;

pub use http_server::IngressServer;
pub use response_buffer::ResponseBuffer;
pub use response_router::ResponseRouter;
