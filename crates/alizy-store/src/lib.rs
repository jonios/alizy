//! Alizy persistence layer (no Tauri): SQLite via SQLx with embedded
//! migrations, OS secret storage, and the profile manager.

pub mod db;
pub mod manager;
pub mod secrets;

pub use db::{Db, DbError, EventFilter, EventRow, HistoryRow, ProfileRow};
pub use manager::{ImportReport, ManagerError, ProfileManager};
pub use secrets::{Backend as SecretBackend, SecretStore};
