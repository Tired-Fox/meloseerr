pub mod app;
pub mod api;
pub mod auth;

#[cfg(feature="ssr")]
#[derive(axum::extract::FromRef, Debug, Clone)]
pub struct State {
    pub leptos_options: leptos::config::LeptosOptions,
    pub key_store: auth::KeyStore,
    pub pool: sqlx::SqlitePool
}

#[cfg(feature = "hydrate")]
#[wasm_bindgen::prelude::wasm_bindgen]
pub fn hydrate() {
    use crate::app::*;
    console_error_panic_hook::set_once();
    leptos::mount::hydrate_body(App);
}
