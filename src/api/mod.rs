use leptos::{prelude::{ServerFnError, expect_context}, server};

use crate::auth::User;

#[server]
pub async fn user_count() -> Result<usize, ServerFnError> {
    let state: crate::State = expect_context();

    User::count(&state.pool)
        .await
        .map_err(ServerFnError::new)
}

#[cfg(feature="ssr")]
pub fn routes() -> axum::Router<crate::State> {
    use axum::{Router, http::Method};
    use tower_http::cors::CorsLayer;

    Router::new()
        .layer(
            CorsLayer::new()
                .allow_methods([Method::GET])
                .allow_origin(tower_http::cors::Any)
        )
        .route("/hello-world", axum::routing::get(move || async { "Hello, World!" }))
}