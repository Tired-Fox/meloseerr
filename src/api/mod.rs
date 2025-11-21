use leptos::{prelude::ServerFnError, server};

#[server]
pub async fn user_count() -> Result<usize, ServerFnError> {
    use crate::auth::User;
    use leptos::prelude::expect_context;

    let state: crate::State = expect_context();

    User::count(&state.pool)
        .await
        .map_err(ServerFnError::new)
}

#[cfg(feature="ssr")]
pub fn routes(state: crate::State) -> axum::Router<crate::State> {
    use axum::Router;

    Router::new()
        .route("/hello-world", axum::routing::get(move || async { "Hello, World!" }))
        .layer(crate::auth::AuthLayer{ state })
}