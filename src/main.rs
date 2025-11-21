#[cfg(feature = "ssr")]
#[tokio::main]
async fn main() {
    use axum::Router;
    use leptos::logging::log;
    use leptos::prelude::*;
    use leptos_axum::{generate_route_list, LeptosRoutes};

    use meloseerr::app::*;
    use meloseerr::api;
    use meloseerr::State;
    use sqlx::sqlite::SqliteConnectOptions;

    let conf = get_configuration(None).unwrap();
    let addr = conf.leptos_options.site_addr;

    let state = State {
        leptos_options: conf.leptos_options,
        key_store: Default::default(),
        pool: sqlx::sqlite::SqlitePool::connect_with(
                SqliteConnectOptions::new()
                    .filename("data.sqlite")
                    .create_if_missing(true)
            )
            .await
            .expect("failed to make connection to database")
    };

    sqlx::migrate!("./migrations")
        .run(&state.pool)
        .await
        .expect("failed to run database migrations");

    // Generate the list of routes in your Leptos App
    let routes = generate_route_list(App);

    let app = Router::new()
        .leptos_routes(&state, routes, {
            let leptos_options = state.leptos_options.clone();
            move || shell(leptos_options.clone())
        })
        .nest("/api", api::routes())
        .fallback(leptos_axum::file_and_error_handler::<State, _>(shell))
        .with_state(state);

    // run our app with hyper
    // `axum::Server` is a re-export of `hyper::Server`
    log!("listening on http://{}", &addr);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app.into_make_service())
        .await
        .unwrap();
}

#[cfg(not(feature = "ssr"))]
pub fn main() {
    // no client-side main function
    // unless we want this to work with e.g., Trunk for pure client-side testing
    // see lib.rs for hydration function instead
}
